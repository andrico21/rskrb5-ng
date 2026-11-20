//! The armor AP-REQ and armor key (MIT `fast.c:51-108`) and the armored
//! request (`fast.c:144-169,253-357`).

use core::{mem, time::Duration};
use std::time::{SystemTime, UNIX_EPOCH};

use rasn::types::Integer;
use rasn_kerberos::{KerberosFlags, KerberosString, KerberosTime, PaData, PrincipalName};
use zeroize::Zeroizing;

use super::{
    ARMOR_AP_REQUEST, ArmorSource, KEY_USAGE_FAST_ENC, KEY_USAGE_FAST_REQ_CHKSUM, PA_FX_COOKIE,
    PA_FX_FAST, Policy,
    asn1::{KrbFastArmor, KrbFastArmoredReq, KrbFastReq, PaFxFastRequest},
    keys::{self, codec, encode},
};
use crate::{
    ap_req,
    ccache::{self, CCache},
    client::{AP_REQ_AUTHENTICATOR_USAGE, AsRepSession, principal::Principal, random_subkey_for},
    crypto::{CryptoPolicy, Use},
    error::{Crypto, Fast as Error},
    keytab::EncryptionKey,
    ticket,
};

/// RFC 4120 `KDCOptions` bit 15, `canonicalize` (RFC 6806 section 3).
const CANONICALIZE_BIT: usize = 15;

/// The armor of one conversation: the armor AP-REQ and the armor key.
pub(super) struct Armor {
    /// `KRB-FX-CF2(subkey, ticket session key, "subkeyarmor", "ticketarmor")`.
    key: EncryptionKey,
    /// The DER armor AP-REQ.
    ap_req: Zeroizing<Vec<u8>>,
}

impl Armor {
    /// The armor key.
    pub(super) const fn key(&self) -> &EncryptionKey {
        &self.key
    }
}

/// Decode the engine's unarmored AS-REQ.
///
/// # Errors
/// Returns [`Error::Codec`] for bytes that are not an AS-REQ.
pub(super) fn decode_request(bytes: &[u8]) -> Result<rasn_kerberos::AsReq, Error> {
    keys::decode("AS-REQ", bytes)
}

/// Choose the conversation's armor under `policy`, consuming `source`.
///
/// # Errors
/// Returns [`Error::ArmorUnavailable`] when `Required` finds no armor, the
/// anonymous provider's failure, and the armor-building errors.
pub(super) fn choose(
    policy: Policy,
    source: &mut ArmorSource,
    crypto_policy: &CryptoPolicy,
    realm: &str,
) -> Result<Option<Armor>, Error> {
    match policy {
        Policy::Off => return Ok(None),
        Policy::Opportunistic | Policy::Required => {}
    }
    let ticket = match mem::replace(source, ArmorSource::None) {
        ArmorSource::None => None,
        ArmorSource::Ticket(ticket) => Some(*ticket),
        ArmorSource::Cache(cache) => cache.armor_ticket(realm, SystemTime::now()),
        ArmorSource::Anonymous(mut provider) => Some(
            provider
                .armor_ticket(realm)
                .map_err(Error::AnonymousArmor)?,
        ),
    };
    match (ticket, policy) {
        (Some(armor_ticket), _) => establish(&armor_ticket, realm, crypto_policy).map(Some),
        (None, Policy::Required) => Err(Error::ArmorUnavailable {
            realm: realm.to_owned(),
        }),
        (None, Policy::Off | Policy::Opportunistic) => Ok(None),
    }
}

/// The unexpired `krbtgt/REALM@REALM` credential of `cache` at `now`.
pub(super) fn from_cache(cache: &CCache, realm: &str, now: SystemTime) -> Option<AsRepSession> {
    let seconds = |value: u32| UNIX_EPOCH.checked_add(Duration::from_secs(value.into()));
    cache
        .credentials()
        .iter()
        .filter(|credential| credential.server().matches_components(&["krbtgt", realm]))
        .filter(|credential| credential.server().realm == realm)
        .find_map(|credential| {
            let end = seconds(credential.times().end_time)?;
            let auth = seconds(credential.times().auth_time)?;
            (end > now).then(|| {
                AsRepSession::new(
                    principal(credential.client()),
                    principal(credential.server()),
                    EncryptionKey::new(credential.key().etype(), credential.key().value().clone()),
                    credential.ticket().clone(),
                    credential.ticket_flags(),
                    auth,
                    end,
                )
            })
        })
}

/// A client principal from a ccache principal.
fn principal(value: &ccache::Principal) -> Principal {
    Principal::new(
        value.realm.clone(),
        value.name_type,
        value.components.clone(),
    )
}

/// Build the armor AP-REQ with a fresh subkey and derive the armor key.
///
/// # Errors
/// Returns [`Error::ArmorTicket`] for a ticket that is not `realm`'s TGT, the
/// policy refusal of its enctypes, and the AP-REQ and key errors.
fn establish(
    armor_ticket: &AsRepSession,
    realm: &str,
    crypto_policy: &CryptoPolicy,
) -> Result<Armor, Error> {
    let service = armor_ticket.service();
    if service.realm != realm || service.components != Principal::tgt_service(realm).components {
        return Err(Error::ArmorTicket {
            realm: realm.to_owned(),
            actual: service.name(),
        });
    }
    let session = armor_ticket.session_key();
    crypto_policy
        .check_use(session.etype(), Use::SessionKey)
        .map_err(Crypto::from)?;
    let decoded = ticket::decode(armor_ticket.ticket())
        .map_err(|error| codec("decode", "armor ticket", &error))?;
    crypto_policy
        .check_use(decoded.enc_part.etype, Use::TicketKey)
        .map_err(Crypto::from)?;
    let subkey =
        random_subkey_for(session).map_err(|error| Error::ArmorRequest(Box::new(error)))?;
    let kvno = decoded.enc_part.kvno;
    let message = ap_req::build(
        decoded,
        ap_req::ap_options_from_bits(0),
        &authenticator(armor_ticket.client(), &subkey)?,
        session,
        AP_REQ_AUTHENTICATOR_USAGE,
        kvno,
    )
    .map_err(|error| codec("build", "armor AP-REQ", &error))?;
    let ap_req = Zeroizing::new(
        ap_req::encode(&message).map_err(|error| codec("encode", "armor AP-REQ", &error))?,
    );
    let key = keys::cf2((&subkey, b"subkeyarmor"), (session, b"ticketarmor"))?;
    crypto_policy
        .check_use(key.etype(), Use::SessionKey)
        .map_err(Crypto::from)?;
    Ok(Armor { key, ap_req })
}

/// The armor authenticator: the client, the current time and the subkey.
///
/// # Errors
/// Returns [`Error::Codec`] for an unrepresentable name or time.
fn authenticator(
    client: &Principal,
    subkey: &EncryptionKey,
) -> Result<rasn_kerberos::Authenticator, Error> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| codec("encode", "authenticator time", &error))?;
    let whole = UNIX_EPOCH
        .checked_add(Duration::from_secs(elapsed.as_secs()))
        .ok_or(Error::Malformed {
            structure: "authenticator",
            reason: "the time is out of range",
        })?;
    let string = |value: &str| {
        KerberosString::try_from(value.to_owned())
            .map_err(|error| codec("encode", "principal", &error))
    };
    Ok(rasn_kerberos::Authenticator {
        authenticator_vno: Integer::from(5_i32),
        crealm: string(&client.realm)?,
        cname: PrincipalName {
            r#type: client.name_type,
            string: client
                .components
                .iter()
                .map(|component| string(component))
                .collect::<Result<_, _>>()?,
        },
        cksum: None,
        cusec: Integer::from(elapsed.subsec_micros()),
        ctime: KerberosTime(chrono::DateTime::<chrono::Utc>::from(whole).into()),
        subkey: Some(rasn_kerberos::EncryptionKey {
            r#type: subkey.etype(),
            value: subkey.value().to_vec().into(),
        }),
        seq_number: None,
        authorization_data: None,
    })
}

/// Wrap `message`: its padata (with the cookie) and body go into the
/// encrypted `KrbFastReq`; the outer request carries the body and only
/// `PA-FX-FAST` (RFC 6113 section 5.4.5).
///
/// # Errors
/// Returns the encoding and key errors.
pub(super) fn wrap(
    armor: &Armor,
    message: rasn_kerberos::AsReq,
    request: &super::ArmorRequest<'_>,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let rasn_kerberos::AsReq(mut outer) = message;
    if request.canonicalize
        && let Some(mut bit) = outer.req_body.kdc_options.0.get_mut(CANONICALIZE_BIT)
    {
        *bit = true;
    }
    let mut padata = outer.padata.take().unwrap_or_default();
    if let Some(cookie) = request.cookie
        && !padata.iter().any(|entry| entry.r#type == PA_FX_COOKIE)
    {
        padata.push(PaData {
            r#type: PA_FX_COOKIE,
            value: cookie.to_vec().into(),
        });
    }
    let body = encode("KDC-REQ-BODY", &outer.req_body)?;
    let inner = encode(
        "KrbFastReq",
        &KrbFastReq::new(
            KerberosFlags::from_slice(&[0; 4]),
            padata,
            outer.req_body.clone(),
        ),
    )?;
    let armored = PaFxFastRequest::ArmoredData(KrbFastArmoredReq::new(
        Some(KrbFastArmor::new(
            ARMOR_AP_REQUEST,
            armor.ap_req.to_vec().into(),
        )),
        keys::checksum(&armor.key, KEY_USAGE_FAST_REQ_CHKSUM, &body)?,
        keys::seal(&armor.key, KEY_USAGE_FAST_ENC, &inner)?,
    ));
    outer.padata = Some(vec![PaData {
        r#type: PA_FX_FAST,
        value: encode("PA-FX-FAST-REQUEST", &armored)?.to_vec().into(),
    }]);
    encode("AS-REQ", &rasn_kerberos::AsReq(outer))
}
