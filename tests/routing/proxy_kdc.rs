//! An in-memory KDC behind the MS-KKDCP proxy seam, for the Tokio-level
//! routing tests: cross-realm TGTs along a trust list, `S4U2Self` by name or
//! certificate (with the `PA-S4U-X509-USER` reply), `S4U2Proxy` with its
//! cross-realm proxy referral, user-to-user tickets and plain service tickets.
//!
//! Every ticket it issues has a fresh session key and a record of its client;
//! a ticket for a service it knows a key of is really encrypted in that key,
//! so the service's keytab decrypts it; every other ticket is opaque.

use core::{
    fmt::{self, Write as _},
    time::Duration,
};
use std::{
    sync::{Mutex, MutexGuard, PoisonError},
    time::{SystemTime, UNIX_EPOCH},
};

use chrono::{DateTime, FixedOffset, Utc};
use rasn::der;
use rskrb5_ng::{
    client::{AsRepSession, principal::Principal},
    config::Config,
    crypto::AesSha1Etype,
    error::KdcProxy,
    keytab::EncryptionKey,
    routing::s4u::{PA_S4U_X509_USER, PaS4uX509User, REPLY_USAGE, UserId},
    transport::{
        kkdcp::ProxyMessage,
        proxy::{KdcProxyTransport, PostFuture, Request},
    },
};
use zeroize::Zeroizing;

use crate::TestError;

/// The enctype of every key (aes256-cts-hmac-sha1-96).
const ETYPE: i32 = 18;
/// `KDC_ERR_S_PRINCIPAL_UNKNOWN`.
const S_PRINCIPAL_UNKNOWN: i32 = 7;
/// `KDC_ERR_BADOPTION`.
const BADOPTION: i32 = 13;

/// What the KDC issues: the ticket's principal, its client, the key that seals
/// it instead of the service's own, and the reply padata.
type Issue = (
    Principal,
    Principal,
    Option<EncryptionKey>,
    Option<Vec<rasn_kerberos::PaData>>,
);

/// One issued ticket: its ciphertext, client and session key.
struct Issued {
    /// The ticket's `enc-part` ciphertext, which identifies it.
    cipher: Vec<u8>,
    /// The ticket's client.
    client: Principal,
    /// The ticket's session key.
    key: EncryptionKey,
}

/// What the KDC knows and has done.
#[derive(Default)]
struct State {
    /// Every ticket issued, the test's own TGTs included.
    issued: Vec<Issued>,
    /// Long-term keys of the services whose tickets are really encrypted.
    services: Vec<(Principal, EncryptionKey)>,
    /// Cross-realm trusts `(from, to)`: the KDC of `from` issues `krbtgt/to@from`.
    trusts: Vec<(String, String)>,
    /// Resource-based delegation targets `(service, target)` a KDC allows.
    delegations: Vec<(Principal, Principal)>,
    /// The user a certificate maps to.
    certificate_user: Option<Principal>,
    /// Whether an `S4U2Self` reply omits the `PA-S4U-X509-USER` answer, as a
    /// KDC that predates it does.
    s4u_answer_omitted: bool,
    /// Every request: KDC realm and requested principal.
    log: Vec<(String, Principal)>,
    /// Requests the KDC could not answer, with the reason.
    failures: Vec<String>,
    /// Counter of the issued session keys.
    serial: u8,
}

/// The in-memory KDC.
pub(crate) struct Kdc(Mutex<State>);

impl fmt::Debug for Kdc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Kdc")
    }
}

impl Kdc {
    /// A KDC whose realms trust each other along `trusts` (both directions).
    pub(crate) fn new(trusts: &[(&str, &str)]) -> Self {
        let state = State {
            trusts: trusts
                .iter()
                .flat_map(|&(from, to)| {
                    [
                        (from.to_owned(), to.to_owned()),
                        (to.to_owned(), from.to_owned()),
                    ]
                })
                .collect(),
            ..State::default()
        };
        Self(Mutex::new(state))
    }

    /// Know the long-term key of `service`.
    pub(crate) fn with_service(self, service: Principal, key: EncryptionKey) -> Self {
        self.state().services.push((service, key));
        self
    }

    /// Let `service` delegate to `target` (resource-based constrained delegation).
    pub(crate) fn with_delegation(self, service: Principal, target: Principal) -> Self {
        self.state().delegations.push((service, target));
        self
    }

    /// Map every certificate to `user`.
    pub(crate) fn with_certificate_user(self, user: Principal) -> Self {
        self.state().certificate_user = Some(user);
        self
    }

    /// Answer `S4U2Self` without the `PA-S4U-X509-USER` element.
    pub(crate) fn without_s4u_answer(self) -> Self {
        self.state().s4u_answer_omitted = true;
        self
    }

    /// A TGT `krbtgt/<realm>@<realm>` for `client`, registered with the KDC.
    pub(crate) fn tgt(&self, client: Principal) -> Result<AsRepSession, TestError> {
        let service = Principal::new(client.realm.as_str(), 2, ["krbtgt", client.realm.as_str()]);
        let (ticket, key) = self.issue(&service, &client, None)?;
        let now = SystemTime::now();
        Ok(AsRepSession::new(
            client,
            service,
            key,
            Zeroizing::new(der::encode(&ticket)?),
            [0x40, 0, 0, 0],
            now,
            now.checked_add(Duration::from_secs(3_600))
                .ok_or("end time")?,
        ))
    }

    /// The requests the KDC could not answer.
    pub(crate) fn failures(&self) -> Vec<String> {
        self.state().failures.clone()
    }

    /// The realm and principal of every request so far.
    pub(crate) fn log(&self) -> Vec<(String, Principal)> {
        self.state().log.clone()
    }

    /// A leaked proxy transport over this KDC.
    pub(crate) fn leak(self) -> &'static Self {
        Box::leak(Box::new(self))
    }

    /// The locked state.
    fn state(&self) -> MutexGuard<'_, State> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Issue a ticket for `service` to `client`, encrypted in `seal` or the
    /// service's known key, else opaque; returns it and its session key.
    fn issue(
        &self,
        service: &Principal,
        client: &Principal,
        seal: Option<&EncryptionKey>,
    ) -> Result<(rasn_kerberos::Ticket, EncryptionKey), TestError> {
        let (serial, known) = {
            let mut state = self.state();
            state.serial = state.serial.wrapping_add(1);
            let known = state
                .services
                .iter()
                .find(|(name, _)| {
                    name.realm == service.realm && name.components == service.components
                })
                .map(|(_, long_term)| long_term.clone());
            (state.serial, known)
        };
        let key = EncryptionKey::new(ETYPE, vec![serial; 32]);
        let cipher = match seal.cloned().or(known) {
            Some(long_term) => {
                let part = rasn_kerberos::EncTicketPart {
                    flags: rasn_kerberos::TicketFlags(rasn_kerberos::KerberosFlags::from_slice(&[
                        0x40, 0, 0, 0,
                    ])),
                    key: rasn_key(&key),
                    crealm: text(&client.realm)?,
                    cname: name(client)?,
                    transited: rasn_kerberos::TransitedEncoding {
                        r#type: 1,
                        contents: Vec::new().into(),
                    },
                    auth_time: time(SystemTime::now())?,
                    start_time: None,
                    end_time: time(
                        SystemTime::now()
                            .checked_add(Duration::from_secs(3_600))
                            .ok_or("end")?,
                    )?,
                    renew_till: None,
                    caddr: None,
                    authorization_data: None,
                };
                AesSha1Etype::from_etype_id(ETYPE)
                    .ok_or("AES256")?
                    .encrypt_message_with_confounder(
                        long_term.value(),
                        &der::encode(&part)?,
                        2,
                        &[serial; 16],
                    )?
            }
            None => vec![serial; 40],
        };
        self.state().issued.push(Issued {
            cipher: cipher.clone(),
            client: client.clone(),
            key: key.clone(),
        });
        let ticket = rasn_kerberos::Ticket {
            tkt_vno: 5_i32.into(),
            realm: text(&service.realm)?,
            sname: name(service)?,
            enc_part: rasn_kerberos::EncryptedData {
                etype: ETYPE,
                kvno: Some(1),
                cipher: cipher.into(),
            },
        };
        Ok((ticket, key))
    }

    /// The client and session key of an issued ticket.
    fn lookup(
        &self,
        ticket: &rasn_kerberos::Ticket,
    ) -> Result<(Principal, EncryptionKey), TestError> {
        self.state()
            .issued
            .iter()
            .find(|issued| issued.cipher.as_slice() == ticket.enc_part.cipher.as_ref())
            .map(|issued| (issued.client.clone(), issued.key.clone()))
            .ok_or_else(|| "a ticket the KDC never issued".into())
    }

    /// Answer one TGS-REQ for the KDC of `realm`.
    fn answer(&self, realm: &str, request: &[u8]) -> Result<Vec<u8>, TestError> {
        let message: rasn_kerberos::TgsReq = der::decode(request)?;
        let body = &message.0.req_body;
        let requested = principal(&body.realm, body.sname.as_ref().ok_or("sname")?)?;
        self.state().log.push((realm.to_owned(), requested.clone()));
        let padata = message.0.padata.as_deref().unwrap_or_default();
        let header: rasn_kerberos::ApReq = der::decode(
            &padata
                .iter()
                .find(|entry| entry.r#type == 1_i32)
                .ok_or("PA-TGS-REQ")?
                .value,
        )?;
        let (header_client, header_key) = self.lookup(&header.ticket)?;
        let options = u32::from_be_bytes(
            body.kdc_options
                .0
                .as_raw_slice()
                .get(..4)
                .ok_or("options")?
                .try_into()?,
        );
        let s4u = padata.iter().find(|entry| entry.r#type == PA_S4U_X509_USER);
        let second = body.additional_tickets.as_deref().and_then(<[_]>::first);
        let decision = if let Some(element) = s4u {
            self.s4u2self(realm, requested.clone(), (&element.value, &header_key))?
        } else if options & 0x0002_0000 != 0 {
            self.s4u2proxy(
                realm,
                requested.clone(),
                (second.ok_or("evidence")?, &header_client),
            )?
        } else if options & 0x0000_0008 != 0 {
            let (_, second_key) = self.lookup(second.ok_or("second ticket")?)?;
            Ok((requested.clone(), header_client, Some(second_key), None))
        } else if self.issues(realm, &requested) {
            Ok((requested.clone(), header_client, None, None))
        } else {
            Err(S_PRINCIPAL_UNKNOWN)
        };
        match decision {
            Ok(issue) => self.tgs_rep(body, (options, &header_key), issue),
            Err(code) => error(realm, &requested, code),
        }
    }

    /// Whether the KDC of `realm` issues a plain ticket for `requested`: a
    /// cross-realm TGT along a trust, or a known service.
    fn issues(&self, realm: &str, requested: &Principal) -> bool {
        match requested.components.as_slice() {
            [first, to] if first == "krbtgt" => self.trusted(realm, to),
            _ => self.state().services.iter().any(|(service, _)| {
                service.realm == requested.realm && service.components == requested.components
            }),
        }
    }

    /// An `S4U2Self` request: the user the KDC names (from the request or the
    /// certificate), a referral to the service's realm for an enterprise name,
    /// and the checksummed `PA-S4U-X509-USER` answer.
    fn s4u2self(
        &self,
        realm: &str,
        requested: Principal,
        element: (&[u8], &EncryptionKey),
    ) -> Result<Result<Issue, i32>, TestError> {
        let user_id = PaS4uX509User::decode_der(element.0)?.user_id;
        let user = match &user_id.cname {
            Some(cname) => principal(&user_id.crealm, cname)?,
            None => self
                .state()
                .certificate_user
                .clone()
                .ok_or("no certificate user")?,
        };
        let issued_for = if requested.name_type == 10_i32 {
            let (_, home) = requested
                .components
                .first()
                .and_then(|enterprise| enterprise.split_once('@'))
                .ok_or("enterprise")?;
            if !self.trusted(realm, home) {
                return Ok(Err(S_PRINCIPAL_UNKNOWN));
            }
            Principal::new(realm, 2, ["krbtgt", home])
        } else {
            requested
        };
        let reply = UserId::new(user_id.nonce, Some(name(&user)?), text(&user.realm)?, None);
        let answer = PaS4uX509User::sign(reply, element.1, REPLY_USAGE)?;
        let padata = (!self.state().s4u_answer_omitted).then_some(vec![rasn_kerberos::PaData {
            r#type: PA_S4U_X509_USER,
            value: der::encode(&answer)?.into(),
        }]);
        Ok(Ok((issued_for, user, None, padata)))
    }

    /// An `S4U2Proxy` request: a proxy TGT to the target's realm when the
    /// target lives elsewhere, else the delegated ticket when the target trusts
    /// the service.
    fn s4u2proxy(
        &self,
        realm: &str,
        requested: Principal,
        tickets: (&rasn_kerberos::Ticket, &Principal),
    ) -> Result<Result<Issue, i32>, TestError> {
        let (user, _) = self.lookup(tickets.0)?;
        let elsewhere = self
            .state()
            .services
            .iter()
            .find(|(service, _)| {
                service.components == requested.components && service.realm != realm
            })
            .map(|(service, _)| service.realm.clone());
        if let Some(target) = elsewhere.filter(|_| requested.realm == realm) {
            return Ok(Ok((
                Principal::new(realm, 2, ["krbtgt", target.as_str()]),
                user,
                None,
                None,
            )));
        }
        let allowed = self.state().delegations.iter().any(|(service, target)| {
            service.components == tickets.1.components && target.components == requested.components
        });
        Ok(if allowed {
            Ok((requested, user, None, None))
        } else {
            Err(BADOPTION)
        })
    }

    /// The TGS-REP issuing `issue` for the request `body`, sealed in the header key.
    fn tgs_rep(
        &self,
        body: &rasn_kerberos::KdcReqBody,
        header: (u32, &EncryptionKey),
        issue: Issue,
    ) -> Result<Vec<u8>, TestError> {
        let (issued_for, client, seal, reply_padata) = issue;
        let (options, header_key) = header;
        let (ticket, key) = self.issue(&issued_for, &client, seal.as_ref())?;
        let now = time(SystemTime::now())?;
        let part = rasn_kerberos::EncTgsRepPart(rasn_kerberos::EncKdcRepPart {
            key: rasn_key(&key),
            last_req: Vec::new(),
            nonce: body.nonce,
            key_expiration: None,
            flags: rasn_kerberos::TicketFlags(rasn_kerberos::KerberosFlags::from_slice(&[
                options.to_be_bytes()[0] & 0x40,
                0,
                0,
                0,
            ])),
            auth_time: now.clone(),
            start_time: Some(now),
            end_time: body.till.clone(),
            renew_till: None,
            srealm: text(&issued_for.realm)?,
            sname: name(&issued_for)?,
            caddr: None,
            encrypted_pa_data: None,
        });
        let cipher = AesSha1Etype::from_etype_id(ETYPE)
            .ok_or("AES256")?
            .encrypt_message_with_confounder(
                header_key.value(),
                &der::encode(&part)?,
                8,
                &[0x44; 16],
            )?;
        Ok(der::encode(&rasn_kerberos::TgsRep(
            rasn_kerberos::KdcRep {
                pvno: 5_i32.into(),
                msg_type: 13_i32.into(),
                padata: reply_padata,
                crealm: text(&client.realm)?,
                cname: name(&client)?,
                ticket,
                enc_part: rasn_kerberos::EncryptedData {
                    etype: ETYPE,
                    kvno: None,
                    cipher: cipher.into(),
                },
            },
        ))?)
    }

    /// Whether the KDC of `from` issues `krbtgt/to@from`.
    fn trusted(&self, from: &str, to: &str) -> bool {
        self.state()
            .trusts
            .iter()
            .any(|(left, right)| left == from && right == to)
    }
}

impl KdcProxyTransport for Kdc {
    fn post<'request>(&'request self, request: Request<'request>) -> PostFuture<'request> {
        let reply = ProxyMessage::decode(request.body)
            .map_err(|error| error.to_string())
            .and_then(|message| {
                let framed = message.kerb_message();
                self.answer(request.realm, framed.get(4..).unwrap_or_default())
                    .map_err(|error| {
                        let text = error.to_string();
                        self.state().failures.push(text.clone());
                        text
                    })
            })
            .and_then(|reply| {
                let length = u32::try_from(reply.len()).map_err(|error| error.to_string())?;
                let mut framed = length.to_be_bytes().to_vec();
                framed.extend_from_slice(&reply);
                ProxyMessage::new(&framed, None, None)
                    .encode()
                    .map(|encoded| encoded.to_vec())
                    .map_err(|error| error.to_string())
            });
        Box::pin(async move { reply.map_err(|text| KdcProxy::NotDelivered(text.into())) })
    }
}

/// A profile of `realms`, each reached through the proxy, with the
/// `[libdefaults]` relations in `libdefaults`.
pub(crate) fn profile(realms: &[&str], libdefaults: &str) -> Result<Config, TestError> {
    let mut blocks = String::new();
    for realm in realms {
        writeln!(
            blocks,
            " {realm} = {{\n  kdc = https://kdc.{}/KdcProxy\n  http_anchors = FILE:/unused.pem\n }}",
            realm.to_ascii_lowercase()
        )?;
    }
    Ok(Config::parse(&format!(
        "[libdefaults]\n dns_lookup_kdc = false\n dns_lookup_realm = false\n{libdefaults}[realms]\n{blocks}"
    ))?)
}

/// A KRB-ERROR of `code` from the KDC of `realm`.
fn error(realm: &str, requested: &Principal, code: i32) -> Result<Vec<u8>, TestError> {
    Ok(der::encode(&rasn_kerberos::KrbError {
        pvno: 5_i32.into(),
        msg_type: 30_i32.into(),
        ctime: None,
        cusec: None,
        stime: time(SystemTime::now())?,
        susec: 0_i32.into(),
        error_code: code,
        crealm: None,
        cname: None,
        realm: text(realm)?,
        sname: name(requested)?,
        e_text: None,
        e_data: None,
    })?)
}

/// A DER encryption key.
fn rasn_key(key: &EncryptionKey) -> rasn_kerberos::EncryptionKey {
    rasn_kerberos::EncryptionKey {
        r#type: key.etype(),
        value: key.value().to_vec().into(),
    }
}

/// A Kerberos string.
fn text(value: &str) -> Result<rasn_kerberos::KerberosString, TestError> {
    rasn_kerberos::KerberosString::from_bytes(value.as_bytes())
        .map_err(|cause| format!("Kerberos string: {cause:?}").into())
}

/// The principal name of `principal`.
fn name(principal: &Principal) -> Result<rasn_kerberos::PrincipalName, TestError> {
    Ok(rasn_kerberos::PrincipalName {
        r#type: principal.name_type,
        string: principal
            .components
            .iter()
            .map(|component| text(component))
            .collect::<Result<_, _>>()?,
    })
}

/// A principal from its DER realm and name.
fn principal(
    realm: &rasn_kerberos::Realm,
    name: &rasn_kerberos::PrincipalName,
) -> Result<Principal, TestError> {
    Ok(Principal::new(
        String::from_utf8(realm.as_bytes().to_vec())?,
        name.r#type,
        name.string
            .iter()
            .map(|part| String::from_utf8(part.as_bytes().to_vec()))
            .collect::<Result<Vec<_>, _>>()?,
    ))
}

/// A whole-second Kerberos time.
fn time(at: SystemTime) -> Result<rasn_kerberos::KerberosTime, TestError> {
    let seconds = at.duration_since(UNIX_EPOCH)?.as_secs();
    let utc = DateTime::<Utc>::from_timestamp(i64::try_from(seconds)?, 0).ok_or("time")?;
    Ok(rasn_kerberos::KerberosTime(
        utc.with_timezone(&FixedOffset::east_opt(0).ok_or("UTC")?),
    ))
}
