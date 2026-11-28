//! A deterministic FAST KDC for one realm.
//!
//! It checks the armor AP-REQ, the request checksum and the inner request, answers with an armored
//! `PREAUTH_REQUIRED` that offers the encrypted challenge, and issues an
//! armored AS-REP for a valid challenge. One [`Tamper`] switch at a time
//! breaks one RFC 6113 rule.

use core::{error::Error, time::Duration};
use std::time::{SystemTime, UNIX_EPOCH};

use rasn::{der, types::Integer};
use rasn_kerberos::{
    ApReq, AsRep, Authenticator, Checksum, EncKdcRepPart, EncTicketPart, EncryptedData,
    EtypeInfo2Entry, KdcRep, KerberosFlags, KerberosString, KerberosTime, KrbError, PaData,
    PaEncTsEnc, PrincipalName, Ticket, TicketFlags, TransitedEncoding,
};
use rskrb5_ng::{
    client::{AsRepSession, principal::Principal},
    crypto::{KerberosEtype, prf},
    kdc_rep,
    keytab::EncryptionKey,
    preauth::fast::{PA_ENCRYPTED_CHALLENGE, PA_FX_COOKIE, PA_FX_ERROR, PA_FX_FAST},
};

use super::asn1::{
    KrbFastArmoredRep, KrbFastFinished, KrbFastReq, KrbFastResponse, PaFxFastReply, PaFxFastRequest,
};

/// The test realm.
pub(crate) const REALM: &str = "FAST.TEST";
/// The client.
pub(crate) const CLIENT: &str = "alice";
/// A boxed test failure.
pub(crate) type TestError = Box<dyn Error>;

/// One RFC 6113 rule the KDC breaks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Tamper {
    /// Nothing.
    None,
    /// The AS-REP has no `KrbFastFinished` (MIT `fast.c:534-538`).
    DropFinished,
    /// The finished ticket checksum is corrupted.
    TicketChecksum,
    /// The finished ticket checksum has a type other than the armor key's.
    TicketChecksumType,
    /// The `KrbFastResponse` nonce is not the request's.
    Nonce,
    /// The AS-REP carries no strengthen key and uses the long-term key.
    DropStrengthenKey,
    /// The strengthen key in the FAST response is not the one that encrypted the reply.
    StrengthenKey,
    /// The AS-REP carries no KDC `PA-ENCRYPTED-CHALLENGE`.
    DropKdcChallenge,
    /// The KDC challenge is encrypted in the client challenge key.
    KdcChallengeKey,
    /// The armored error carries a strengthen key.
    ErrorStrengthenKey,
    /// The armored error carries no `PA-FX-ERROR`.
    ErrorWithoutFxError,
    /// The error is not armored.
    UnarmoredError,
    /// The AS-REP is not armored.
    UnarmoredReply,
    /// The armored error's cookie exceeds the client's bound.
    OversizedCookie,
    /// The armored error's ciphertext is corrupted.
    ErrorCiphertext,
    /// The armored AS-REP's ciphertext is corrupted.
    ReplyCiphertext,
}

/// The fake KDC.
pub(crate) struct Kdc {
    /// The `krbtgt/REALM` key.
    tgs_key: EncryptionKey,
    /// The client's long-term key.
    client_key: EncryptionKey,
    /// The rule to break.
    tamper: Tamper,
    /// The client name the finished message reports, if not the requested one.
    canonical: Option<&'static str>,
    /// Every request received, as sent.
    requests: Vec<Vec<u8>>,
    /// Whether a valid encrypted challenge arrived.
    challenge_verified: bool,
    /// The cookie of the armored error.
    cookie: Vec<u8>,
    /// The realm a request to [`REALM`] is referred to.
    referral: Option<&'static str>,
    /// How many seconds the KDC clock runs ahead of the client's.
    ahead: u64,
    /// The time of the last verified encrypted challenge, in Unix seconds.
    challenge_time: Option<i64>,
}

impl Kdc {
    /// A KDC with fixed keys.
    pub(crate) fn new() -> Self {
        Self {
            tgs_key: EncryptionKey::new(18, vec![0x11; 32]),
            client_key: EncryptionKey::new(18, vec![0x22; 32]),
            tamper: Tamper::None,
            canonical: None,
            requests: Vec::new(),
            challenge_verified: false,
            cookie: b"MIT\x01cookie-state".to_vec(),
            referral: None,
            ahead: 0,
            challenge_time: None,
        }
    }

    /// A KDC whose clock runs `seconds` ahead of the client's.
    pub(crate) fn ahead(seconds: u64) -> Self {
        Self {
            ahead: seconds,
            ..Self::new()
        }
    }

    /// The time of the last verified encrypted challenge, in Unix seconds.
    pub(crate) const fn challenge_time(&self) -> Option<i64> {
        self.challenge_time
    }

    /// A KDC that breaks `tamper`.
    pub(crate) fn tampering(tamper: Tamper) -> Self {
        Self {
            tamper,
            ..Self::new()
        }
    }

    /// A KDC whose finished message reports `client`.
    pub(crate) fn canonicalizing(client: &'static str) -> Self {
        Self {
            canonical: Some(client),
            ..Self::new()
        }
    }

    /// A KDC that refers requests to [`REALM`] to `realm` (RFC 6806 section 7).
    pub(crate) fn referring(realm: &'static str) -> Self {
        Self {
            referral: Some(realm),
            ..Self::new()
        }
    }

    /// Every request received, as sent.
    pub(crate) fn requests(&self) -> &[Vec<u8>] {
        &self.requests
    }

    /// Whether a valid encrypted challenge arrived.
    pub(crate) const fn challenge_verified(&self) -> bool {
        self.challenge_verified
    }

    /// The client's long-term key.
    pub(crate) const fn client_key(&self) -> &EncryptionKey {
        &self.client_key
    }

    /// An armor TGT of the realm, issued to a host.
    pub(crate) fn armor_ticket(&self) -> Result<AsRepSession, TestError> {
        self.armor_ticket_in(REALM)
    }

    /// An armor TGT of `realm`'s TGS (this KDC serves every realm), issued to a host.
    pub(crate) fn armor_ticket_in(&self, realm: &str) -> Result<AsRepSession, TestError> {
        let session = EncryptionKey::new(18, vec![0x33; 32]);
        let ticket = self.ticket(realm, &["host", "armor.fast.test"], &session)?;
        let now = SystemTime::now();
        Ok(AsRepSession::new(
            Principal::new(realm, 3, ["host", "armor.fast.test"]),
            Principal::tgt_service(realm),
            session,
            der::encode(&ticket)?.into(),
            [0x40, 0x60, 0, 0],
            now,
            now.checked_add(Duration::from_secs(3600)).ok_or("time")?,
        ))
    }

    /// Answer one request.
    pub(crate) fn handle(&mut self, request: &[u8]) -> Result<Vec<u8>, TestError> {
        self.requests.push(request.to_vec());
        let rasn_kerberos::AsReq(outer) = der::decode(request)?;
        let padata = outer.padata.clone().unwrap_or_default();
        let [fast] = padata.as_slice() else {
            return Err("the outer request must carry exactly one padata".into());
        };
        if fast.r#type != PA_FX_FAST {
            return Err("the outer padata is not PA-FX-FAST".into());
        }
        let PaFxFastRequest::ArmoredData(armored) = der::decode(&fast.value)?;
        let armor = armored.armor.ok_or("AS armor missing")?;
        let ap_req: ApReq = der::decode(&armor.armor_value)?;
        let enc_ticket: EncTicketPart =
            der::decode(&open(&self.tgs_key, 2, &ap_req.ticket.enc_part)?)?;
        let session = EncryptionKey::new(enc_ticket.key.r#type, enc_ticket.key.value.to_vec());
        let authenticator: Authenticator =
            der::decode(&open(&session, 11, &ap_req.authenticator)?)?;
        let subkey = authenticator.subkey.ok_or("armor subkey missing")?;
        let armor_key = cf2(
            (
                &EncryptionKey::new(subkey.r#type, subkey.value.to_vec()),
                b"subkeyarmor",
            ),
            (&session, b"ticketarmor"),
        )?;
        let body = der::encode(&outer.req_body)?;
        let checksum = etype(&armor_key)?.checksum(armor_key.value(), &body, 50)?;
        if armored.req_checksum.checksum.as_ref() != checksum.as_slice() {
            return Err("the request checksum does not verify".into());
        }
        let inner: KrbFastReq = der::decode(&open(&armor_key, 51, &armored.enc_fast_req)?)?;
        if inner.req_body != outer.req_body {
            return Err("the inner body differs from the outer body".into());
        }
        let context = Context {
            armor_key,
            nonce: inner.req_body.nonce,
            request: request.to_vec(),
            realm: String::from_utf8(outer.req_body.realm.as_bytes().to_vec())?,
        };
        if let Some(referred) = self.referral
            && context.realm == REALM
        {
            return wrong_realm(&context, &inner, referred);
        }
        match inner
            .padata
            .iter()
            .find(|entry| entry.r#type == PA_ENCRYPTED_CHALLENGE)
        {
            Some(challenge) => {
                let cookie = inner
                    .padata
                    .iter()
                    .find(|entry| entry.r#type == PA_FX_COOKIE);
                if cookie.map(|entry| entry.value.to_vec()) != Some(self.cookie.clone()) {
                    return Err("the challenge does not echo the cookie".into());
                }
                let client_key = cf2(
                    (&context.armor_key, b"clientchallengearmor"),
                    (&self.client_key, b"challengelongterm"),
                )?;
                let encrypted: EncryptedData = der::decode(&challenge.value)?;
                let stamp = der::decode::<PaEncTsEnc>(&open(&client_key, 54, &encrypted)?)?;
                self.challenge_time = Some(stamp.patimestamp.0.timestamp());
                self.challenge_verified = true;
                self.as_rep(&context, &inner)
            }
            None => self.preauth_required(&context, &inner),
        }
    }

    /// The armored `PREAUTH_REQUIRED` that offers the encrypted challenge.
    fn preauth_required(
        &self,
        context: &Context,
        inner: &KrbFastReq,
    ) -> Result<Vec<u8>, TestError> {
        let clock = SystemTime::now()
            .checked_add(Duration::from_secs(self.ahead))
            .ok_or("KDC clock")?;
        let fx_error = error(inner, None, clock)?;
        let info = vec![EtypeInfo2Entry {
            etype: 18,
            salt: Some(KerberosString::try_from(format!(
                "{}{CLIENT}",
                context.realm
            ))?),
            s2kparams: None,
        }];
        let cookie = if self.tamper == Tamper::OversizedCookie {
            vec![0x43; 9000]
        } else {
            self.cookie.clone()
        };
        let mut padata = vec![
            pa(PA_FX_ERROR, der::encode(&fx_error)?),
            pa(19, der::encode(&info)?),
            pa(PA_ENCRYPTED_CHALLENGE, Vec::new()),
            pa(PA_FX_COOKIE, cookie),
        ];
        if self.tamper == Tamper::ErrorWithoutFxError {
            padata.retain(|entry| entry.r#type != PA_FX_ERROR);
        }
        let strengthen =
            (self.tamper == Tamper::ErrorStrengthenKey).then(|| rasn_kerberos::EncryptionKey {
                r#type: 18,
                value: vec![0x44; 32].into(),
            });
        let response = KrbFastResponse {
            padata,
            strengthen_key: strengthen,
            finished: None,
            nonce: context.nonce,
        };
        let mut sealed = seal(&context.armor_key, 52, &der::encode(&response)?)?;
        if self.tamper == Tamper::ErrorCiphertext {
            flip(&mut sealed)?;
        }
        let method_data = if self.tamper == Tamper::UnarmoredError {
            vec![
                pa(19, der::encode(&info)?),
                pa(PA_ENCRYPTED_CHALLENGE, Vec::new()),
            ]
        } else {
            vec![pa(
                PA_FX_FAST,
                der::encode(&PaFxFastReply::ArmoredData(KrbFastArmoredRep {
                    enc_fast_rep: sealed,
                }))?,
            )]
        };
        Ok(der::encode(&error(
            inner,
            Some(der::encode(&method_data)?),
            clock,
        )?)?)
    }

    /// The armored AS-REP of a verified challenge.
    fn as_rep(&self, context: &Context, inner: &KrbFastReq) -> Result<Vec<u8>, TestError> {
        let client = self.canonical.unwrap_or(CLIENT);
        let ticket = self.ticket(
            &context.realm,
            &[client],
            &EncryptionKey::new(18, vec![0x55; 32]),
        )?;
        let strengthen = EncryptionKey::new(18, vec![0x66; 32]);
        let unstrengthened = matches!(
            self.tamper,
            Tamper::DropStrengthenKey | Tamper::UnarmoredReply
        );
        let reply_key = if unstrengthened {
            self.client_key.clone()
        } else {
            cf2(
                (&strengthen, b"strengthenkey"),
                (&self.client_key, b"replykey"),
            )?
        };
        let enc_part = kdc_rep::encrypt_as_rep_enc_part(
            &enc_part(context, inner, &reply_key)?,
            &reply_key,
            None,
        )?;
        let reported = match self.tamper {
            Tamper::DropStrengthenKey => None,
            Tamper::StrengthenKey => Some(vec![0x67; 32]),
            Tamper::None
            | Tamper::DropFinished
            | Tamper::TicketChecksum
            | Tamper::TicketChecksumType
            | Tamper::Nonce
            | Tamper::DropKdcChallenge
            | Tamper::KdcChallengeKey
            | Tamper::ErrorStrengthenKey
            | Tamper::ErrorWithoutFxError
            | Tamper::UnarmoredError
            | Tamper::UnarmoredReply
            | Tamper::OversizedCookie
            | Tamper::ErrorCiphertext
            | Tamper::ReplyCiphertext => Some(strengthen.value().to_vec()),
        };
        let response = KrbFastResponse {
            padata: self.kdc_challenge(context)?,
            strengthen_key: reported.map(|value| rasn_kerberos::EncryptionKey {
                r#type: 18,
                value: value.into(),
            }),
            finished: (self.tamper != Tamper::DropFinished)
                .then(|| self.finished(context, client, &ticket))
                .transpose()?,
            nonce: if self.tamper == Tamper::Nonce {
                context.nonce.wrapping_add(1)
            } else {
                context.nonce
            },
        };
        let mut sealed = seal(&context.armor_key, 52, &der::encode(&response)?)?;
        if self.tamper == Tamper::ReplyCiphertext {
            flip(&mut sealed)?;
        }
        let outer_padata = if self.tamper == Tamper::UnarmoredReply {
            None
        } else {
            Some(vec![pa(
                PA_FX_FAST,
                der::encode(&PaFxFastReply::ArmoredData(KrbFastArmoredRep {
                    enc_fast_rep: sealed,
                }))?,
            )])
        };
        Ok(der::encode(&AsRep(KdcRep {
            pvno: Integer::from(5_i32),
            msg_type: Integer::from(11_i32),
            padata: outer_padata,
            crealm: string(&context.realm)?,
            cname: name(1, &[CLIENT])?,
            ticket,
            enc_part,
        }))?)
    }

    /// The finished message over `ticket` for `client`.
    fn finished(
        &self,
        context: &Context,
        client: &str,
        ticket: &Ticket,
    ) -> Result<KrbFastFinished, TestError> {
        let mut value = etype(&context.armor_key)?.checksum(
            context.armor_key.value(),
            &der::encode(ticket)?,
            53,
        )?;
        if self.tamper == Tamper::TicketChecksum {
            flip_bytes(&mut value)?;
        }
        let r#type = if self.tamper == Tamper::TicketChecksumType {
            15_i32
        } else {
            etype(&context.armor_key)?.checksum_type_id()
        };
        Ok(KrbFastFinished {
            timestamp: time(whole(SystemTime::now())?),
            usec: Integer::from(0_i32),
            crealm: string(&context.realm)?,
            cname: name(1, &[client])?,
            ticket_checksum: Checksum {
                r#type,
                checksum: value.into(),
            },
        })
    }

    /// The reply padata: the KDC's encrypted challenge.
    fn kdc_challenge(&self, context: &Context) -> Result<Vec<PaData>, TestError> {
        if self.tamper == Tamper::DropKdcChallenge {
            return Ok(Vec::new());
        }
        let pepper: &[u8] = if self.tamper == Tamper::KdcChallengeKey {
            b"clientchallengearmor"
        } else {
            b"kdcchallengearmor"
        };
        let key = cf2(
            (&context.armor_key, pepper),
            (&self.client_key, b"challengelongterm"),
        )?;
        let timestamp = der::encode(&PaEncTsEnc {
            patimestamp: time(whole(SystemTime::now())?),
            pausec: None,
        })?;
        Ok(vec![pa(
            PA_ENCRYPTED_CHALLENGE,
            der::encode(&seal(&key, 55, &timestamp)?)?,
        )])
    }

    /// A ticket of `realm` for `client`, sealed in the TGS key.
    fn ticket(
        &self,
        realm: &str,
        client: &[&str],
        session: &EncryptionKey,
    ) -> Result<Ticket, TestError> {
        let now = whole(SystemTime::now())?;
        let part = EncTicketPart {
            flags: TicketFlags(KerberosFlags::from_slice(&[0x40, 0x60, 0, 0])),
            key: rasn_kerberos::EncryptionKey {
                r#type: session.etype(),
                value: session.value().to_vec().into(),
            },
            crealm: string(realm)?,
            cname: name(1, client)?,
            transited: TransitedEncoding {
                r#type: 1,
                contents: Vec::new().into(),
            },
            auth_time: time(now),
            start_time: None,
            end_time: time(now.checked_add(Duration::from_secs(3600)).ok_or("time")?),
            renew_till: None,
            caddr: None,
            authorization_data: None,
        };
        Ok(Ticket {
            tkt_vno: Integer::from(5_i32),
            realm: string(realm)?,
            sname: name(2, &["krbtgt", realm])?,
            enc_part: seal(&self.tgs_key, 2, &der::encode(&part)?)?,
        })
    }
}

/// The armor key, the nonce and the bytes of one armored request.
struct Context {
    /// The armor key.
    armor_key: EncryptionKey,
    /// The inner request nonce.
    nonce: u32,
    /// The request as received.
    request: Vec<u8>,
    /// The realm the request was sent to.
    realm: String,
}

/// The encrypted part of the AS-REP, with the RFC 6806 checksum over the
/// request as received when the request asked for it.
fn enc_part(
    context: &Context,
    inner: &KrbFastReq,
    reply_key: &EncryptionKey,
) -> Result<EncKdcRepPart, TestError> {
    let negotiated = inner.padata.iter().any(|entry| entry.r#type == 149_i32);
    let encrypted_pa_data = if negotiated {
        let cipher = etype(reply_key)?;
        Some(vec![pa(
            149_i32,
            der::encode(&Checksum {
                r#type: cipher.checksum_type_id(),
                checksum: cipher
                    .checksum(reply_key.value(), &context.request, 56)?
                    .into(),
            })?,
        )])
    } else {
        None
    };
    let flags = if negotiated {
        0x0061_0000_u32
    } else {
        0x0060_0000_u32
    };
    Ok(EncKdcRepPart {
        key: rasn_kerberos::EncryptionKey {
            r#type: 18,
            value: vec![0x55; 32].into(),
        },
        last_req: Vec::new(),
        nonce: inner.req_body.nonce,
        key_expiration: None,
        flags: TicketFlags(KerberosFlags::from_slice(&flags.to_be_bytes())),
        auth_time: time(whole(SystemTime::now())?),
        start_time: None,
        end_time: inner.req_body.till.clone(),
        renew_till: None,
        srealm: string(&context.realm)?,
        sname: name(2, &["krbtgt", &context.realm])?,
        caddr: None,
        encrypted_pa_data,
    })
}

/// The armored `KDC_ERR_WRONG_REALM` that refers the client to `realm`.
fn wrong_realm(context: &Context, inner: &KrbFastReq, realm: &str) -> Result<Vec<u8>, TestError> {
    let mut referral = error(inner, None, SystemTime::now())?;
    referral.error_code = 68_i32;
    referral.crealm = Some(string(realm)?);
    let response = KrbFastResponse {
        padata: vec![pa(PA_FX_ERROR, der::encode(&referral)?)],
        strengthen_key: None,
        finished: None,
        nonce: context.nonce,
    };
    let sealed = seal(&context.armor_key, 52, &der::encode(&response)?)?;
    let method_data = vec![pa(
        PA_FX_FAST,
        der::encode(&PaFxFastReply::ArmoredData(KrbFastArmoredRep {
            enc_fast_rep: sealed,
        }))?,
    )];
    referral.e_data = Some(der::encode(&method_data)?.into());
    Ok(der::encode(&referral)?)
}

/// The KRB-ERROR `PREAUTH_REQUIRED` for `inner` with `e_data` at the KDC time `stime`.
fn error(
    inner: &KrbFastReq,
    e_data: Option<Vec<u8>>,
    stime: SystemTime,
) -> Result<KrbError, TestError> {
    let realm = String::from_utf8(inner.req_body.realm.as_bytes().to_vec())?;
    Ok(KrbError {
        pvno: Integer::from(5_i32),
        msg_type: Integer::from(30_i32),
        ctime: None,
        cusec: None,
        stime: time(whole(stime)?),
        susec: Integer::from(0_i32),
        error_code: 25,
        crealm: Some(string(&realm)?),
        cname: inner.req_body.cname.clone(),
        realm: string(&realm)?,
        sname: name(2, &["krbtgt", &realm])?,
        e_text: None,
        e_data: e_data.map(Into::into),
    })
}

/// One PA-DATA.
pub(crate) fn pa(r#type: i32, value: Vec<u8>) -> PaData {
    PaData {
        r#type,
        value: value.into(),
    }
}

/// The implemented enctype of `key`.
pub(crate) fn etype(key: &EncryptionKey) -> Result<KerberosEtype, TestError> {
    Ok(KerberosEtype::from_etype_id(key.etype()).ok_or("enctype")?)
}

/// `KRB-FX-CF2` of two keys.
pub(crate) fn cf2(
    (first, first_pepper): (&EncryptionKey, &[u8]),
    (second, second_pepper): (&EncryptionKey, &[u8]),
) -> Result<EncryptionKey, TestError> {
    let combined = prf::krb_fx_cf2(
        &prf::CfInput::new(prf::Key::new(etype(first)?, first.value()), first_pepper),
        &prf::CfInput::new(prf::Key::new(etype(second)?, second.value()), second_pepper),
    )?;
    Ok(EncryptionKey::new(first.etype(), combined.to_vec()))
}

/// Encrypt with a fixed confounder.
pub(crate) fn seal(
    key: &EncryptionKey,
    usage: u32,
    plain: &[u8],
) -> Result<EncryptedData, TestError> {
    let cipher = etype(key)?;
    let sealed = cipher.encrypt_message_with_confounder(
        key.value(),
        plain,
        usage,
        &vec![0x5a; cipher.confounder_len()],
    )?;
    Ok(EncryptedData {
        etype: key.etype(),
        kvno: None,
        cipher: sealed.into(),
    })
}

/// Decrypt.
pub(crate) fn open(
    key: &EncryptionKey,
    usage: u32,
    encrypted: &EncryptedData,
) -> Result<Vec<u8>, TestError> {
    Ok(etype(key)?.decrypt_message(key.value(), &encrypted.cipher, usage)?)
}

/// Corrupt the first ciphertext byte.
pub(crate) fn flip(encrypted: &mut EncryptedData) -> Result<(), TestError> {
    let mut bytes = encrypted.cipher.to_vec();
    flip_bytes(&mut bytes)?;
    encrypted.cipher = bytes.into();
    Ok(())
}

/// Corrupt the first byte.
pub(crate) fn flip_bytes(bytes: &mut [u8]) -> Result<(), TestError> {
    let first = bytes.first_mut().ok_or("empty")?;
    *first ^= 0x01;
    Ok(())
}

/// `value` truncated to whole seconds.
pub(crate) fn whole(value: SystemTime) -> Result<SystemTime, TestError> {
    let seconds = value.duration_since(UNIX_EPOCH)?.as_secs();
    Ok(UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds))
        .ok_or("time")?)
}

/// A Kerberos time.
pub(crate) fn time(value: SystemTime) -> KerberosTime {
    KerberosTime(chrono::DateTime::<chrono::Utc>::from(value).into())
}

/// A Kerberos string.
pub(crate) fn string(value: &str) -> Result<KerberosString, TestError> {
    Ok(KerberosString::try_from(value.to_owned())?)
}

/// A principal name.
pub(crate) fn name(r#type: i32, components: &[&str]) -> Result<PrincipalName, TestError> {
    Ok(PrincipalName {
        r#type,
        string: components
            .iter()
            .map(|component| string(component))
            .collect::<Result<_, _>>()?,
    })
}
