//! An in-process KDC and the relay the acceptor reaches it through.
//!
//! One realm, one user with a password, one `krbtgt`, and the `HTTP/<host>`
//! services of its keytab. It answers a password AS exchange (a probe that
//! asks for preauthentication, then the encrypted timestamp) and the TGS
//! exchange for those services, with real encryption in fixed AES256 keys, so
//! the crate's own acceptor opens the tickets it issues.

use core::time::Duration;
use std::{
    sync::{Mutex, MutexGuard, PoisonError},
    time::{SystemTime, UNIX_EPOCH},
};

use chrono::{DateTime, FixedOffset, Utc};
use rasn::der;
use rskrb5_ng::{
    ap_req,
    client::principal::Principal,
    crypto::AesSha1Etype,
    gss::iakerb::{KdcRelay, RelayFailure},
    keytab::EncryptionKey,
    ticket,
};

use super::context::{Context as _, TestError};

/// The realm.
pub(super) const REALM: &str = "EXAMPLE.COM";
/// The user.
pub(super) const USER: &str = "alice";
/// The user's password.
pub(super) const PASSWORD: &[u8] = b"correct horse";
/// aes256-cts-hmac-sha1-96.
const ETYPE: i32 = 18;
/// `KDC_ERR_PREAUTH_REQUIRED`.
const PREAUTH_REQUIRED: i32 = 25;
/// `KDC_ERR_S_PRINCIPAL_UNKNOWN`.
const S_PRINCIPAL_UNKNOWN: i32 = 7;

/// The cipher.
fn cipher() -> Result<AesSha1Etype, TestError> {
    AesSha1Etype::from_etype_id(ETYPE).context("AES256")
}

/// The key of the user, as the KDC derives it.
fn user_key() -> Result<EncryptionKey, TestError> {
    let salt = format!("{REALM}{USER}");
    let bytes = cipher()?.string_to_key(PASSWORD, salt.as_bytes(), "00001000")?;
    Ok(EncryptionKey::new(ETYPE, bytes))
}

/// The key of `krbtgt/REALM`.
fn tgs_key() -> EncryptionKey {
    EncryptionKey::new(ETYPE, vec![0x71; 32])
}

/// The long-term key of `HTTP/<host>`, the one `super::support::keytab` holds.
pub(super) fn service_key(host: &str) -> EncryptionKey {
    let seed = host.bytes().fold(0x5c_u8, u8::wrapping_add);
    EncryptionKey::new(ETYPE, vec![seed; 32])
}

/// A Kerberos string.
fn text(value: &str) -> Result<rasn_kerberos::KerberosString, TestError> {
    rasn_kerberos::KerberosString::from_bytes(value.as_bytes())
        .map_err(|cause| format!("Kerberos string: {cause:?}").into())
}

/// A principal name.
fn name(kind: i32, components: &[&str]) -> Result<rasn_kerberos::PrincipalName, TestError> {
    Ok(rasn_kerberos::PrincipalName {
        r#type: kind,
        string: components
            .iter()
            .map(|component| text(component))
            .collect::<Result<_, _>>()?,
    })
}

/// A whole-second Kerberos time.
fn time(at: SystemTime) -> Result<rasn_kerberos::KerberosTime, TestError> {
    let seconds = at.duration_since(UNIX_EPOCH)?.as_secs();
    let utc = DateTime::<Utc>::from_timestamp(i64::try_from(seconds)?, 0).context("time")?;
    Ok(rasn_kerberos::KerberosTime(
        utc.with_timezone(&FixedOffset::east_opt(0).context("UTC")?),
    ))
}

/// A DER encryption key.
fn rasn_key(key: &EncryptionKey) -> rasn_kerberos::EncryptionKey {
    rasn_kerberos::EncryptionKey {
        r#type: key.etype(),
        value: key.value().to_vec().into(),
    }
}

/// The DER ticket for `server`, sealed in its key, for `client`, valid over `at`.
fn sealed(
    server: (&[&str], &EncryptionKey),
    client: &str,
    session: &EncryptionKey,
    at: (SystemTime, SystemTime),
) -> Result<Vec<u8>, TestError> {
    let part = rasn_kerberos::EncTicketPart {
        flags: rasn_kerberos::TicketFlags(rasn_kerberos::KerberosFlags::from_slice(&[
            0x40, 0, 0, 0,
        ])),
        key: rasn_key(session),
        crealm: text(REALM)?,
        cname: name(1, &[client])?,
        transited: rasn_kerberos::TransitedEncoding {
            r#type: 1,
            contents: Vec::new().into(),
        },
        auth_time: time(at.0)?,
        start_time: None,
        end_time: time(at.1)?,
        renew_till: None,
        caddr: None,
        authorization_data: None,
    };
    let kind: i32 = if server.0.first() == Some(&"krbtgt") {
        2
    } else {
        3
    };
    Ok(ticket::encode_build_ticket_with_confounder(
        text(REALM)?,
        name(kind, server.0)?,
        &part,
        server.1,
        Some(1),
        &[0x12; 16],
    )?)
}

/// The DER ticket of the user for `HTTP/www.example.com`, valid over `at`.
pub(super) fn service_ticket(
    session: &EncryptionKey,
    at: (SystemTime, SystemTime),
) -> Result<Vec<u8>, TestError> {
    sealed(
        (
            &["HTTP", super::support::HOST],
            &service_key(super::support::HOST),
        ),
        USER,
        session,
        at,
    )
}

/// The in-process KDC.
#[derive(Debug, Default)]
pub(super) struct Kdc {
    /// The kinds of request answered, in order: `AS` or `TGS` and the realm.
    log: Mutex<Vec<(String, &'static str)>>,
}

impl Kdc {
    /// A KDC.
    pub(super) fn new() -> Self {
        Self::default()
    }

    /// The requests answered so far.
    pub(super) fn log(&self) -> Vec<(String, &'static str)> {
        self.state().clone()
    }

    /// The locked log.
    fn state(&self) -> MutexGuard<'_, Vec<(String, &'static str)>> {
        self.log.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// A ticket for `server`, sealed in its key, for `client`, valid for an hour.
    fn issue(
        server: (&[&str], &EncryptionKey),
        client: &str,
        session: &EncryptionKey,
    ) -> Result<rasn_kerberos::Ticket, TestError> {
        let now = SystemTime::now();
        let end = now.checked_add(Duration::from_hours(1)).context("end")?;
        Ok(der::decode(&sealed(server, client, session, (now, end))?)?)
    }

    /// A KRB-ERROR of `code`, with `data` as its e-data.
    fn error(
        code: i32,
        sname: (i32, &[&str]),
        data: Option<Vec<u8>>,
    ) -> Result<Vec<u8>, TestError> {
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
            realm: text(REALM)?,
            sname: name(sname.0, sname.1)?,
            e_text: None,
            e_data: data.map(Into::into),
        })?)
    }

    /// The reply part: `key`, the request's nonce, valid for an hour.
    fn reply_part(
        body: &rasn_kerberos::KdcReqBody,
        key: &EncryptionKey,
        sname: (i32, &[&str]),
    ) -> Result<rasn_kerberos::EncKdcRepPart, TestError> {
        let now = time(SystemTime::now())?;
        Ok(rasn_kerberos::EncKdcRepPart {
            key: rasn_key(key),
            last_req: Vec::new(),
            nonce: body.nonce,
            key_expiration: None,
            flags: rasn_kerberos::TicketFlags(rasn_kerberos::KerberosFlags::from_slice(&[
                0, 0, 0, 0,
            ])),
            auth_time: now.clone(),
            start_time: Some(now),
            end_time: body.till.clone(),
            renew_till: None,
            srealm: text(REALM)?,
            sname: name(sname.0, sname.1)?,
            caddr: None,
            encrypted_pa_data: None,
        })
    }

    /// The AS exchange: a probe is told to preauthenticate, the encrypted
    /// timestamp under the user's key gets the TGT.
    fn as_exchange(request: &[u8]) -> Result<Vec<u8>, TestError> {
        let message: rasn_kerberos::AsReq = der::decode(request)?;
        let body = &message.0.req_body;
        let padata = message.0.padata.as_deref().unwrap_or_default();
        let key = user_key()?;
        let Some(timestamp) = padata.iter().find(|entry| entry.r#type == 2_i32) else {
            let info = rasn_kerberos::EtypeInfo2::from([rasn_kerberos::EtypeInfo2Entry {
                etype: ETYPE,
                salt: Some(text(&format!("{REALM}{USER}"))?),
                s2kparams: None,
            }]);
            let offers = rasn_kerberos::MethodData::from([rasn_kerberos::PaData {
                r#type: 19,
                value: der::encode(&info)?.into(),
            }]);
            return Self::error(
                PREAUTH_REQUIRED,
                (2_i32, &["krbtgt", REALM]),
                Some(der::encode(&offers)?),
            );
        };
        let sealed: rasn_kerberos::EncryptedData = der::decode(&timestamp.value)?;
        drop(cipher()?.decrypt_message(key.value(), sealed.cipher.as_ref(), 1)?);
        let session = EncryptionKey::new(ETYPE, vec![0x6d; 32]);
        let ticket = Self::issue((&["krbtgt", REALM], &tgs_key()), USER, &session)?;
        let part = rasn_kerberos::EncAsRepPart(Self::reply_part(
            body,
            &session,
            (2_i32, &["krbtgt", REALM]),
        )?);
        let cipher_text = cipher()?.encrypt_message_with_confounder(
            key.value(),
            &der::encode(&part)?,
            3,
            &[0x33; 16],
        )?;
        Ok(der::encode(&rasn_kerberos::AsRep(rasn_kerberos::KdcRep {
            pvno: 5_i32.into(),
            msg_type: 11_i32.into(),
            padata: None,
            crealm: text(REALM)?,
            cname: name(1, &[USER])?,
            ticket,
            enc_part: rasn_kerberos::EncryptedData {
                etype: ETYPE,
                kvno: None,
                cipher: cipher_text.into(),
            },
        }))?)
    }

    /// The TGS exchange for an `HTTP/<host>` service of the realm.
    fn tgs_exchange(request: &[u8]) -> Result<Vec<u8>, TestError> {
        let message: rasn_kerberos::TgsReq = der::decode(request)?;
        let body = &message.0.req_body;
        let padata = message.0.padata.as_deref().unwrap_or_default();
        let header: rasn_kerberos::ApReq = der::decode(
            &padata
                .iter()
                .find(|entry| entry.r#type == 1_i32)
                .context("PA-TGS-REQ")?
                .value,
        )?;
        let sealed = cipher()?.decrypt_message(
            tgs_key().value(),
            header.ticket.enc_part.cipher.as_ref(),
            2,
        )?;
        let enc: rasn_kerberos::EncTicketPart = der::decode(&sealed)?;
        let session = EncryptionKey::new(enc.key.r#type, enc.key.value.to_vec());
        let authenticator = ap_req::decrypt_ap_req_authenticator(&header, &session, 7)?;
        let components: Vec<String> = body
            .sname
            .as_ref()
            .context("sname")?
            .string
            .iter()
            .map(|part| String::from_utf8(part.as_bytes().to_vec()))
            .collect::<Result<_, _>>()?;
        let parts: Vec<&str> = components.iter().map(String::as_str).collect();
        let [service, host] = parts.as_slice() else {
            return Self::error(S_PRINCIPAL_UNKNOWN, (3_i32, &parts), None);
        };
        let issued = EncryptionKey::new(ETYPE, vec![0x4b; 32]);
        let ticket = Self::issue((&parts, &service_key(host)), USER, &issued)?;
        let part = rasn_kerberos::EncTgsRepPart(Self::reply_part(
            body,
            &issued,
            (3_i32, &[service, host]),
        )?);
        let (reply_key, usage) = authenticator.subkey.as_ref().map_or_else(
            || (session.clone(), 8_u32),
            |subkey| {
                (
                    EncryptionKey::new(subkey.r#type, subkey.value.to_vec()),
                    9_u32,
                )
            },
        );
        let cipher_text = cipher()?.encrypt_message_with_confounder(
            reply_key.value(),
            &der::encode(&part)?,
            usage,
            &[0x44; 16],
        )?;
        Ok(der::encode(&rasn_kerberos::TgsRep(
            rasn_kerberos::KdcRep {
                pvno: 5_i32.into(),
                msg_type: 13_i32.into(),
                padata: None,
                crealm: text(REALM)?,
                cname: name(1, &[USER])?,
                ticket,
                enc_part: rasn_kerberos::EncryptedData {
                    etype: ETYPE,
                    kvno: None,
                    cipher: cipher_text.into(),
                },
            },
        ))?)
    }

    /// Answer `request` for the KDC of `realm`.
    pub(super) fn answer(&self, realm: &str, request: &[u8]) -> Result<Vec<u8>, TestError> {
        if realm != REALM {
            return Err(format!("no KDC of {realm}").into());
        }
        match request.first() {
            Some(0x6a) => {
                self.state().push((realm.to_owned(), "AS"));
                Self::as_exchange(request)
            }
            Some(0x6c) => {
                self.state().push((realm.to_owned(), "TGS"));
                Self::tgs_exchange(request)
            }
            _ => Err("neither an AS-REQ nor a TGS-REQ".into()),
        }
    }
}

/// The application's relay: it hands every request to the [`Kdc`] and
/// records what it was asked.
#[derive(Debug)]
pub(super) struct Relay<'kdc> {
    /// The KDC behind the relay.
    pub kdc: &'kdc Kdc,
    /// The `(realm, request)` pairs the acceptor relayed.
    pub asked: Vec<(String, Vec<u8>)>,
    /// A failure to report instead of an answer.
    pub failure: Option<RelayFailure>,
}

impl<'kdc> Relay<'kdc> {
    /// A relay to `kdc`.
    pub(super) const fn new(kdc: &'kdc Kdc) -> Self {
        Self {
            kdc,
            asked: Vec::new(),
            failure: None,
        }
    }
}

impl KdcRelay for Relay<'_> {
    fn relay(&mut self, realm: &str, request: &[u8]) -> Result<Vec<u8>, RelayFailure> {
        self.asked.push((realm.to_owned(), request.to_vec()));
        if let Some(failure) = &self.failure {
            return Err(failure.clone());
        }
        self.kdc
            .answer(realm, request)
            .map_err(|cause| RelayFailure::Other(cause.to_string()))
    }
}

/// The client principal.
pub(super) fn client() -> Principal {
    Principal::user(REALM, USER)
}
