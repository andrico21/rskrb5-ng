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
    time::SystemTime,
};

use rasn::der;
use rskrb5_ng::{
    ap_req,
    client::principal::Principal,
    gss::iakerb::{KdcRelay, RelayFailure},
    keytab::EncryptionKey,
};

use super::{
    context::{Context as _, TestError},
    seal::{
        ETYPE, PREAUTH_REQUIRED, REALM, S_PRINCIPAL_UNKNOWN, USER, cipher, name, rasn_key, sealed,
        service_key, text, tgs_key, time, user_key,
    },
};

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
