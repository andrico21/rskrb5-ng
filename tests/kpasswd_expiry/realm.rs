//! A fake realm: an AS exchange that checks the pre-authentication against the
//! account's current password, and the account's expiry state.

use core::time::Duration;
use std::{sync::Mutex, time::SystemTime};

use chrono::{DateTime, FixedOffset, Utc};
use rasn::{der, types::Integer};
use rskrb5_ng::{
    client::{
        AS_REP_ENCPART_USAGE, KDC_ERR_PREAUTH_REQUIRED, PA_ENC_TIMESTAMP, PA_ETYPE_INFO2,
        PreauthKeyInfo, derive_password_reply_key, principal::Principal,
    },
    crypto::AesSha1Etype,
    keytab::EncryptionKey,
};

use super::{
    TestError,
    support::{REALM, changepw_key, held, ticket_for},
};

/// RFC 4120 `KDC_ERR_KEY_EXPIRED`.
pub(super) const KDC_ERR_KEY_EXPIRED: i32 = 23;
/// RFC 4120 `KDC_ERR_PREAUTH_FAILED`.
const KDC_ERR_PREAUTH_FAILED: i32 = 24;
/// The salt of the account `testuser1`.
const SALT: &str = "TEST.GOKRB5testuser1";

/// What the KDC puts into the encrypted part of the TGT reply about expiry.
#[derive(Clone, Copy, Default)]
pub(super) struct ExpiryFields {
    /// The `key-expiration` field.
    pub key_expiration: Option<SystemTime>,
    /// A `last-req` entry of type 6 (password expiration).
    pub last_req_password: Option<SystemTime>,
    /// A `last-req` entry of type 7 (account expiration).
    pub last_req_account: Option<SystemTime>,
}

/// One AS request the KDC answered.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct AsSeen {
    /// The requested service, joined with `/`.
    pub service: String,
    /// Whether the PA-ENC-TIMESTAMP decrypted under the account's current password.
    pub preauthenticated: bool,
}

/// The state of the account and the requests seen.
pub(super) struct Realm {
    /// The account's current password.
    pub password: Mutex<Vec<u8>>,
    /// Whether the password has expired: tickets other than `kadmin/changepw` are refused.
    pub expired: Mutex<bool>,
    /// The expiry fields of a TGT reply.
    pub expiry: Mutex<ExpiryFields>,
    /// Every AS request answered, in order.
    pub seen: Mutex<Vec<AsSeen>>,
}

impl Realm {
    /// A realm whose account has `password`.
    pub(super) fn new(password: &[u8], expired: bool) -> Self {
        Self {
            password: Mutex::new(password.to_vec()),
            expired: Mutex::new(expired),
            expiry: Mutex::new(ExpiryFields::default()),
            seen: Mutex::new(Vec::new()),
        }
    }

    /// The AS requests answered so far.
    pub(super) fn requests(&self) -> Vec<AsSeen> {
        held(&self.seen).clone()
    }

    /// Remember a request.
    fn record(&self, service: &[String], preauthenticated: bool) {
        held(&self.seen).push(AsSeen {
            service: service.join("/"),
            preauthenticated,
        });
    }

    /// The account.
    pub(super) fn account() -> Principal {
        Principal::user(REALM, "testuser1")
    }

    /// The pre-authentication key info of the account.
    pub(super) fn key_info() -> PreauthKeyInfo {
        PreauthKeyInfo::new(18)
            .with_salt(Some(SALT.to_owned()))
            .with_s2kparams(Some(vec![0_u8, 0_u8, 16_u8, 0_u8]))
    }

    /// The reply key of the account for `password`.
    pub(super) fn key_for(password: &[u8]) -> Result<EncryptionKey, TestError> {
        Ok(derive_password_reply_key(
            &Self::account(),
            password,
            &Self::key_info(),
        )?)
    }

    /// Answer one AS request.
    pub(super) fn answer(&self, request: &[u8]) -> Result<Vec<u8>, TestError> {
        let decoded: rasn_kerberos::AsReq = der::decode(request)?;
        let body = &decoded.0.req_body;
        let service: Vec<String> = body
            .sname
            .as_ref()
            .ok_or("sname")?
            .string
            .iter()
            .map(|part| String::from_utf8_lossy(part.as_bytes()).into_owned())
            .collect();
        let password = held(&self.password).clone();
        let key = Self::key_for(&password)?;
        let timestamp = decoded
            .0
            .padata
            .iter()
            .flatten()
            .find(|padata| padata.r#type == PA_ENC_TIMESTAMP);
        let Some(proof_padata) = timestamp else {
            self.record(&service, false);
            return preauth_required(&service);
        };
        let proof: rasn_kerberos::EncryptedData = der::decode(&proof_padata.value)?;
        let preauthenticated = AesSha1Etype::from_etype_id(18)
            .ok_or("AES-SHA1")?
            .decrypt_message(key.value(), &proof.cipher, 1)
            .is_ok();
        self.record(&service, preauthenticated);
        if !preauthenticated {
            return krb_error(KDC_ERR_PREAUTH_FAILED, &service, None);
        }
        let changepw = service == ["kadmin", "changepw"];
        if *held(&self.expired) && !changepw {
            return krb_error(KDC_ERR_KEY_EXPIRED, &service, None);
        }
        let expiry = if changepw {
            ExpiryFields::default()
        } else {
            *held(&self.expiry)
        };
        as_rep(&decoded, &service, &key, expiry)
    }
}

/// A Kerberos time for `time`.
pub(super) fn kerberos_time(time: SystemTime) -> Result<rasn_kerberos::KerberosTime, TestError> {
    let instant: DateTime<Utc> = time.into();
    let utc = DateTime::<Utc>::from_timestamp(instant.timestamp(), 0).ok_or("time")?;
    let offset = FixedOffset::east_opt(0).ok_or("offset")?;
    Ok(rasn_kerberos::KerberosTime(utc.with_timezone(&offset)))
}

/// A Kerberos string.
fn string(value: &str) -> Result<rasn_kerberos::KerberosString, TestError> {
    Ok(rasn_kerberos::KerberosString::try_from(value.to_owned())?)
}

/// A principal name of `parts`.
fn name(name_type: i32, parts: &[String]) -> Result<rasn_kerberos::PrincipalName, TestError> {
    Ok(rasn_kerberos::PrincipalName {
        r#type: name_type,
        string: parts
            .iter()
            .map(|part| string(part))
            .collect::<Result<_, _>>()?,
    })
}

/// A KRB-ERROR for the account, naming `service`, with optional METHOD-DATA.
fn krb_error(
    code: i32,
    service: &[String],
    method_data: Option<Vec<u8>>,
) -> Result<Vec<u8>, TestError> {
    Ok(der::encode(&rasn_kerberos::KrbError {
        pvno: Integer::from(5_i32),
        msg_type: Integer::from(30_i32),
        ctime: None,
        cusec: None,
        stime: kerberos_time(SystemTime::now())?,
        susec: Integer::from(0_i32),
        error_code: code,
        crealm: Some(string(REALM)?),
        cname: Some(name(1, &["testuser1".to_owned()])?),
        realm: string(REALM)?,
        sname: name(2, service)?,
        e_text: None,
        e_data: method_data.map(Into::into),
    })?)
}

/// `KDC_ERR_PREAUTH_REQUIRED` offering `ETYPE-INFO2` and `PA-ENC-TIMESTAMP`.
fn preauth_required(service: &[String]) -> Result<Vec<u8>, TestError> {
    let info = rasn_kerberos::EtypeInfo2::from([rasn_kerberos::EtypeInfo2Entry {
        etype: 18,
        salt: Some(string(SALT)?),
        s2kparams: Some(vec![0_u8, 0_u8, 16_u8, 0_u8].into()),
    }]);
    let methods = rasn_kerberos::MethodData::from([
        rasn_kerberos::PaData {
            r#type: PA_ETYPE_INFO2,
            value: der::encode(&info)?.into(),
        },
        rasn_kerberos::PaData {
            r#type: PA_ENC_TIMESTAMP,
            value: Vec::new().into(),
        },
    ]);
    krb_error(
        KDC_ERR_PREAUTH_REQUIRED,
        service,
        Some(der::encode(&methods)?),
    )
}

/// An AS-REP for the requested service under `key`.
fn as_rep(
    request: &rasn_kerberos::AsReq,
    service: &[String],
    key: &EncryptionKey,
    expiry: ExpiryFields,
) -> Result<Vec<u8>, TestError> {
    let body = &request.0.req_body;
    let now = SystemTime::now();
    let session_key = if service == ["kadmin", "changepw"] {
        changepw_key()
    } else {
        EncryptionKey::new(18, vec![0x11; 32])
    };
    let mut last_req = vec![rasn_kerberos::LastReqValue {
        r#type: 0,
        value: kerberos_time(now.checked_sub(Duration::from_hours(1)).ok_or("time")?)?,
    }];
    for (kind, value) in [
        (6_i32, expiry.last_req_password),
        (7_i32, expiry.last_req_account),
    ] {
        if let Some(time) = value {
            last_req.push(rasn_kerberos::LastReqValue {
                r#type: kind,
                value: kerberos_time(time)?,
            });
        }
    }
    let part = rasn_kerberos::EncAsRepPart(rasn_kerberos::EncKdcRepPart {
        key: rasn_kerberos::EncryptionKey {
            r#type: session_key.etype(),
            value: session_key.value().to_vec().into(),
        },
        last_req,
        nonce: body.nonce,
        key_expiration: expiry.key_expiration.map(kerberos_time).transpose()?,
        flags: rasn_kerberos::TicketFlags(rasn_kerberos::KerberosFlags::from_slice(&[0; 4])),
        auth_time: kerberos_time(now)?,
        start_time: Some(kerberos_time(now)?),
        end_time: body.till.clone(),
        renew_till: None,
        srealm: string(REALM)?,
        sname: name(2, service)?,
        caddr: None,
        encrypted_pa_data: None,
    });
    let cipher = AesSha1Etype::from_etype_id(18)
        .ok_or("AES-SHA1")?
        .encrypt_message_with_confounder(
            key.value(),
            &der::encode(&part)?,
            AS_REP_ENCPART_USAGE,
            &[0x42; 16],
        )?;
    let parts: Vec<&str> = service.iter().map(String::as_str).collect();
    Ok(der::encode(&rasn_kerberos::AsRep(rasn_kerberos::KdcRep {
        pvno: Integer::from(5_i32),
        msg_type: Integer::from(11_i32),
        padata: None,
        crealm: string(REALM)?,
        cname: name(1, &["testuser1".to_owned()])?,
        ticket: ticket_for(&parts)?,
        enc_part: rasn_kerberos::EncryptedData {
            etype: key.etype(),
            kvno: Some(3),
            cipher: cipher.into(),
        },
    }))?)
}
