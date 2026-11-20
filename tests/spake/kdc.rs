//! A fake KDC: `PREAUTH_REQUIRED`, encrypted timestamp and AS-REP; with the
//! `spake` leaf, `half` adds the KDC half of RFC 9588 (edwards25519, AES256).
//!
//! The KDC half is independent of the crate's SPAKE code: its transcript and
//! `K'[n]` derivation follow RFC 9588 sections 6 and 7 over the public PRF
//! primitives, and its group arithmetic is `curve25519-dalek` used directly.

use core::{error::Error, time::Duration};
use std::time::UNIX_EPOCH;

use rasn::{der, types::Integer};
use rasn_kerberos::{EncryptedData, PaData};
use rskrb5_ng::{
    client::{PreauthKeyInfo, derive_password_reply_key, principal::Principal},
    crypto::KerberosEtype,
    keytab::EncryptionKey,
    preauth::spake::PA_SPAKE,
};

/// The KDC half of RFC 9588.
#[cfg(feature = "spake")]
#[path = "kdc/half.rs"]
mod half;

/// Test failures.
pub(crate) type TestError = Box<dyn Error>;

/// The realm of the scenarios.
pub(crate) const REALM: &str = "TEST.RSKRB5";
/// The client's password.
pub(crate) const PASSWORD: &[u8] = b"spake-password";
/// The salt the KDC announces.
const SALT: &str = "TEST.RSKRB5spakeuser";
/// The KDC's conversation cookie.
pub(crate) const COOKIE: &[u8] = b"kdc-cookie-1";
/// `PA-ENC-TIMESTAMP`.
pub(crate) const PA_ENC_TIMESTAMP: i32 = 2;
/// `PA-FX-COOKIE`.
pub(crate) const PA_FX_COOKIE: i32 = 133;
/// `PA-ETYPE-INFO2`.
const PA_ETYPE_INFO2: i32 = 19;
/// `KDC_ERR_PREAUTH_FAILED`.
#[cfg(feature = "spake")]
pub(crate) const PREAUTH_FAILED: i32 = 24;
/// `KDC_ERR_PREAUTH_REQUIRED`.
const PREAUTH_REQUIRED: i32 = 25;
/// The KDC clock and the reply's start time.
const START: u64 = 1_893_553_445;
/// The reply's end time.
const END: u64 = 1_893_557_045;

/// What `PREAUTH_REQUIRED` offers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Offer {
    /// An empty PA-SPAKE before PA-ENC-TIMESTAMP.
    SpakeFirst,
    /// PA-ENC-TIMESTAMP before an empty PA-SPAKE.
    #[cfg(feature = "spake")]
    TimestampFirst,
    /// The challenge itself before PA-ENC-TIMESTAMP (RFC 9588 section 4.6).
    #[cfg(feature = "spake")]
    Optimistic,
    /// PA-ENC-TIMESTAMP alone (PA-SPAKE stripped).
    TimestampOnly,
}

/// How the KDC misbehaves.
#[cfg(feature = "spake")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Fault {
    /// It does not.
    Honest,
    /// It uses `T = w*M`, so the client's shared element is the identity.
    Identity,
    /// The challenge delivered has one more factor than the transcript holds.
    Tamper,
    /// It answers the support message with `PREAUTH_FAILED`, offering encrypted timestamp.
    FailSupport,
}

/// What the fake KDC offers and how it misbehaves.
#[derive(Clone, Debug)]
pub(crate) struct Script {
    /// The mechanisms of `PREAUTH_REQUIRED`.
    pub offer: Offer,
    /// The challenge group.
    #[cfg(feature = "spake")]
    pub group: i32,
    /// The offered second factors.
    #[cfg(feature = "spake")]
    pub factors: Vec<(i32, Option<Vec<u8>>)>,
    /// Bytes delivered instead of the KDC element `T`.
    #[cfg(feature = "spake")]
    pub element: Option<Vec<u8>>,
    /// Bytes delivered instead of the challenge after the support message.
    #[cfg(feature = "spake")]
    pub raw_challenge: Option<Vec<u8>>,
    /// The misbehaviour.
    #[cfg(feature = "spake")]
    pub fault: Fault,
}

impl Default for Script {
    fn default() -> Self {
        Self {
            offer: Offer::SpakeFirst,
            #[cfg(feature = "spake")]
            group: 1,
            #[cfg(feature = "spake")]
            factors: vec![(1, None)],
            #[cfg(feature = "spake")]
            element: None,
            #[cfg(feature = "spake")]
            raw_challenge: None,
            #[cfg(feature = "spake")]
            fault: Fault::Honest,
        }
    }
}

/// The fake KDC.
pub(crate) struct Kdc {
    /// Its behaviour.
    script: Script,
    /// The client's long-term key.
    key: EncryptionKey,
    /// The support message received.
    #[cfg(feature = "spake")]
    support: Vec<u8>,
    /// The challenge of the transcript.
    #[cfg(feature = "spake")]
    challenge: Vec<u8>,
    /// The PA-DATA of every request, in order.
    requests: Vec<Vec<PaData>>,
}

/// The client principal of the scenarios.
pub(crate) fn client() -> Principal {
    Principal::user(REALM, "spakeuser")
}

/// The client's long-term key under the announced salt.
///
/// # Errors
/// Returns the key derivation errors.
pub(crate) fn long_term_key() -> Result<EncryptionKey, TestError> {
    Ok(derive_password_reply_key(
        &client(),
        PASSWORD,
        &PreauthKeyInfo::new(18).with_salt(Some(SALT.to_owned())),
    )?)
}

/// A Kerberos time.
///
/// # Errors
/// Returns an error for an unrepresentable time.
fn kerberos_time(seconds: u64) -> Result<rasn_kerberos::KerberosTime, TestError> {
    let time = UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds))
        .ok_or("time")?;
    Ok(rasn_kerberos::KerberosTime(
        chrono::DateTime::<chrono::Utc>::from(time).into(),
    ))
}

impl Script {
    /// The default script offering `offer`.
    #[cfg(feature = "spake")]
    pub(crate) fn offering(offer: Offer) -> Self {
        Self {
            offer,
            ..Self::default()
        }
    }

    /// The default script offering `offer`.
    #[cfg(not(feature = "spake"))]
    pub(crate) const fn offering(offer: Offer) -> Self {
        Self { offer }
    }
}

impl Kdc {
    /// A KDC following `script`.
    ///
    /// # Errors
    /// Returns the key derivation errors.
    pub(crate) fn new(script: Script) -> Result<Self, TestError> {
        Ok(Self {
            script,
            key: long_term_key()?,
            #[cfg(feature = "spake")]
            support: Vec::new(),
            #[cfg(feature = "spake")]
            challenge: Vec::new(),
            requests: Vec::new(),
        })
    }

    /// The PA-DATA of every request received.
    pub(crate) fn requests(&self) -> &[Vec<PaData>] {
        &self.requests
    }

    /// Answer one AS-REQ.
    ///
    /// # Errors
    /// Returns decoding errors and protocol violations of the client.
    pub(crate) fn answer(&mut self, request: &[u8]) -> Result<Vec<u8>, TestError> {
        let message: rasn_kerberos::AsReq = der::decode(request)?;
        let padata = message.0.padata.clone().unwrap_or_default();
        self.requests.push(padata.clone());
        if padata.iter().any(|entry| entry.r#type == PA_ENC_TIMESTAMP) {
            return as_rep(&message, &self.key);
        }
        let Some(spake) = padata.iter().find(|entry| entry.r#type == PA_SPAKE) else {
            #[cfg(feature = "spake")]
            let spake_value = optimistic(self)?;
            #[cfg(not(feature = "spake"))]
            let spake_value = Vec::new();
            return self.preauth_required(spake_value);
        };
        let cookie = padata
            .iter()
            .any(|entry| entry.r#type == PA_FX_COOKIE && *entry.value == *COOKIE);
        if !cookie {
            return Err("the KDC cookie was not echoed".into());
        }
        spake_reply(self, &message, spake)
    }

    /// `PREAUTH_REQUIRED` with `ETYPE-INFO2`, the cookie and the scripted offers.
    ///
    /// # Errors
    /// Returns the encoding errors.
    fn preauth_required(&self, spake_value: Vec<u8>) -> Result<Vec<u8>, TestError> {
        let info = rasn_kerberos::EtypeInfo2::from([rasn_kerberos::EtypeInfo2Entry {
            etype: 18,
            salt: Some(rasn_kerberos::KerberosString::try_from(SALT.to_owned())?),
            s2kparams: None,
        }]);
        let mut offers = vec![offer(PA_ETYPE_INFO2, der::encode(&info)?)];
        let timestamp = offer(PA_ENC_TIMESTAMP, Vec::new());
        let mechanisms = match self.script.offer {
            Offer::SpakeFirst => vec![offer(PA_SPAKE, spake_value), timestamp],
            #[cfg(feature = "spake")]
            Offer::TimestampFirst => vec![timestamp, offer(PA_SPAKE, spake_value)],
            #[cfg(feature = "spake")]
            Offer::Optimistic => vec![offer(PA_SPAKE, spake_value), timestamp],
            Offer::TimestampOnly => vec![timestamp],
        };
        offers.extend(mechanisms);
        offers.extend(cookie_offer());
        krb_error(PREAUTH_REQUIRED, &offers)
    }
}

/// The KDC half answers a PA-SPAKE request.
///
/// # Errors
/// Returns the errors of the KDC half.
#[cfg(feature = "spake")]
fn spake_reply(
    kdc: &mut Kdc,
    message: &rasn_kerberos::AsReq,
    spake: &PaData,
) -> Result<Vec<u8>, TestError> {
    half::answer(kdc, message, spake)
}

/// Without the leaf the client never sends PA-SPAKE.
///
/// # Errors
/// Always: the request is a protocol violation.
#[cfg(not(feature = "spake"))]
fn spake_reply(
    _kdc: &mut Kdc,
    _message: &rasn_kerberos::AsReq,
    _spake: &PaData,
) -> Result<Vec<u8>, TestError> {
    Err("PA-SPAKE sent without the spake leaf".into())
}

/// The PA-SPAKE value of `PREAUTH_REQUIRED`: the challenge when the script is
/// optimistic, else empty.
///
/// # Errors
/// Returns the errors of the KDC half.
#[cfg(feature = "spake")]
fn optimistic(kdc: &mut Kdc) -> Result<Vec<u8>, TestError> {
    if kdc.script.offer == Offer::Optimistic {
        half::challenge(kdc)
    } else {
        Ok(Vec::new())
    }
}

/// One METHOD-DATA entry.
pub(crate) fn offer(kind: i32, value: Vec<u8>) -> PaData {
    PaData {
        r#type: kind,
        value: value.into(),
    }
}

/// The cookie entry.
pub(crate) fn cookie_offer() -> [PaData; 1] {
    [offer(PA_FX_COOKIE, COOKIE.to_vec())]
}

/// The KDC's principal name.
///
/// # Errors
/// Returns the string conversion errors.
fn tgs() -> Result<rasn_kerberos::PrincipalName, TestError> {
    Ok(rasn_kerberos::PrincipalName {
        r#type: 2,
        string: vec![
            rasn_kerberos::KerberosString::try_from("krbtgt".to_owned())?,
            rasn_kerberos::KerberosString::try_from(REALM.to_owned())?,
        ],
    })
}

/// A KRB-ERROR with `code` and METHOD-DATA `offers`.
///
/// # Errors
/// Returns the encoding errors.
pub(crate) fn krb_error(code: i32, offers: &[PaData]) -> Result<Vec<u8>, TestError> {
    let e_data = if offers.is_empty() {
        None
    } else {
        Some(der::encode(&offers.to_vec())?.into())
    };
    Ok(der::encode(&rasn_kerberos::KrbError {
        pvno: Integer::from(5_i32),
        msg_type: Integer::from(30_i32),
        ctime: None,
        cusec: None,
        stime: kerberos_time(START)?,
        susec: Integer::from(0_i32),
        error_code: code,
        crealm: None,
        cname: None,
        realm: rasn_kerberos::KerberosString::try_from(REALM.to_owned())?,
        sname: tgs()?,
        e_text: None,
        e_data,
    })?)
}

/// An AS-REP answering `request`, encrypted in `reply_key`.
///
/// # Errors
/// Returns the encoding and encryption errors.
pub(crate) fn as_rep(
    request: &rasn_kerberos::AsReq,
    reply_key: &EncryptionKey,
) -> Result<Vec<u8>, TestError> {
    let body = &request.0.req_body;
    let sname = body.sname.clone().ok_or("sname")?;
    let part = rasn_kerberos::EncAsRepPart(rasn_kerberos::EncKdcRepPart {
        key: rasn_kerberos::EncryptionKey {
            r#type: 18,
            value: vec![0x5a_u8; 32].into(),
        },
        last_req: vec![rasn_kerberos::LastReqValue {
            r#type: 0,
            value: kerberos_time(START)?,
        }],
        nonce: body.nonce,
        key_expiration: None,
        flags: rasn_kerberos::TicketFlags(rasn_kerberos::KerberosFlags::from_slice(&[0_u8; 4])),
        auth_time: kerberos_time(START)?,
        start_time: Some(kerberos_time(START)?),
        end_time: kerberos_time(END)?,
        renew_till: None,
        srealm: body.realm.clone(),
        sname: sname.clone(),
        caddr: None,
        encrypted_pa_data: None,
    });
    let etype = KerberosEtype::from_etype_id(reply_key.etype()).ok_or("etype")?;
    let cipher = etype.encrypt_message_with_confounder(
        reply_key.value(),
        &der::encode(&part)?,
        3,
        &[0x11_u8; 16],
    )?;
    Ok(der::encode(&rasn_kerberos::AsRep(rasn_kerberos::KdcRep {
        pvno: Integer::from(5_i32),
        msg_type: Integer::from(11_i32),
        padata: None,
        crealm: body.realm.clone(),
        cname: body.cname.clone().ok_or("cname")?,
        ticket: rasn_kerberos::Ticket {
            tkt_vno: Integer::from(5_i32),
            realm: body.realm.clone(),
            sname,
            enc_part: EncryptedData {
                etype: 18,
                kvno: Some(2),
                cipher: vec![0xde_u8, 0xad, 0xbe, 0xef].into(),
            },
        },
        enc_part: EncryptedData {
            etype: reply_key.etype(),
            kvno: Some(3),
            cipher: cipher.into(),
        },
    }))?)
}
