//! Forged AP-REQs for acceptor tests.
//!
//! A service ticket with a chosen client realm, transited encoding and
//! TRANSITED-POLICY-CHECKED flag, encrypted in a password-derived service key,
//! with a matching authenticator.

use core::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use chrono::{DateTime, FixedOffset, Utc};
use rasn::der;
use rskrb5_ng::{
    ap_req::{ap_options_from_bits, build_ap_req_with_confounder, encode},
    crypto::AesSha1Etype,
    keytab::{EncryptionKey, Keytab, Principal},
};
use zeroize::Zeroizing;

use crate::TestError;

/// The service principal components every forged ticket is for.
pub(crate) const SERVICE: [&str; 2] = ["HTTP", "host.svc.test"];

/// The service realm every forged ticket is for.
pub(crate) const SERVICE_REALM: &str = "SVC.TEST";

/// The validation instant of every forged ticket.
pub(crate) const NOW_SECONDS: u64 = 1_893_553_447;

/// The service key's enctype (aes256-cts-hmac-sha1-96).
const ETYPE: i32 = 18;

/// The validation instant.
pub(crate) fn now() -> Result<SystemTime, TestError> {
    UNIX_EPOCH
        .checked_add(Duration::from_secs(NOW_SECONDS))
        .ok_or_else(|| "time is representable".into())
}

/// The service keytab: one AES256 key derived from `password`.
pub(crate) fn keytab(password: &str) -> Result<Keytab, TestError> {
    let mut keytab = Keytab::default();
    keytab.add_entry_from_password(
        Principal::new(SERVICE_REALM, 1, SERVICE),
        Zeroizing::new(password.as_bytes().to_vec()),
        now()?,
        1,
        ETYPE,
    )?;
    Ok(keytab)
}

/// What a forged ticket says about its path.
pub(crate) struct Transit<'contents> {
    /// The client's realm.
    pub client_realm: &'contents str,
    /// The `tr-type`.
    pub kind: i32,
    /// The encoded transited realms.
    pub contents: &'contents [u8],
    /// Whether the KDC set TRANSITED-POLICY-CHECKED.
    pub checked: bool,
}

/// A DER AP-REQ for the service, its ticket encrypted in the first key of `keytab`.
pub(crate) fn ap_req(keytab: &Keytab, transit: &Transit<'_>) -> Result<Vec<u8>, TestError> {
    let (service_key, _) = keytab.find_key(&SERVICE, SERVICE_REALM, 1, ETYPE)?;
    let session = EncryptionKey::new(ETYPE, vec![0x5a; 32]);
    let mut flags = rasn_kerberos::KerberosFlags::repeat(false, 32);
    flags.set(12, transit.checked);
    let part = rasn_kerberos::EncTicketPart {
        flags: rasn_kerberos::TicketFlags(flags),
        key: rasn_kerberos::EncryptionKey {
            r#type: ETYPE,
            value: session.value().to_vec().into(),
        },
        crealm: text(transit.client_realm)?,
        cname: name(&["alice"])?,
        transited: rasn_kerberos::TransitedEncoding {
            r#type: transit.kind,
            contents: transit.contents.to_vec().into(),
        },
        auth_time: time(NOW_SECONDS)?,
        start_time: None,
        end_time: time(NOW_SECONDS.saturating_add(3_600))?,
        renew_till: None,
        caddr: None,
        authorization_data: None,
    };
    let etype = AesSha1Etype::from_etype_id(ETYPE).ok_or("AES256 is supported")?;
    let ticket = rasn_kerberos::Ticket {
        tkt_vno: 5_i32.into(),
        realm: text(SERVICE_REALM)?,
        sname: name(&SERVICE)?,
        enc_part: rasn_kerberos::EncryptedData {
            etype: ETYPE,
            kvno: Some(1),
            cipher: etype
                .encrypt_message_with_confounder(
                    service_key.value(),
                    &der::encode(&part)?,
                    2,
                    &[0x11; 16],
                )?
                .into(),
        },
    };
    let authenticator = rasn_kerberos::Authenticator {
        authenticator_vno: 5_i32.into(),
        crealm: text(transit.client_realm)?,
        cname: name(&["alice"])?,
        cksum: None,
        cusec: 0_i32.into(),
        ctime: time(NOW_SECONDS)?,
        subkey: None,
        seq_number: None,
        authorization_data: None,
    };
    let request = build_ap_req_with_confounder(
        ticket,
        ap_options_from_bits(0),
        &authenticator,
        &session,
        11,
        None,
        &[0x22; 16],
    )?;
    Ok(encode(&request)?)
}

/// A Kerberos string.
fn text(value: &str) -> Result<rasn_kerberos::KerberosString, TestError> {
    rasn_kerberos::KerberosString::from_bytes(value.as_bytes())
        .map_err(|cause| format!("Kerberos string: {cause:?}").into())
}

/// A principal name of type 1.
fn name(components: &[&str]) -> Result<rasn_kerberos::PrincipalName, TestError> {
    Ok(rasn_kerberos::PrincipalName {
        r#type: 1,
        string: components
            .iter()
            .map(|component| text(component))
            .collect::<Result<_, _>>()?,
    })
}

/// A whole-second Kerberos time.
fn time(seconds: u64) -> Result<rasn_kerberos::KerberosTime, TestError> {
    let utc = DateTime::<Utc>::from_timestamp(i64::try_from(seconds)?, 0)
        .ok_or("time is representable")?;
    let offset = FixedOffset::east_opt(0).ok_or("UTC offset")?;
    Ok(rasn_kerberos::KerberosTime(utc.with_timezone(&offset)))
}
