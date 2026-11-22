//! Service tickets that carry a given PAC, for the acceptor tests of the PAC API.
//!
//! The service key is the AES256 service key of the generated vectors, the realm `TEST.PAC`, the
//! client `pacuser` with the authentication time the vectors name.

use core::{error::Error, time::Duration};
use std::time::{SystemTime, UNIX_EPOCH};

use chrono::{DateTime, FixedOffset, Utc};
use rasn::der;
use rskrb5_ng::{
    crypto::AesSha1Etype,
    keytab::{EncryptionKey, Keytab},
    pac::{AD_IF_RELEVANT, AD_WIN2K_PAC},
};

/// Authentication time of the vectors, seconds since the Unix epoch.
pub(crate) const AUTH_TIME: u64 = 1_494_083_591;
/// Key version of the service key in the keytab and the ticket.
const KVNO: u32 = 1;
/// The ticket session key.
const SESSION_KEY: [u8; 32] = [0x5a; 32];
/// Confounder of the ticket encryption.
const TICKET_CONFOUNDER: [u8; 16] = [0x11; 16];
/// Confounder of the authenticator encryption.
const AUTHENTICATOR_CONFOUNDER: [u8; 16] = [0x22; 16];

/// A Kerberos string.
fn string(value: &str) -> Result<rasn_kerberos::KerberosString, Box<dyn Error>> {
    Ok(rasn_kerberos::KerberosString::from_bytes(value.as_bytes())?)
}

/// A principal name of type `NT-PRINCIPAL`.
fn name(components: &[&str]) -> Result<rasn_kerberos::PrincipalName, Box<dyn Error>> {
    Ok(rasn_kerberos::PrincipalName {
        r#type: 1,
        string: components
            .iter()
            .map(|component| string(component))
            .collect::<Result<_, _>>()?,
    })
}

/// A Kerberos time `seconds` after the Unix epoch.
fn time(seconds: u64) -> Result<rasn_kerberos::KerberosTime, Box<dyn Error>> {
    let utc = DateTime::<Utc>::from_timestamp(i64::try_from(seconds)?, 0).ok_or("time")?;
    let zero = FixedOffset::east_opt(0).ok_or("offset")?;
    Ok(rasn_kerberos::KerberosTime(utc.with_timezone(&zero)))
}

/// A keytab with the one service key `HTTP/pac.test.pac@TEST.PAC` (aes256-cts-hmac-sha1-96).
pub(crate) fn service_keytab(key: &[u8]) -> Result<Keytab, Box<dyn Error>> {
    let mut bytes = vec![5, 2];
    let mut entry = Vec::new();
    entry.extend_from_slice(&2_u16.to_be_bytes());
    for part in ["TEST.PAC", "HTTP", "pac.test.pac"] {
        entry.extend_from_slice(&u16::try_from(part.len())?.to_be_bytes());
        entry.extend_from_slice(part.as_bytes());
    }
    entry.extend_from_slice(&1_u32.to_be_bytes());
    entry.extend_from_slice(&0_u32.to_be_bytes());
    entry.push(u8::try_from(KVNO)?);
    entry.extend_from_slice(&18_u16.to_be_bytes());
    entry.extend_from_slice(&u16::try_from(key.len())?.to_be_bytes());
    entry.extend_from_slice(key);
    entry.extend_from_slice(&KVNO.to_be_bytes());
    bytes.extend_from_slice(&i32::try_from(entry.len())?.to_be_bytes());
    bytes.extend_from_slice(&entry);
    Ok(Keytab::parse(&bytes)?)
}

/// The authorization data that wraps `pac` in an `AD-IF-RELEVANT` container.
pub(crate) fn authorization_data(
    pac: Vec<u8>,
) -> Result<rasn_kerberos::AuthorizationData, Box<dyn Error>> {
    let nested =
        rasn_kerberos::AuthorizationData::from(vec![rasn_kerberos::AuthorizationDataValue {
            r#type: AD_WIN2K_PAC,
            data: pac.into(),
        }]);
    Ok(rasn_kerberos::AuthorizationData::from(vec![
        rasn_kerberos::AuthorizationDataValue {
            r#type: AD_IF_RELEVANT,
            data: der::encode(&nested)?.into(),
        },
    ]))
}

/// An `EncTicketPart` for `pacuser` that carries `authorization_data`.
pub(crate) fn enc_ticket(
    client: &str,
    auth_time: u64,
    authorization_data: Option<rasn_kerberos::AuthorizationData>,
) -> Result<rasn_kerberos::EncTicketPart, Box<dyn Error>> {
    Ok(rasn_kerberos::EncTicketPart {
        flags: rasn_kerberos::TicketFlags(rasn_kerberos::KerberosFlags::repeat(false, 32)),
        key: rasn_kerberos::EncryptionKey {
            r#type: 18,
            value: SESSION_KEY.to_vec().into(),
        },
        crealm: string("TEST.PAC")?,
        cname: name(&[client])?,
        transited: rasn_kerberos::TransitedEncoding {
            r#type: 1,
            contents: Vec::new().into(),
        },
        auth_time: time(auth_time)?,
        start_time: Some(time(auth_time)?),
        end_time: time(auth_time.checked_add(36_000).ok_or("time")?)?,
        renew_till: None,
        caddr: None,
        authorization_data,
    })
}

/// The time the acceptor runs at: a minute after the authentication.
pub(crate) fn now() -> Result<SystemTime, Box<dyn Error>> {
    UNIX_EPOCH
        .checked_add(Duration::from_secs(AUTH_TIME + 60))
        .ok_or_else(|| "time".into())
}

/// An AP-REQ whose ticket is `ticket` sealed under `service_key`, for `pacuser`.
pub(crate) fn ap_req(
    ticket: &rasn_kerberos::EncTicketPart,
    service_key: &[u8],
) -> Result<Vec<u8>, Box<dyn Error>> {
    let etype = AesSha1Etype::Aes256;
    let sealed = etype.encrypt_message_with_confounder(
        service_key,
        &der::encode(ticket)?,
        2,
        &TICKET_CONFOUNDER,
    )?;
    let authenticator = rasn_kerberos::Authenticator {
        authenticator_vno: 5_i32.into(),
        crealm: string("TEST.PAC")?,
        cname: ticket.cname.clone(),
        cksum: None,
        cusec: 0_i32.into(),
        ctime: time(AUTH_TIME + 60)?,
        subkey: None,
        seq_number: None,
        authorization_data: None,
    };
    let sealed_authenticator = etype.encrypt_message_with_confounder(
        &SESSION_KEY,
        &der::encode(&authenticator)?,
        11,
        &AUTHENTICATOR_CONFOUNDER,
    )?;
    let request = rasn_kerberos::ApReq {
        pvno: 5_i32.into(),
        msg_type: 14_i32.into(),
        ap_options: rasn_kerberos::ApOptions(rasn_kerberos::KerberosFlags::repeat(false, 32)),
        ticket: rasn_kerberos::Ticket {
            tkt_vno: 5_i32.into(),
            realm: string("TEST.PAC")?,
            sname: name(&["HTTP", "pac.test.pac"])?,
            enc_part: rasn_kerberos::EncryptedData {
                etype: 18,
                kvno: Some(KVNO),
                cipher: sealed.into(),
            },
        },
        authenticator: rasn_kerberos::EncryptedData {
            etype: 18,
            kvno: None,
            cipher: sealed_authenticator.into(),
        },
    };
    Ok(der::encode(&request)?)
}

/// The service key as an owner.
pub(crate) fn key(bytes: &[u8]) -> EncryptionKey {
    EncryptionKey::new(18, bytes.to_vec())
}
