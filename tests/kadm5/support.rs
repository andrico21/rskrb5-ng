//! In-process fixtures.
//!
//! The admin principal `admin/admin@EXAMPLE.COM` holds a live service ticket
//! for `kadmin/admin@EXAMPLE.COM` (MIT `KADM5_ADMIN_SERVICE`,
//! `admin.h:64`), sealed under a fixed AES256 service key that the loopback
//! server's keytab also holds, so the crate's own acceptor opens it. Times are
//! taken from the clock, a minute back and an hour ahead.

use core::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use chrono::{DateTime, FixedOffset, Utc};
use rskrb5_ng::{
    client::{TgsRepSession, principal::Principal},
    gss::Credential,
    kadm5::Options,
    keytab::{self, EncryptionKey, Keytab},
    ticket,
};
use zeroize::Zeroizing;

use super::context::{Context as _, TestError};

/// The realm of every ticket.
pub(super) const REALM: &str = "EXAMPLE.COM";

/// aes256-cts-hmac-sha1-96.
const ETYPE: i32 = 18;

/// The service key of `kadmin/admin`.
fn service_key() -> EncryptionKey {
    EncryptionKey::new(ETYPE, vec![0x4b; 32])
}

/// The session key of the admin ticket.
fn session_key() -> EncryptionKey {
    EncryptionKey::new(ETYPE, vec![0x2d; 32])
}

/// The administrator.
pub(super) fn admin() -> Principal {
    Principal::new(REALM, 1, ["admin", "admin"])
}

/// `kadmin/admin@EXAMPLE.COM`.
pub(super) fn service() -> Principal {
    Principal::new(REALM, 1, ["kadmin", "admin"])
}

/// The loopback server's keytab: the `kadmin/admin` key.
pub(super) fn keytab() -> Keytab {
    let mut keytab = Keytab::new();
    keytab.entries_mut().push(keytab::Entry::new(
        keytab::Principal::new(REALM, 1, ["kadmin", "admin"]),
        0,
        1,
        service_key(),
        1,
    ));
    keytab
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

/// A whole-second time.
fn whole(at: SystemTime) -> Result<SystemTime, TestError> {
    let seconds = at.duration_since(UNIX_EPOCH)?.as_secs();
    UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds))
        .context("time is representable")
}

/// A Kerberos time.
fn time(at: SystemTime) -> Result<rasn_kerberos::KerberosTime, TestError> {
    let seconds = at.duration_since(UNIX_EPOCH)?.as_secs();
    let utc = DateTime::<Utc>::from_timestamp(i64::try_from(seconds)?, 0)
        .context("time is representable")?;
    let offset = FixedOffset::east_opt(0).context("UTC offset")?;
    Ok(rasn_kerberos::KerberosTime(utc.with_timezone(&offset)))
}

/// The admin's live service ticket for `kadmin/admin`.
pub(super) fn ticket() -> Result<TgsRepSession, TestError> {
    let now = SystemTime::now();
    let start = whole(now.checked_sub(Duration::from_mins(1)).context("start")?)?;
    let end = whole(now.checked_add(Duration::from_hours(1)).context("end")?)?;
    let session = session_key();
    let part = rasn_kerberos::EncTicketPart {
        flags: rasn_kerberos::TicketFlags(rasn_kerberos::KerberosFlags::repeat(false, 32)),
        key: rasn_kerberos::EncryptionKey {
            r#type: session.etype(),
            value: session.value().to_vec().into(),
        },
        crealm: text(REALM)?,
        cname: name(1, &["admin", "admin"])?,
        transited: rasn_kerberos::TransitedEncoding {
            r#type: 1,
            contents: Vec::new().into(),
        },
        auth_time: time(start)?,
        start_time: None,
        end_time: time(end)?,
        renew_till: None,
        caddr: None,
        authorization_data: None,
    };
    let der = ticket::encode_build_ticket_with_confounder(
        text(REALM)?,
        name(1, &["kadmin", "admin"])?,
        &part,
        &service_key(),
        Some(1),
        &[0x11; 16],
    )?;
    Ok(TgsRepSession::new(
        admin(),
        service(),
        session,
        Zeroizing::new(der),
        [0; 4],
        start,
        end,
    ))
}

/// The admin's initiator credential.
pub(super) fn credential() -> Result<Credential, TestError> {
    Ok(Credential::from_service_ticket(&ticket()?))
}

/// The client options of the scenarios: the realm, privacy, the newest API.
pub(super) fn options() -> Options {
    Options::new(REALM)
}
