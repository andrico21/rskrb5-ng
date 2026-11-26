//! The keys, names, times and sealed tickets of the in-process KDC.
//!
//! One realm, one user with a password, one `krbtgt`, and the `HTTP/<host>`
//! service keys, all in fixed AES256 keys so the crate's own acceptor opens
//! the tickets the KDC issues.

use std::time::{SystemTime, UNIX_EPOCH};

use chrono::{DateTime, FixedOffset, Utc};
use rskrb5_ng::{crypto::AesSha1Etype, keytab::EncryptionKey, ticket};

use super::context::{Context as _, TestError};

/// The realm.
pub(super) const REALM: &str = "EXAMPLE.COM";
/// The user.
pub(super) const USER: &str = "alice";
/// The user's password.
pub(super) const PASSWORD: &[u8] = b"correct horse";
/// aes256-cts-hmac-sha1-96.
pub(super) const ETYPE: i32 = 18;
/// `KDC_ERR_PREAUTH_REQUIRED`.
pub(super) const PREAUTH_REQUIRED: i32 = 25;
/// `KDC_ERR_S_PRINCIPAL_UNKNOWN`.
pub(super) const S_PRINCIPAL_UNKNOWN: i32 = 7;

/// The cipher.
pub(super) fn cipher() -> Result<AesSha1Etype, TestError> {
    AesSha1Etype::from_etype_id(ETYPE).context("AES256")
}

/// The key of the user, as the KDC derives it.
pub(super) fn user_key() -> Result<EncryptionKey, TestError> {
    let salt = format!("{REALM}{USER}");
    let bytes = cipher()?.string_to_key(PASSWORD, salt.as_bytes(), "00001000")?;
    Ok(EncryptionKey::new(ETYPE, bytes))
}

/// The key of `krbtgt/REALM`.
pub(super) fn tgs_key() -> EncryptionKey {
    EncryptionKey::new(ETYPE, vec![0x71; 32])
}

/// The long-term key of `HTTP/<host>`, the one `super::support::keytab` holds.
pub(super) fn service_key(host: &str) -> EncryptionKey {
    let seed = host.bytes().fold(0x5c_u8, u8::wrapping_add);
    EncryptionKey::new(ETYPE, vec![seed; 32])
}

/// A Kerberos string.
pub(super) fn text(value: &str) -> Result<rasn_kerberos::KerberosString, TestError> {
    rasn_kerberos::KerberosString::from_bytes(value.as_bytes())
        .map_err(|cause| format!("Kerberos string: {cause:?}").into())
}

/// A principal name.
pub(super) fn name(
    kind: i32,
    components: &[&str],
) -> Result<rasn_kerberos::PrincipalName, TestError> {
    Ok(rasn_kerberos::PrincipalName {
        r#type: kind,
        string: components
            .iter()
            .map(|component| text(component))
            .collect::<Result<_, _>>()?,
    })
}

/// A whole-second Kerberos time.
pub(super) fn time(at: SystemTime) -> Result<rasn_kerberos::KerberosTime, TestError> {
    let seconds = at.duration_since(UNIX_EPOCH)?.as_secs();
    let utc = DateTime::<Utc>::from_timestamp(i64::try_from(seconds)?, 0).context("time")?;
    Ok(rasn_kerberos::KerberosTime(
        utc.with_timezone(&FixedOffset::east_opt(0).context("UTC")?),
    ))
}

/// A DER encryption key.
pub(super) fn rasn_key(key: &EncryptionKey) -> rasn_kerberos::EncryptionKey {
    rasn_kerberos::EncryptionKey {
        r#type: key.etype(),
        value: key.value().to_vec().into(),
    }
}

/// The DER ticket for `server`, sealed in its key, for `client`, valid over `at`.
pub(super) fn sealed(
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

/// The flags of a reply: `FORWARDABLE` when the request asks for it (RFC 4120
/// `KDCOptions` bit 1), nothing else.
pub(super) fn reply_flags(body: &rasn_kerberos::KdcReqBody) -> rasn_kerberos::TicketFlags {
    let forwardable = body.kdc_options.0.get(1).is_some_and(|bit| *bit);
    rasn_kerberos::TicketFlags(rasn_kerberos::KerberosFlags::from_slice(&[
        u8::from(forwardable) << 6_u8,
        0,
        0,
        0,
    ]))
}
