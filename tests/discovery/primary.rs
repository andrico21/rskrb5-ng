//! The primary-KDC retry after a replica's failure (MIT-dns-7, MIT-config-45): MIT
//! `get_in_tkt.c:2031-2045`, with the primary list of `locate_kdc.c:243-250,880-891`.

extern crate alloc;

use alloc::sync::Arc;
use core::{
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};
use std::time::SystemTime;

use chrono::{DateTime, FixedOffset, Utc};
use rasn::{der, types::Integer};
use rasn_kerberos::{KerberosString, KerberosTime, KrbError, PrincipalName};
use rskrb5_ng::{
    client::{
        options::AsReq,
        principal::Principal,
        transport::{KdcProtocol, Tokio},
    },
    config::Config,
    error::Client as ClientError,
};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::TcpListener,
    task::JoinHandle,
    time::timeout,
};

use crate::{TestError, closed_port::reserve_closed_tcp_port};

/// The realm every test logs in to.
const REALM: &str = "TEST.GOKRB5";

/// A TCP KDC that answers every request with one KRB-ERROR and counts its connections.
pub(super) struct Stub {
    /// Where it listens.
    pub address: String,
    /// Connections accepted so far.
    pub contacts: Arc<AtomicUsize>,
    /// The serving task.
    pub task: JoinHandle<()>,
}

impl Drop for Stub {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// An encoded KRB-ERROR with `code`.
pub(super) fn krb_error(code: i32) -> Result<Vec<u8>, TestError> {
    let utc = DateTime::<Utc>::from_timestamp(1_893_553_440, 0).ok_or("valid time")?;
    let zone = FixedOffset::east_opt(0).ok_or("UTC offset")?;
    let text = |value: &str| KerberosString::try_from(value).map_err(|cause| format!("{cause}"));
    let error = KrbError {
        pvno: Integer::from(5_i32),
        msg_type: Integer::from(30_i32),
        ctime: None,
        cusec: None,
        stime: KerberosTime(utc.with_timezone(&zone)),
        susec: Integer::from(0_i32),
        error_code: code,
        crealm: None,
        cname: None,
        realm: text(REALM)?,
        sname: PrincipalName {
            r#type: 2,
            string: vec![text("krbtgt")?, text(REALM)?],
        },
        e_text: None,
        e_data: None,
    };
    Ok(der::encode(&error).map_err(|cause| format!("KRB-ERROR encodes: {cause}"))?)
}

/// Start a KDC that answers with `code`.
pub(super) async fn kdc(code: i32) -> Result<Stub, TestError> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?.to_string();
    let reply = krb_error(code)?;
    let contacts = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&contacts);
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let _seen = counted.fetch_add(1, Ordering::SeqCst);
            let mut header = [0_u8; 4];
            if stream.read_exact(&mut header).await.is_err() {
                continue;
            }
            let Ok(length) = usize::try_from(u32::from_be_bytes(header)) else {
                continue;
            };
            let mut request = vec![0_u8; length];
            if stream.read_exact(&mut request).await.is_err() {
                continue;
            }
            let Ok(size) = u32::try_from(reply.len()) else {
                continue;
            };
            let mut frame = size.to_be_bytes().to_vec();
            frame.extend_from_slice(&reply);
            drop(stream.write_all(&frame).await);
        }
    });
    Ok(Stub {
        address,
        contacts,
        task,
    })
}

/// A profile whose realm lists `kdcs` in order and `primaries` as `primary_kdc`.
fn profile(kdcs: &[&str], primaries: &[&str]) -> Result<Config, TestError> {
    let realm: String = kdcs
        .iter()
        .map(|address| format!("kdc = {address}\n"))
        .chain(
            primaries
                .iter()
                .map(|address| format!("primary_kdc = {address}\n")),
        )
        .collect();
    Ok(Config::parse(&format!(
        "[libdefaults]\ndns_lookup_kdc = false\n[realms]\n{REALM} = {{\n{realm}}}\n"
    ))?)
}

/// Log in with a password and return the code of the KDC's error.
async fn login_error_code(config: &Config) -> Result<i32, TestError> {
    let result = timeout(
        Duration::from_secs(10),
        Tokio::new().login_tgt_with_password_config(
            config,
            KdcProtocol::Tcp,
            Principal::user(REALM, "testuser1"),
            b"wrong",
            AsReq::new(SystemTime::now(), 7),
        ),
    )
    .await?;
    match result {
        Err(ClientError::Kdc(error)) => Ok(error.error_code()),
        other => Err(format!("expected a KDC error, got {other:?}").into()),
    }
}

/// A replica's failure is retried once on the primary, whose answer is the result.
#[tokio::test]
async fn a_replica_failure_is_retried_on_the_primary() -> Result<(), TestError> {
    // Given a replica that refuses the preauthentication and a primary that answers otherwise.
    let replica = kdc(24).await?;
    let primary = kdc(6).await?;
    let config = profile(&[&replica.address, &primary.address], &[&primary.address])?;
    // When a password login runs.
    let code = login_error_code(&config).await?;
    // Then the primary was asked once after the replica, and its error is the result.
    assert_eq!(code, 6_i32);
    assert_eq!(replica.contacts.load(Ordering::SeqCst), 1);
    assert_eq!(primary.contacts.load(Ordering::SeqCst), 1);
    Ok(())
}

/// A replica's error is retried on the primary also when encrypted timestamp is disabled.
///
/// The timestamp refusal applies to a preauthentication challenge only (MIT
/// `preauth_encts.c:68-73`); any other KDC error stays the KDC's error.
#[tokio::test]
async fn a_replica_failure_is_retried_on_the_primary_when_timestamps_are_disabled()
-> Result<(), TestError> {
    // Given a realm that disables encrypted timestamp, a refusing replica and a primary.
    let replica = kdc(24).await?;
    let primary = kdc(6).await?;
    let config = Config::parse(&format!(
        "[libdefaults]\ndns_lookup_kdc = false\n[realms]\n{REALM} = {{\nkdc = {}\nkdc = {}\nprimary_kdc = {}\ndisable_encrypted_timestamp = true\n}}\n",
        replica.address, primary.address, primary.address
    ))?;
    // When a password login runs.
    let code = login_error_code(&config).await?;
    // Then the primary was asked after the replica, and its error is the result.
    assert_eq!(code, 6_i32);
    assert_eq!(replica.contacts.load(Ordering::SeqCst), 1);
    assert_eq!(primary.contacts.load(Ordering::SeqCst), 1);
    Ok(())
}

/// A primary's own failure is final: it is not asked twice.
#[tokio::test]
async fn a_primary_failure_is_not_retried() -> Result<(), TestError> {
    // Given a primary listed before the replica.
    let primary = kdc(24).await?;
    let replica = kdc(6).await?;
    let config = profile(&[&primary.address, &replica.address], &[&primary.address])?;
    // When a password login runs.
    let code = login_error_code(&config).await?;
    // Then only the primary was contacted, once.
    assert_eq!(code, 24_i32);
    assert_eq!(primary.contacts.load(Ordering::SeqCst), 1);
    assert_eq!(replica.contacts.load(Ordering::SeqCst), 0);
    Ok(())
}

/// A realm without primaries has no replicas to distrust: no retry.
#[tokio::test]
async fn a_realm_without_primaries_is_not_retried() -> Result<(), TestError> {
    let first = kdc(24).await?;
    let second = kdc(6).await?;
    let config = profile(&[&first.address, &second.address], &[])?;
    let code = login_error_code(&config).await?;
    assert_eq!(code, 24_i32);
    assert_eq!(first.contacts.load(Ordering::SeqCst), 1);
    assert_eq!(second.contacts.load(Ordering::SeqCst), 0);
    Ok(())
}

/// A primary that cannot be reached leaves the replica's error as the result (MIT restores it).
#[tokio::test]
async fn an_unreachable_primary_keeps_the_replicas_error() -> Result<(), TestError> {
    // Given a replica and a primary on a closed port.
    let replica = kdc(24).await?;
    let closed = format!("127.0.0.1:{}", reserve_closed_tcp_port()?);
    let config = profile(&[&replica.address], &[&closed])?;
    // When a password login runs.
    let code = login_error_code(&config).await?;
    // Then the replica's error stands.
    assert_eq!(code, 24_i32);
    assert_eq!(replica.contacts.load(Ordering::SeqCst), 1);
    Ok(())
}

/// `master_kdc` names the primaries when `primary_kdc` is absent.
#[tokio::test]
async fn master_kdc_names_the_primary_when_primary_kdc_is_absent() -> Result<(), TestError> {
    let replica = kdc(24).await?;
    let primary = kdc(6).await?;
    let config = Config::parse(&format!(
        "[libdefaults]\ndns_lookup_kdc = false\n[realms]\n{REALM} = {{\nkdc = {}\nkdc = {}\nmaster_kdc = {}\n}}\n",
        replica.address, primary.address, primary.address
    ))?;
    assert_eq!(login_error_code(&config).await?, 6_i32);
    Ok(())
}
