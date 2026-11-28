//! Service tickets that a GSS initiator credential acquires from a KDC on the
//! network (`gss_acquire_cred` followed by the first `gss_init_sec_context` in
//! MIT): the in-process KDC of these scenarios behind a loopback TCP listener.
//!
//! The profile sets `udp_preference_limit = 1`, so the client speaks TCP only
//! and no UDP socket is involved.

use core::time::Duration;
use std::{
    fs,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use rskrb5_ng::{
    Config,
    error::Gss,
    gss::{Acceptor, AcceptorOptions, Credential, InitStep, Initiator, InitiatorOptions},
};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::{TcpListener, TcpStream},
    time::timeout,
};

use super::{
    client_keytab::keytab_credential,
    context::{Context as _, TestError},
    kdc::Kdc,
    seal::{REALM, USER},
    support::{HOST, keytab, password_credential, target},
};

/// The bound of every exchange and every read of the KDC.
const BOUND: Duration = Duration::from_secs(30);

/// Read one length-prefixed request; `None` once the client hung up.
async fn read_frame(stream: &mut TcpStream) -> Option<Vec<u8>> {
    let mut header = [0_u8; 4];
    let _header_length: usize = timeout(BOUND, stream.read_exact(&mut header))
        .await
        .ok()?
        .ok()?;
    let mut request = vec![0_u8; usize::try_from(u32::from_be_bytes(header)).ok()?];
    let _request_length: usize = timeout(BOUND, stream.read_exact(&mut request))
        .await
        .ok()?
        .ok()?;
    Some(request)
}

/// Answer every request of one connection until it closes.
async fn answer_connection(mut stream: TcpStream, kdc: Arc<Kdc>) {
    while let Some(request) = read_frame(&mut stream).await {
        let Ok(reply) = kdc.answer(REALM, &request) else {
            return;
        };
        let Ok(length) = u32::try_from(reply.len()) else {
            return;
        };
        if stream.write_all(&length.to_be_bytes()).await.is_err()
            || stream.write_all(&reply).await.is_err()
        {
            return;
        }
    }
}

/// The KDC listening on loopback, and the profile that names it.
async fn serve() -> Result<(Arc<Kdc>, Config), TestError> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let kdc = Arc::new(Kdc::new());
    let served = Arc::clone(&kdc);
    drop(tokio::spawn(async move {
        while let Ok((stream, _peer)) = listener.accept().await {
            drop(tokio::spawn(answer_connection(stream, Arc::clone(&served))));
        }
    }));
    let config = Config::parse(&format!(
        "[libdefaults]\n default_realm = {REALM}\n dns_lookup_kdc = false\n \
         dns_lookup_realm = false\n udp_preference_limit = 1\n\
         [realms]\n {REALM} = {{\n  kdc = 127.0.0.1:{port}\n }}\n"
    ))?;
    Ok((kdc, config))
}

/// The kinds of request the KDC answered, in order.
fn kinds(kdc: &Kdc) -> Vec<&'static str> {
    kdc.log().iter().map(|(_realm, kind)| *kind).collect()
}

/// Acquire a ticket for `HTTP@<host>` into `credential` and check what it kept:
/// the user's TGT and service ticket in a new cache for the user, the TGT's end
/// as the credential's expiry, and a ticket the acceptor of the host takes.
async fn acquire_and_check(mut credential: Credential) -> Result<(), TestError> {
    let (kdc, config) = serve().await?;
    // Given an initiator credential that holds no ticket yet,
    assert!(credential.ccache().is_none());
    assert_eq!(credential.inquire().expires(), None);
    // when it acquires a ticket for the service,
    timeout(
        BOUND,
        credential.acquire_service_ticket(&target()?, &config),
    )
    .await??;
    // then the KDC answered the probe, the preauthenticated AS-REQ and the TGS-REQ,
    assert_eq!(kinds(&kdc), ["AS", "AS", "TGS"]);
    // the credential keeps both tickets in a cache of the user,
    let cache = credential
        .ccache()
        .context("the credential keeps a cache")?;
    assert_eq!(cache.client_name(), USER);
    assert_eq!(cache.credentials().len(), 2);
    assert!(cache.contains_server(&["krbtgt", REALM]));
    assert!(cache.contains_server(&["HTTP", HOST]));
    // its expiry is the TGT's end,
    let tgt_end = cache
        .credentials()
        .iter()
        .find(|entry| entry.server().components == ["krbtgt", REALM])
        .map(|entry| entry.times().end_time)
        .context("the TGT")?;
    assert_eq!(
        credential.inquire().expires(),
        UNIX_EPOCH.checked_add(Duration::from_secs(u64::from(tgt_end)))
    );
    assert!(credential.inquire().expires() > Some(SystemTime::now()));
    // and the kept service ticket opens a context with the host's acceptor
    // without another exchange.
    let mut initiator = Initiator::new(target()?, InitiatorOptions::new());
    let InitStep::Continue(token) = initiator.init_sec_context(&credential, None)? else {
        return Err("mutual authentication waits for the AP-REP".into());
    };
    let store = Credential::from_keytab(keytab());
    let accepted = Acceptor::new(&store, AcceptorOptions::new())?.accept_sec_context(&token)?;
    let inquiry = accepted.into_context().inquire();
    let client = inquiry.source().principal();
    assert_eq!(
        (client.realm.as_str(), client.components.as_slice()),
        (REALM, [USER.to_owned()].as_slice())
    );
    assert_eq!(kinds(&kdc).len(), 3);
    Ok(())
}

/// A password credential acquires the TGT and the service ticket and keeps both.
#[tokio::test]
async fn a_password_credential_keeps_the_acquired_tickets() -> Result<(), TestError> {
    acquire_and_check(password_credential(true)?).await
}

/// A client-keytab credential acquires the TGT and the service ticket and keeps both.
#[tokio::test]
async fn a_client_keytab_credential_keeps_the_acquired_tickets() -> Result<(), TestError> {
    let (credential, directory) = keytab_credential("acquire")?;
    acquire_and_check(credential).await?;
    fs::remove_dir_all(&directory)?;
    Ok(())
}

/// An acceptor credential acquires nothing: the KDC is never asked.
#[tokio::test]
async fn an_acceptor_credential_acquires_no_ticket() -> Result<(), TestError> {
    let (kdc, config) = serve().await?;
    let mut credential = Credential::from_keytab(keytab());
    let refused = timeout(
        BOUND,
        credential.acquire_service_ticket(&target()?, &config),
    )
    .await?;
    assert!(
        matches!(refused, Err(Gss::WrongCredentialUsage(_))),
        "{refused:?}"
    );
    assert!(kinds(&kdc).is_empty() && credential.ccache().is_none());
    Ok(())
}
