//! `request_timeout`: one total budget over DNS, connect, retries and read (MIT-config-38,
//! MIT-dns-8).

use core::{future::pending, time::Duration};
use std::time::Instant;

use hickory_resolver::proto::rr::RecordType;
use rskrb5_ng::{
    client::transport::{KdcProtocol, Tokio},
    config::Config,
    error::Client as ClientError,
};
use tokio::{io::AsyncReadExt as _, net::TcpListener, task::JoinSet, time::timeout};

use crate::{
    TestError,
    fixture::{Dns, Reply, documentation, srv},
};

/// The realm every test contacts.
const REALM: &str = "TEST.GOKRB5";

/// A profile with the given KDCs (`kdc = ...` lines) and `request_timeout`.
fn profile(timeout_seconds: &str, kdcs: &str) -> Result<Config, TestError> {
    Ok(Config::parse(&format!(
        "[libdefaults]\ndns_lookup_kdc = true\nrequest_timeout = {timeout_seconds}\n[realms]\n{REALM} = {{\n{kdcs}\n}}\n"
    ))?)
}

/// MIT-config-38: a nonzero `request_timeout` is honoured (it was refused before), and
/// bounds all DNS lookups together although each answer alone is fast enough.
#[tokio::test]
async fn the_budget_covers_every_dns_lookup_together() -> Result<(), TestError> {
    // Given a resolver whose every answer takes 600 ms and a set that needs two rounds.
    let rules = || -> Result<_, TestError> {
        Ok([
            (
                "_kerberos._tcp.test.gokrb5.",
                RecordType::SRV,
                Reply::Records(vec![srv(0, 88, "kdc.test.gokrb5.")?]),
            ),
            (
                "kdc.test.gokrb5.",
                RecordType::A,
                Reply::Records(vec![documentation()]),
            ),
        ])
    };
    let dns = Dns::start_slow(rules()?, Duration::from_millis(600)).await?;
    let transport = Tokio::new().with_dns_server(&dns.address().to_string())?;
    let capped = Config::parse("[libdefaults]\ndns_lookup_kdc = true\nrequest_timeout = 1s\n")?;
    let uncapped = Config::parse("[libdefaults]\ndns_lookup_kdc = true\n")?;
    // When the KDCs are discovered under a 1 s budget and without one.
    let begun = Instant::now();
    let with_budget = transport
        .discover_kdcs(&capped, REALM, KdcProtocol::Tcp)
        .await;
    let spent = begun.elapsed();
    let without = transport
        .discover_kdcs(&uncapped, REALM, KdcProtocol::Tcp)
        .await?;
    // Then the budget ends the lookup at its total, and no budget lets it finish.
    assert!(
        matches!(with_budget, Err(ClientError::TransportTimeout(total)) if total == Duration::from_secs(1)),
        "{with_budget:?}"
    );
    assert!(spent < Duration::from_millis(1900), "{spent:?}");
    assert_eq!(without.len(), 1);
    Ok(())
}

/// A KDC that accepts and never answers ends at the budget, not at the per-exchange timeout,
/// and several of them share the one budget.
#[tokio::test]
async fn the_budget_is_shared_by_the_endpoints_and_cuts_the_wait_for_a_reply()
-> Result<(), TestError> {
    // Given two KDCs that accept a connection and read the request but never reply.
    let first = TcpListener::bind("127.0.0.1:0").await?;
    let second = TcpListener::bind("127.0.0.1:0").await?;
    let kdcs = format!(
        "kdc = {}\nkdc = {}",
        first.local_addr()?,
        second.local_addr()?
    );
    let silent = |listener: TcpListener| {
        tokio::spawn(async move {
            let mut held = JoinSet::new();
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                drop(held.spawn(async move {
                    let mut sink = [0_u8; 64];
                    drop(stream.read(&mut sink).await);
                    pending::<()>().await;
                }));
            }
        })
    };
    let tasks = [silent(first), silent(second)];
    let config = profile("1s", &kdcs)?;
    // When a request is sent with a 5 s per-exchange timeout.
    let begun = Instant::now();
    let result = timeout(
        Duration::from_secs(8),
        Tokio::new().send_to_realm(&config, KdcProtocol::Tcp, REALM, b"request"),
    )
    .await?;
    let spent = begun.elapsed();
    for task in tasks {
        task.abort();
    }
    // Then the whole request ended at the budget, far below the 2 x 5 s the attempts could take.
    assert!(
        matches!(&result, Err(ClientError::TransportTimeout(total)) if *total == Duration::from_secs(1)),
        "{result:?}"
    );
    assert!(spent < Duration::from_secs(3), "{spent:?}");
    Ok(())
}
