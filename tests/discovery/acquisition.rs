//! Host acquisition (MIT-config-14, -34, -35, the client share of MIT-dns-4).
//!
//! Canonical names are made lazily, each name other than the host itself needs
//! the caller's approval, and the next name is tried only after the KDC said
//! the principal is unknown (MIT `k5_canonprinc`, `get_creds.c:1292-1305`).

use std::sync::{Mutex, PoisonError};

use hickory_resolver::proto::rr::RecordType;
use rskrb5_ng::{
    client::{
        Tokio as Client,
        principal::Principal,
        process_kdc_error,
        transport::{KdcProtocol, Tokio},
    },
    config::Config,
    discovery::hostname::CanonicalizationPolicy,
    error::Client as ClientError,
};

use crate::{
    TestError,
    closed_port::reserve_closed_tcp_port,
    fixture::{Dns, Reply, cname, documentation, ptr},
    primary::krb_error,
};

/// A zone where `short` is a CNAME of `real.example.com`, whose address has a PTR name.
async fn zone() -> Result<Dns, TestError> {
    Dns::start([
        (
            "short.",
            RecordType::A,
            Reply::Owned(vec![
                ("short.", cname("real.example.com.")?),
                ("real.example.com.", documentation()),
            ]),
        ),
        (
            "7.2.0.192.in-addr.arpa.",
            RecordType::PTR,
            Reply::Records(vec![ptr("Ptr.Example.COM.")?]),
        ),
    ])
    .await
}

/// The transport asking `dns` and the policy of `lines`.
fn setup(dns: &Dns, lines: &str) -> Result<(Tokio, CanonicalizationPolicy), TestError> {
    let config = Config::parse(&format!("[libdefaults]\n{lines}\n"))?;
    Ok((
        Tokio::new().with_dns_server(&dns.address().to_string())?,
        CanonicalizationPolicy::from_config(&config),
    ))
}

/// How the fake KDC answers a request for a host name.
type Answer<'answer> = &'answer (dyn Fn(&str) -> Result<String, ClientError> + Sync);

/// Run an acquisition of `host` that records every name it tries and answers
/// each with `answer`, approving the names `approved` lists.
async fn acquire(
    (transport, policy): &(Tokio, CanonicalizationPolicy),
    host: &str,
    (approved, answer): (&[&str], Answer<'_>),
) -> (Result<String, ClientError>, Vec<String>) {
    let tried = Mutex::new(Vec::new());
    let approve = |_requested: &str, candidate: &str| approved.contains(&candidate);
    let result = policy
        .acquire(transport, (host, &approve), async |name: &str| {
            tried
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(name.to_owned());
            answer(name)
        })
        .await;
    (
        result,
        tried.into_inner().unwrap_or_else(PoisonError::into_inner),
    )
}

/// MIT-config-14 `fallback`: the host itself answers, so DNS is never asked.
#[tokio::test]
async fn fallback_does_not_resolve_after_plain_success() -> Result<(), TestError> {
    let dns = zone().await?;
    let setup = setup(&dns, "dns_canonicalize_hostname = fallback")?;
    let (result, tried) = acquire(&setup, "Short", (&[], &|name| Ok(name.to_owned()))).await;
    assert_eq!(result?, "short");
    assert_eq!(tried, ["short"]);
    assert_eq!(dns.questions()?, Vec::<String>::new());
    Ok(())
}

/// MIT-config-14 `fallback`: after the KDC does not know the host's principal,
/// DNS names an approved canonical host, which is tried next.
#[tokio::test]
async fn fallback_resolves_after_principal_unknown() -> Result<(), TestError> {
    let dns = zone().await?;
    let setup = setup(&dns, "dns_canonicalize_hostname = fallback\nrdns = false")?;
    // The KDC does not know `host/short` (`KDC_ERR_S_PRINCIPAL_UNKNOWN`).
    let unknown = krb_error(7)?;
    let kdc = |name: &str| -> Result<String, ClientError> {
        if name == "short" {
            return Err(ClientError::Kdc(Box::new(process_kdc_error(&unknown)?)));
        }
        Ok(name.to_owned())
    };
    let (result, tried) = acquire(&setup, "short", (&["real.example.com"], &kdc)).await;
    assert_eq!(result?, "real.example.com");
    assert_eq!(tried, ["short", "real.example.com"]);
    assert!(
        !dns.questions()?.is_empty(),
        "DNS is asked after the first answer"
    );
    Ok(())
}

/// MIT-config-14 `true`: the DNS name is used when the policy approves it, and
/// a refused one is never tried.
#[tokio::test]
async fn opted_in_host_acquisition_uses_canonical_name() -> Result<(), TestError> {
    let dns = zone().await?;
    let setup = setup(&dns, "dns_canonicalize_hostname = true\nrdns = false")?;
    let (approved, tried) = acquire(
        &setup,
        "short",
        (&["real.example.com"], &|name| Ok(name.to_owned())),
    )
    .await;
    assert_eq!(approved?, "real.example.com");
    assert_eq!(tried, ["real.example.com"]);
    let (refused, none) = acquire(&setup, "short", (&[], &|name| Ok(name.to_owned()))).await;
    assert!(
        matches!(&refused, Err(ClientError::HostNameNotApproved { host }) if host == "short"),
        "{refused:?}"
    );
    assert_eq!(none, Vec::<String>::new());
    Ok(())
}

/// MIT-config-35: with `rdns` the PTR name is proposed, and an unapproved one
/// is refused instead of used.
#[tokio::test]
async fn unapproved_ptr_identity_is_refused() -> Result<(), TestError> {
    let dns = zone().await?;
    let setup = setup(&dns, "dns_canonicalize_hostname = true\nrdns = true")?;
    let (refused, tried) = acquire(
        &setup,
        "short",
        (&["real.example.com"], &|name| Ok(name.to_owned())),
    )
    .await;
    assert!(
        matches!(&refused, Err(ClientError::HostNameNotApproved { host: _ })),
        "{refused:?}"
    );
    assert_eq!(tried, Vec::<String>::new());
    let (approved, _) = acquire(
        &setup,
        "short",
        (&["ptr.example.com"], &|name| Ok(name.to_owned())),
    )
    .await;
    assert_eq!(approved?, "ptr.example.com");
    Ok(())
}

/// MIT-config-35: without `rdns` no reverse lookup is made.
#[tokio::test]
async fn rdns_false_never_queries_ptr() -> Result<(), TestError> {
    let dns = zone().await?;
    let setup = setup(&dns, "dns_canonicalize_hostname = true\nrdns = false")?;
    let (result, _) = acquire(
        &setup,
        "short",
        (&["real.example.com"], &|name| Ok(name.to_owned())),
    )
    .await;
    assert_eq!(result?, "real.example.com");
    let questions = dns.questions()?;
    assert!(!questions.is_empty(), "the forward lookup is made");
    assert!(
        questions
            .iter()
            .all(|question| !question.contains("in-addr.arpa")),
        "{questions:?}"
    );
    Ok(())
}

/// MIT-config-34: the explicit `qualify_shortname` suffix names the host only
/// with the caller's approval, and without DNS.
#[tokio::test]
async fn host_acquisition_uses_explicit_shortname_suffix() -> Result<(), TestError> {
    let dns = zone().await?;
    let setup = setup(
        &dns,
        "dns_canonicalize_hostname = false\nqualify_shortname = example.org",
    )?;
    let (approved, _) = acquire(
        &setup,
        "kdc",
        (&["kdc.example.org"], &|name| Ok(name.to_owned())),
    )
    .await;
    assert_eq!(approved?, "kdc.example.org");
    let (refused, tried) = acquire(&setup, "kdc", (&[], &|name| Ok(name.to_owned()))).await;
    assert!(
        matches!(&refused, Err(ClientError::HostNameNotApproved { host }) if host == "kdc"),
        "{refused:?}"
    );
    assert_eq!(tried, Vec::<String>::new());
    assert_eq!(dns.questions()?, Vec::<String>::new());
    Ok(())
}

/// The stored default `dns_canonicalize_hostname = true` makes no ordinary
/// acquisition ask DNS: only the explicit host-acquisition operation does.
#[tokio::test]
async fn default_host_acquisition_issues_no_dns() -> Result<(), TestError> {
    // Given the default profile, a refused KDC and a DNS peer that records questions.
    let dns = zone().await?;
    let port = reserve_closed_tcp_port()?;
    let config = Config::parse(&format!(
        "[libdefaults]\ndns_lookup_kdc = false\n[realms]\nTEST.GOKRB5 = {{\nkdc = 127.0.0.1:{port}\n}}\n"
    ))?;
    let mut client = Client::with_password(
        config,
        KdcProtocol::Tcp,
        Principal::user("TEST.GOKRB5", "alice"),
        b"password".to_vec(),
    )
    .with_transport(Tokio::new().with_dns_server(&dns.address().to_string())?);
    // When a ticket for a host-based service is requested the ordinary way.
    let service = Principal::host_based_service("HTTP", "short")?;
    let result = client.get_service_ticket(service).await;
    // Then the request failed at the KDC and DNS was never asked.
    assert!(result.is_err(), "the KDC port is closed");
    assert_eq!(dns.questions()?, Vec::<String>::new());
    Ok(())
}
