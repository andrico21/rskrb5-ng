//! DNS URI records before SRV records, sites, roles, registered locators (MIT-dns-1, -2,
//! -6, MIT-config-17, -46, MIT-plugin-6).

use hickory_resolver::proto::{op::ResponseCode, rr::RecordType};
use rskrb5_ng::{
    client::transport::{KdcEndpoint, KdcEndpointSource, KdcProtocol, Tokio},
    config::Config,
};

use crate::{
    TestError,
    fixture::{Dns, Reply, srv, uri},
};

/// The realm every test discovers.
const REALM: &str = "TEST.GOKRB5";
/// URI discovery name of the KDC service.
const KDC_URI: &str = "_kerberos.test.gokrb5.";

/// A profile with DNS discovery and, optionally, URI records and a site.
fn config(uri_lookup: bool, site: Option<&str>) -> Result<Config, TestError> {
    let realm = site.map_or_else(String::new, |name| {
        format!("[realms]\nTEST.GOKRB5 = {{\nsitename = {name}\n}}\n")
    });
    Ok(Config::parse(&format!(
        "[libdefaults]\ndns_lookup_kdc = true\ndns_uri_lookup = {uri_lookup}\n{realm}"
    ))?)
}

/// A transport that asks `dns`.
fn via(dns: &Dns) -> Result<Tokio, TestError> {
    Ok(Tokio::new().with_dns_server(&dns.address().to_string())?)
}

/// The `host:port` of each endpoint.
fn authorities(endpoints: &[KdcEndpoint]) -> Vec<String> {
    endpoints.iter().map(KdcEndpoint::authority).collect()
}

/// The questions that ask for `kind`.
fn asked(dns: &Dns, kind: &str) -> Result<usize, TestError> {
    Ok(dns
        .questions()?
        .iter()
        .filter(|question| question.starts_with(kind))
        .count())
}

/// MIT-dns-2, MIT-config-17: URI records come before SRV records, and SRV is not asked
/// when a URI record gives a server.
#[tokio::test]
async fn uri_records_are_used_before_srv_records() -> Result<(), TestError> {
    // Given a URI record and an SRV record for the same realm.
    let dns = Dns::start([
        (
            KDC_URI,
            RecordType::Unknown(256),
            Reply::Records(vec![uri(0, "krb5srv::tcp:127.0.0.1:1088")]),
        ),
        (
            "_kerberos._tcp.test.gokrb5.",
            RecordType::SRV,
            Reply::Records(vec![srv(0, 2088, "127.0.0.1.")?]),
        ),
    ])
    .await?;
    // When the KDCs are discovered with URI lookup on.
    let endpoints = via(&dns)?
        .discover_kdcs(&config(true, None)?, REALM, KdcProtocol::Tcp)
        .await?;
    // Then the URI record's server is used, and SRV was never asked.
    assert_eq!(authorities(&endpoints), ["127.0.0.1:1088"]);
    assert_eq!(
        endpoints.first().map(|endpoint| endpoint.source),
        Some(KdcEndpointSource::DnsUri)
    );
    assert_eq!(asked(&dns, "SRV")?, 0);
    Ok(())
}

/// MIT-config-17: URI lookup is off by default (this crate), so only SRV is asked.
#[tokio::test]
async fn uri_lookup_is_off_unless_enabled() -> Result<(), TestError> {
    // Given both kinds of record.
    let dns = Dns::start([
        (
            KDC_URI,
            RecordType::Unknown(256),
            Reply::Records(vec![uri(0, "krb5srv::tcp:127.0.0.1:1088")]),
        ),
        (
            "_kerberos._tcp.test.gokrb5.",
            RecordType::SRV,
            Reply::Records(vec![srv(0, 2088, "127.0.0.1.")?]),
        ),
    ])
    .await?;
    // When URI lookup is off, then SRV is used and no URI question is sent.
    let endpoints = via(&dns)?
        .discover_kdcs(&config(false, None)?, REALM, KdcProtocol::Tcp)
        .await?;
    assert_eq!(authorities(&endpoints), ["127.0.0.1:2088"]);
    assert_eq!(asked(&dns, "Unknown")?, 0);
    Ok(())
}

/// QA failure scenario: a URI record with an unknown transport is ignored and the next one used.
#[tokio::test]
async fn a_uri_record_with_an_unknown_transport_is_ignored() -> Result<(), TestError> {
    // Given records that MIT's `parse_uri_fields` rejects, before a good one.
    let dns = Dns::start([(
        KDC_URI,
        RecordType::Unknown(256),
        Reply::Records(vec![
            uri(0, "krb5srv::carrier-pigeon:127.0.0.9:88"),
            uri(1, "http::tcp:127.0.0.9:88"),
            uri(2, "krb5srv:tcp:127.0.0.9:88"),
            uri(3, "krb5srv::kkdcp:https://kdc.example/KdcProxy"),
            uri(4, "KRB5SRV:M:TCP:127.0.0.1:1088"),
        ]),
    )])
    .await?;
    // When the KDCs are discovered.
    let endpoints = via(&dns)?
        .discover_kdcs(&config(true, None)?, REALM, KdcProtocol::Tcp)
        .await?;
    // Then only the well-formed TCP record is used.
    assert_eq!(authorities(&endpoints), ["127.0.0.1:1088"]);
    Ok(())
}

/// With no usable URI record discovery goes on to SRV.
#[tokio::test]
async fn srv_is_used_when_no_uri_record_is_usable() -> Result<(), TestError> {
    // Given only an unusable URI record and an SRV record.
    let dns = Dns::start([
        (
            KDC_URI,
            RecordType::Unknown(256),
            Reply::Records(vec![uri(0, "krb5srv::bogus:127.0.0.9")]),
        ),
        (
            "_kerberos._tcp.test.gokrb5.",
            RecordType::SRV,
            Reply::Records(vec![srv(0, 2088, "127.0.0.1.")?]),
        ),
    ])
    .await?;
    // When the KDCs are discovered, then SRV answers.
    let endpoints = via(&dns)?
        .discover_kdcs(&config(true, None)?, REALM, KdcProtocol::Tcp)
        .await?;
    assert_eq!(authorities(&endpoints), ["127.0.0.1:2088"]);
    Ok(())
}

/// The requested transport selects URI records; `Auto` keeps each record's own.
#[tokio::test]
async fn uri_transport_follows_the_request() -> Result<(), TestError> {
    // Given a UDP and a TCP record.
    let dns = Dns::start([(
        KDC_URI,
        RecordType::Unknown(256),
        Reply::Records(vec![
            uri(0, "krb5srv::udp:127.0.0.1:1088"),
            uri(1, "krb5srv::tcp:127.0.0.1:1089"),
        ]),
    )])
    .await?;
    let transport = via(&dns)?;
    let profile = config(true, None)?;
    // When each protocol is requested.
    let udp = transport
        .discover_kdcs(&profile, REALM, KdcProtocol::Udp)
        .await?;
    let tcp = transport
        .discover_kdcs(&profile, REALM, KdcProtocol::Tcp)
        .await?;
    let auto = transport
        .discover_kdcs(&profile, REALM, KdcProtocol::Auto)
        .await?;
    // Then each gets its records, and `Auto` keeps the protocol of each.
    assert_eq!(authorities(&udp), ["127.0.0.1:1088"]);
    assert_eq!(authorities(&tcp), ["127.0.0.1:1089"]);
    assert_eq!(authorities(&auto), ["127.0.0.1:1088", "127.0.0.1:1089"]);
    assert_eq!(
        auto.iter()
            .map(|endpoint| endpoint.protocol)
            .collect::<Vec<_>>(),
        [KdcProtocol::Udp, KdcProtocol::Tcp]
    );
    Ok(())
}

/// MIT-dns-6, MIT-config-46: the realm's site is asked first, as
/// `<service>.<proto>.<site>._sites.<realm>`.
#[tokio::test]
async fn the_site_is_asked_before_the_realm() -> Result<(), TestError> {
    // Given a site-specific and a generic SRV set.
    let dns = Dns::start([
        (
            "_kerberos._tcp.hq._sites.test.gokrb5.",
            RecordType::SRV,
            Reply::Records(vec![srv(0, 3088, "127.0.0.1.")?]),
        ),
        (
            "_kerberos._tcp.test.gokrb5.",
            RecordType::SRV,
            Reply::Records(vec![srv(0, 4088, "127.0.0.1.")?]),
        ),
    ])
    .await?;
    // When a realm with and one without the site relation are discovered.
    let with = via(&dns)?
        .discover_kdcs(&config(false, Some("HQ"))?, REALM, KdcProtocol::Tcp)
        .await?;
    let without = via(&dns)?
        .discover_kdcs(&config(false, None)?, REALM, KdcProtocol::Tcp)
        .await?;
    // Then the site's servers come only for the realm that names its site.
    assert_eq!(authorities(&with), ["127.0.0.1:3088"]);
    assert_eq!(authorities(&without), ["127.0.0.1:4088"]);
    Ok(())
}

/// A site that has no records, or whose lookup fails, falls back to the realm's own name.
#[tokio::test]
async fn a_site_without_an_answer_falls_back_to_the_realm() -> Result<(), TestError> {
    // Given a site name that answers SERVFAIL for SRV and is absent for URI.
    let dns = Dns::start([
        (
            "_kerberos._tcp.hq._sites.test.gokrb5.",
            RecordType::SRV,
            Reply::Code(ResponseCode::ServFail),
        ),
        (
            "_kerberos._tcp.test.gokrb5.",
            RecordType::SRV,
            Reply::Records(vec![srv(0, 4088, "127.0.0.1.")?]),
        ),
        (
            KDC_URI,
            RecordType::Unknown(256),
            Reply::Records(vec![uri(0, "krb5srv::tcp:127.0.0.1:5088")]),
        ),
    ])
    .await?;
    let transport = via(&dns)?;
    // When SRV and then URI discovery run for that site.
    let srv_only = transport
        .discover_kdcs(&config(false, Some("hq"))?, REALM, KdcProtocol::Tcp)
        .await?;
    let uri_first = transport
        .discover_kdcs(&config(true, Some("hq"))?, REALM, KdcProtocol::Tcp)
        .await?;
    // Then each falls back to the realm's own record.
    assert_eq!(authorities(&srv_only), ["127.0.0.1:4088"]);
    assert_eq!(authorities(&uri_first), ["127.0.0.1:5088"]);
    assert!(
        dns.questions()?
            .iter()
            .any(|question| question.contains("_kerberos.hq._sites.test.gokrb5.")),
        "the site's URI name was not asked"
    );
    Ok(())
}

/// MIT-dns-2: kpasswd discovery asks URI records before SRV records too.
#[tokio::test]
async fn kpasswd_discovery_uses_uri_records_first() -> Result<(), TestError> {
    // Given a `_kpasswd` URI record and a `_kpasswd._tcp` SRV record.
    let dns = Dns::start([
        (
            "_kpasswd.test.gokrb5.",
            RecordType::Unknown(256),
            Reply::Records(vec![uri(0, "krb5srv::tcp:127.0.0.1:1464")]),
        ),
        (
            "_kpasswd._tcp.test.gokrb5.",
            RecordType::SRV,
            Reply::Records(vec![srv(0, 2464, "127.0.0.1.")?]),
        ),
    ])
    .await?;
    // When the password servers are discovered for TCP.
    let endpoints = via(&dns)?
        .discover_kpasswd_servers(&config(true, None)?, REALM, KdcProtocol::Tcp)
        .await?;
    // Then the URI record's server is used.
    assert_eq!(authorities(&endpoints), ["127.0.0.1:1464"]);
    assert_eq!(asked(&dns, "SRV")?, 0);
    Ok(())
}
