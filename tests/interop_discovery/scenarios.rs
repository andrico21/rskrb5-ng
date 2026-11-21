//! The scenarios of the `discovery` suite.

use core::{
    error::Error,
    net::{IpAddr, SocketAddr},
    time::Duration,
};
use std::{
    io,
    time::{SystemTime, UNIX_EPOCH},
};

use hickory_resolver::{
    TokioResolver,
    config::{ConnectionConfig, NameServerConfig, ResolverConfig},
    net::runtime,
};
use rskrb5_ng::{
    client::{
        options::AsReq,
        principal::Principal,
        transport::{KdcEndpointSource, KdcProtocol, Tokio as TokioKdcTransport},
    },
    config::Config,
    discovery::{hostname::CanonicalizationPolicy, locate::EndpointRole},
};
use tokio::runtime::{Builder, Runtime};

use crate::harness::{self, Fixture};

/// The AES-SHA2 enctype of the realm's strongest key.
const AES256_SHA2: i32 = 20;

/// The TEST.RSKRB5 KDC (fixture `mit-kdc`).
const MIT_KDC: Fixture = Fixture::new("mit-kdc", "INTEROP_MIT_KDC");

/// The `CoreDNS` server, host view (fixture `dns`).
const DNS: Fixture = Fixture::new("dns", "INTEROP_DNS");

/// The site of the zone's site-specific records.
const SITE: &str = "lab1";

/// The current-thread Tokio runtime the scenarios run on.
fn runtime() -> io::Result<Runtime> {
    Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
}

/// A transport that asks the fixture's DNS server.
fn transport() -> Result<TokioKdcTransport, Box<dyn Error>> {
    Ok(TokioKdcTransport::new()
        .with_timeout(Duration::from_secs(10))
        .with_dns_server(&harness::var("INTEROP_DNS_SERVER")?)?)
}

/// A profile with DNS discovery, optionally with URI records, a site and the TXT lookup.
fn profile(
    realm: &str,
    uri: bool,
    site: Option<&str>,
    txt: bool,
) -> Result<Config, Box<dyn Error>> {
    let entry = site.map_or_else(String::new, |name| {
        format!("[realms]\n {realm} = {{\n  sitename = {name}\n }}\n")
    });
    Ok(Config::parse(&format!(
        "[libdefaults]\n default_realm = {realm}\n dns_lookup_kdc = true\n dns_uri_lookup = {uri}\n dns_lookup_realm = {txt}\n{entry}"
    ))?)
}

/// The port the TEST KDC is published on.
fn kdc_port() -> Result<u16, Box<dyn Error>> {
    Ok(harness::var("INTEROP_MIT_KDC")?
        .rsplit_once(':')
        .ok_or("INTEROP_MIT_KDC has no port")?
        .1
        .parse()?)
}

/// The test user, its password and its realm.
fn user() -> Result<(Principal, Vec<u8>), Box<dyn Error>> {
    Ok((
        Principal::user(
            harness::var("INTEROP_MIT_REALM")?,
            harness::var("INTEROP_MIT_USER")?,
        ),
        harness::var("INTEROP_MIT_USER_PASSWORD")?.into_bytes(),
    ))
}

/// A nonce for the AS-REQ.
fn nonce() -> Result<u32, Box<dyn Error>> {
    let elapsed = SystemTime::now().duration_since(UNIX_EPOCH)?;
    Ok(u32::try_from(elapsed.as_nanos() & 0x00ff_ffff)?)
}

/// URI records are used before SRV records, and a login through each discovered endpoint works.
#[test]
fn uri_records_discover_the_test_kdc_before_srv() -> Result<(), Box<dyn Error>> {
    if !harness::require(
        "uri_records_discover_the_test_kdc_before_srv",
        &[DNS, MIT_KDC],
    )? {
        return Ok(());
    }
    runtime()?.block_on(async {
        let (user, password) = user()?;
        let realm = user.realm.clone();
        let port = kdc_port()?;
        let transport = transport()?;
        // Given URI lookup on, the zone's `_kerberos` URI records name the KDC over UDP and TCP
        // and the KDC proxy over MS-KKDCP, a stream (MIT `locate_kdc.c:683-690`).
        let uri = profile(&realm, true, None, false)?;
        let endpoints = transport
            .discover_kdcs(&uri, &realm, KdcProtocol::Auto)
            .await?;
        assert_eq!(
            endpoints
                .iter()
                .map(|endpoint| (endpoint.protocol, endpoint.proxy.is_some()))
                .collect::<Vec<_>>(),
            [
                (KdcProtocol::Udp, false),
                (KdcProtocol::Tcp, false),
                (KdcProtocol::Tcp, true)
            ]
        );
        for endpoint in &endpoints {
            assert_eq!(endpoint.source, KdcEndpointSource::DnsUri);
            if endpoint.proxy.is_none() {
                assert_eq!(endpoint.port, port);
            }
        }
        // And with URI lookup off the same KDC comes from the SRV records.
        let srv = profile(&realm, false, None, false)?;
        for endpoint in transport
            .discover_kdcs(&srv, &realm, KdcProtocol::Tcp)
            .await?
        {
            assert_eq!(endpoint.source, KdcEndpointSource::DnsSrv);
            assert_eq!(endpoint.port, port);
        }
        // When a password login uses each discovery, then both authenticate against MIT.
        for config in [&uri, &srv] {
            let session = transport
                .login_tgt_with_password_config(
                    config,
                    KdcProtocol::Tcp,
                    user.clone(),
                    &password,
                    AsReq::new(SystemTime::now(), nonce()?)
                        .with_ticket_lifetime(Duration::from_hours(1))
                        .with_etypes(vec![AES256_SHA2]),
                )
                .await?;
            assert_eq!(session.client(), &user);
        }
        Ok::<_, Box<dyn Error>>(())
    })
}

/// The realm's site records are asked first: the zone's site URI record is one UDP record
/// flagged primary, against the two records of the realm itself.
#[test]
fn the_site_records_answer_before_the_realm_records() -> Result<(), Box<dyn Error>> {
    if !harness::require(
        "the_site_records_answer_before_the_realm_records",
        &[DNS, MIT_KDC],
    )? {
        return Ok(());
    }
    runtime()?.block_on(async {
        let realm = harness::var("INTEROP_MIT_REALM")?;
        let transport = transport()?;
        let plain = profile(&realm, true, None, false)?;
        let sited = profile(&realm, true, Some(SITE), false)?;
        let generic = transport
            .discover_kdcs(&plain, &realm, KdcProtocol::Auto)
            .await?;
        let site = transport
            .discover_kdcs(&sited, &realm, KdcProtocol::Auto)
            .await?;
        assert_eq!(generic.len(), 3, "the realm's URI records: {generic:?}");
        assert_eq!(site.len(), 1, "the site's URI record: {site:?}");
        assert_eq!(
            site.first().map(|endpoint| endpoint.protocol),
            Some(KdcProtocol::Udp)
        );
        // And a site that the zone does not know falls back to the realm's records.
        let unknown = profile(&realm, true, Some("nowhere"), false)?;
        let fallback = transport
            .discover_kdcs(&unknown, &realm, KdcProtocol::Auto)
            .await?;
        assert_eq!(fallback.len(), 3, "{fallback:?}");
        // The SRV records of the site name the same KDC.
        let srv_site = profile(&realm, false, Some(SITE), false)?;
        let by_srv = transport
            .discover_kdcs(&srv_site, &realm, KdcProtocol::Tcp)
            .await?;
        assert_eq!(by_srv.len(), 1, "{by_srv:?}");
        Ok::<_, Box<dyn Error>>(())
    })
}

/// A primary KDC is the URI record flagged `m`, and only that one.
#[test]
fn the_primary_role_is_the_flagged_uri_record() -> Result<(), Box<dyn Error>> {
    if !harness::require(
        "the_primary_role_is_the_flagged_uri_record",
        &[DNS, MIT_KDC],
    )? {
        return Ok(());
    }
    runtime()?.block_on(async {
        let realm = harness::var("INTEROP_MIT_REALM")?;
        let transport = transport()?;
        let config = profile(&realm, true, None, false)?;
        let primaries = transport
            .locator(&config)
            .locate(None, &realm, EndpointRole::PrimaryKdc, KdcProtocol::Auto)
            .await?;
        assert_eq!(primaries.len(), 1, "{primaries:?}");
        assert_eq!(
            primaries.first().map(|endpoint| endpoint.protocol),
            Some(KdcProtocol::Udp)
        );
        assert_eq!(
            primaries.first().map(|endpoint| endpoint.port),
            Some(kdc_port()?)
        );
        Ok::<_, Box<dyn Error>>(())
    })
}

/// The zone's `_kerberos` TXT record maps a host of the zone to its realm, only on request.
#[test]
fn the_txt_record_maps_a_host_to_the_realm_only_when_asked() -> Result<(), Box<dyn Error>> {
    if !harness::require(
        "the_txt_record_maps_a_host_to_the_realm_only_when_asked",
        &[DNS, MIT_KDC],
    )? {
        return Ok(());
    }
    runtime()?.block_on(async {
        let realm = harness::var("INTEROP_MIT_REALM")?;
        let transport = transport()?;
        let host = "svc.deep.test.rskrb5";
        let on = profile(&realm, false, None, true)?;
        let off = profile(&realm, false, None, false)?;
        let mapped = transport
            .host_realms(&on)
            .fallback_realm(None, host)
            .await?;
        let heuristic = transport
            .host_realms(&off)
            .fallback_realm(None, host)
            .await?;
        assert_eq!(
            mapped.as_deref(),
            Some(realm.as_str()),
            "the TXT record of the zone"
        );
        assert_eq!(
            heuristic.as_deref(),
            Some("DEEP.TEST.RSKRB5"),
            "the parent-domain heuristic"
        );
        Ok::<_, Box<dyn Error>>(())
    })
}

/// The zone's IPv6 record is served to the crate's resolver, and canonicalization over the
/// zone leaves a name that DNS knows unchanged.
#[test]
fn the_ipv6_record_of_the_zone_resolves() -> Result<(), Box<dyn Error>> {
    if !harness::require("the_ipv6_record_of_the_zone_resolves", &[DNS, MIT_KDC])? {
        return Ok(());
    }
    runtime()?.block_on(async {
        let server = harness::var("INTEROP_DNS_SERVER")?;
        let address: SocketAddr = server.parse()?;
        let mut udp = ConnectionConfig::udp();
        udp.port = address.port();
        let mut tcp = ConnectionConfig::tcp();
        tcp.port = address.port();
        let mut resolver_config = ResolverConfig::default();
        resolver_config.name_servers =
            vec![NameServerConfig::new(address.ip(), true, vec![udp, tcp])];
        let resolver = TokioResolver::builder_with_config(
            resolver_config,
            runtime::TokioRuntimeProvider::default(),
        )
        .build()?;
        let lookup = resolver.lookup_ip("kdc6.test.rskrb5.").await?;
        assert!(
            lookup
                .iter()
                .any(|ip| ip == IpAddr::from([0, 0, 0, 0, 0, 0, 0, 1])),
            "the zone's host view answers ::1 for kdc6"
        );
        let policy =
            CanonicalizationPolicy::from_config(&Config::parse("[libdefaults]\n rdns = false\n")?);
        let name = policy
            .expand(&transport()?, "KDC6.test.rskrb5.", true)
            .await?;
        assert_eq!(name, "kdc6.test.rskrb5");
        Ok::<_, Box<dyn Error>>(())
    })
}
