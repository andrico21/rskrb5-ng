//! Plan-1 discovery residuals (register rows FU-DSC-P01 to FU-DSC-P08), each pinned on
//! the route a caller reaches it by.

use hickory_resolver::proto::{op::ResponseCode, rr::RecordType};
use rskrb5_ng::{
    client::transport::{KdcEndpoint, KdcProtocol, Tokio},
    config::Config,
    error::Client as ClientError,
};

use crate::{
    TestError,
    fixture::{Dns, Reply, srv},
};

/// The realm every test discovers.
const REALM: &str = "TEST.GOKRB5";

/// A profile that enables SRV discovery and lists no server.
fn dns_config() -> Result<Config, TestError> {
    Ok(Config::parse("[libdefaults]\ndns_lookup_kdc = true\n")?)
}

/// A transport that asks `dns` for discovery.
fn via(dns: &Dns) -> Result<Tokio, TestError> {
    Ok(Tokio::new().with_dns_server(&dns.address().to_string())?)
}

/// FU-DSC-P01 (KDC path): a root target in a set that also holds a real record drops only
/// itself (MIT `locate_kdc.c:376-390` adds each record; the root entry never resolves).
#[tokio::test]
async fn kdc_set_with_a_root_target_keeps_the_real_records() -> Result<(), TestError> {
    // Given an SRV set with a root target and a usable literal target.
    let dns = Dns::start([(
        "_kerberos._tcp.test.gokrb5.",
        RecordType::SRV,
        Reply::Records(vec![srv(0, 88, ".")?, srv(1, 1088, "127.0.0.1.")?]),
    )])
    .await?;
    // When the KDCs are discovered.
    let endpoints = via(&dns)?
        .discover_kdcs(&dns_config()?, REALM, KdcProtocol::Tcp)
        .await?;
    // Then the real record is kept and the root one is not an endpoint.
    let authorities: Vec<String> = endpoints.iter().map(KdcEndpoint::authority).collect();
    assert_eq!(authorities, ["127.0.0.1:1088"]);
    Ok(())
}

/// FU-DSC-P01 (explicit kpasswd path): the same rule for `_kpasswd`.
#[tokio::test]
async fn kpasswd_set_with_a_root_target_keeps_the_real_records() -> Result<(), TestError> {
    // Given an explicit-protocol `_kpasswd` set with a root target and a usable literal target.
    let dns = Dns::start([(
        "_kpasswd._tcp.test.gokrb5.",
        RecordType::SRV,
        Reply::Records(vec![srv(0, 464, ".")?, srv(1, 1464, "127.0.0.1.")?]),
    )])
    .await?;
    // When the servers are discovered.
    let endpoints = via(&dns)?
        .discover_kpasswd_servers(&dns_config()?, REALM, KdcProtocol::Tcp)
        .await?;
    // Then the real record is kept.
    let authorities: Vec<String> = endpoints.iter().map(KdcEndpoint::authority).collect();
    assert_eq!(authorities, ["127.0.0.1:1464"]);
    Ok(())
}

/// A root target alone stays "service unavailable" (A8), on both paths.
#[tokio::test]
async fn a_lone_root_target_stays_service_unavailable() -> Result<(), TestError> {
    // Given sets whose only record is a root target.
    let dns = Dns::start([
        (
            "_kerberos._tcp.test.gokrb5.",
            RecordType::SRV,
            Reply::Records(vec![srv(0, 88, ".")?]),
        ),
        (
            "_kpasswd._tcp.test.gokrb5.",
            RecordType::SRV,
            Reply::Records(vec![srv(0, 464, ".")?]),
        ),
    ])
    .await?;
    let transport = via(&dns)?;
    let config = dns_config()?;
    // When either service is discovered, then it is reported unavailable.
    let kdc = transport
        .discover_kdcs(&config, REALM, KdcProtocol::Tcp)
        .await;
    let password = transport
        .discover_kpasswd_servers(&config, REALM, KdcProtocol::Tcp)
        .await;
    assert!(matches!(
        kdc,
        Err(ClientError::DnsServiceUnavailable {
            service: _,
            realm: _
        })
    ));
    assert!(matches!(
        password,
        Err(ClientError::DnsServiceUnavailable {
            service: _,
            realm: _
        })
    ));
    Ok(())
}

/// FU-DSC-P02: an unresolvable published KDC target gives the endpoint-failure shape of
/// kpasswd (MIT `sendto_kdc.c:758-786` skips it, `:1603` is `KRB5_KDC_UNREACH`).
#[tokio::test]
async fn kdc_target_that_does_not_resolve_is_an_endpoint_failure() -> Result<(), TestError> {
    // Given a published set whose only target does not exist.
    let dns = Dns::start([(
        "_kerberos._tcp.test.gokrb5.",
        RecordType::SRV,
        Reply::Records(vec![srv(0, 88, "missing.test.gokrb5.")?]),
    )])
    .await?;
    // When the KDCs are discovered with the explicit resolver.
    let result = via(&dns)?
        .discover_kdcs(&dns_config()?, REALM, KdcProtocol::Tcp)
        .await;
    // Then the failure is the one kpasswd reports.
    assert!(
        matches!(&result, Err(ClientError::KdcEndpointFailures { realm, protocol: KdcProtocol::Tcp, failures })
            if realm == REALM && failures.len() == 1),
        "{result:?}"
    );
    Ok(())
}

/// FU-DSC-P03: a target lookup that fails for another reason than "no such name or address"
/// aborts discovery (MIT `sendto_kdc.c:764-766,1542-1545`), with one error prefix.
#[tokio::test]
async fn a_target_servfail_aborts_discovery_with_a_single_prefix() -> Result<(), TestError> {
    // Given a set whose first target lookup answers SERVFAIL and whose second is usable.
    let dns = Dns::start([
        (
            "_kerberos._tcp.test.gokrb5.",
            RecordType::SRV,
            Reply::Records(vec![
                srv(0, 88, "broken.test.gokrb5.")?,
                srv(1, 88, "127.0.0.1.")?,
            ]),
        ),
        (
            "broken.test.gokrb5.",
            RecordType::A,
            Reply::Code(ResponseCode::ServFail),
        ),
        (
            "broken.test.gokrb5.",
            RecordType::AAAA,
            Reply::Code(ResponseCode::ServFail),
        ),
    ])
    .await?;
    // When the KDCs are discovered.
    let result = via(&dns)?
        .discover_kdcs(&dns_config()?, REALM, KdcProtocol::Tcp)
        .await;
    // Then the lookup is aborted, and the error does not repeat its own prefix.
    assert!(
        matches!(&result, Err(ClientError::DnsSrvLookup { realm: _, protocol: _, message })
            if message.contains("broken.test.gokrb5") && !message.contains("DNS SRV lookup failed")),
        "{result:?}"
    );
    Ok(())
}

/// FU-DSC-P03: a target with no address data is skipped like an unknown name.
#[tokio::test]
async fn a_target_without_address_data_is_skipped() -> Result<(), TestError> {
    // Given a first target that exists without addresses and a usable second one.
    let dns = Dns::start([
        (
            "_kerberos._tcp.test.gokrb5.",
            RecordType::SRV,
            Reply::Records(vec![
                srv(0, 88, "empty.test.gokrb5.")?,
                srv(1, 1088, "127.0.0.1.")?,
            ]),
        ),
        ("empty.test.gokrb5.", RecordType::A, Reply::NoData),
        ("empty.test.gokrb5.", RecordType::AAAA, Reply::NoData),
    ])
    .await?;
    // When the KDCs are discovered, then the usable target remains.
    let endpoints = via(&dns)?
        .discover_kdcs(&dns_config()?, REALM, KdcProtocol::Tcp)
        .await?;
    let authorities: Vec<String> = endpoints.iter().map(KdcEndpoint::authority).collect();
    assert_eq!(authorities, ["127.0.0.1:1088"]);
    Ok(())
}

/// FU-DSC-P04 (explicit protocol): an SRV answer that is neither NXDOMAIN nor an empty
/// NOERROR is an error, never an absent set that opens the `_kerberos-adm` fallback.
#[tokio::test]
async fn a_servfail_for_kpasswd_does_not_fall_back_to_the_admin_service() -> Result<(), TestError> {
    // Given SERVFAIL for `_kpasswd._tcp` and a usable administrative record.
    let dns = Dns::start([
        (
            "_kpasswd._tcp.test.gokrb5.",
            RecordType::SRV,
            Reply::Code(ResponseCode::ServFail),
        ),
        (
            "_kerberos-adm._tcp.test.gokrb5.",
            RecordType::SRV,
            Reply::Records(vec![srv(0, 749, "127.0.0.1.")?]),
        ),
    ])
    .await?;
    // When the servers are discovered, then the failure is reported.
    let result = via(&dns)?
        .discover_kpasswd_servers(&dns_config()?, REALM, KdcProtocol::Tcp)
        .await;
    assert!(
        matches!(
            &result,
            Err(ClientError::DnsSrvLookup {
                realm: _,
                protocol: KdcProtocol::Tcp,
                message: _
            })
        ),
        "{result:?}"
    );
    assert!(
        !dns.questions()?
            .iter()
            .any(|question| question.contains("_kerberos-adm")),
        "the administrative service was asked"
    );
    Ok(())
}

/// FU-DSC-P04 (Auto): the same, and an empty NOERROR set still means absent.
#[tokio::test]
async fn auto_kpasswd_discovery_propagates_an_srv_error_but_not_an_empty_answer()
-> Result<(), TestError> {
    // Given SERVFAIL for the UDP set, an empty TCP set and a usable administrative record.
    let admin = (
        "_kerberos-adm._tcp.test.gokrb5.",
        RecordType::SRV,
        Reply::Records(vec![srv(0, 749, "127.0.0.1.")?]),
    );
    let failing = Dns::start([
        (
            "_kpasswd._udp.test.gokrb5.",
            RecordType::SRV,
            Reply::Code(ResponseCode::ServFail),
        ),
        ("_kpasswd._tcp.test.gokrb5.", RecordType::SRV, Reply::NoData),
        admin,
    ])
    .await?;
    let config = dns_config()?;
    // When the request runs, then the discovery error is reported before anything is sent.
    let result = via(&failing)?
        .send_to_kpasswd_realm(&config, KdcProtocol::Auto, REALM, b"request")
        .await;
    assert!(
        matches!(
            &result,
            Err(ClientError::DnsSrvLookup {
                realm: _,
                protocol: _,
                message: _
            })
        ),
        "{result:?}"
    );
    // And with both sets merely empty the administrative fallback is used by discovery.
    let empty = Dns::start([
        ("_kpasswd._udp.test.gokrb5.", RecordType::SRV, Reply::NoData),
        ("_kpasswd._tcp.test.gokrb5.", RecordType::SRV, Reply::NoData),
        (
            "_kerberos-adm._tcp.test.gokrb5.",
            RecordType::SRV,
            Reply::Records(vec![srv(0, 749, "127.0.0.1.")?]),
        ),
    ])
    .await?;
    let endpoints = via(&empty)?
        .discover_kpasswd_servers(&config, REALM, KdcProtocol::Auto)
        .await?;
    assert_eq!(endpoints.len(), 1, "{endpoints:?}");
    Ok(())
}

/// FU-DSC-P05: a failed administrative lookup names the `_tcp` label it queried.
///
/// That is what `DnsSrvLookup::protocol` defines; the A8 test
/// `kpasswd_auto_failing_admin_lookup_is_reported` pins the same for `Auto`.
#[tokio::test]
async fn a_failed_admin_lookup_names_the_label_it_queried() -> Result<(), TestError> {
    // Given an absent `_kpasswd._udp` set and an administrative lookup that fails.
    let dns = Dns::start([
        ("_kpasswd._udp.test.gokrb5.", RecordType::SRV, Reply::NoData),
        (
            "_kerberos-adm._tcp.test.gokrb5.",
            RecordType::SRV,
            Reply::Code(ResponseCode::ServFail),
        ),
    ])
    .await?;
    // When UDP servers are discovered.
    let result = via(&dns)?
        .discover_kpasswd_servers(&dns_config()?, REALM, KdcProtocol::Udp)
        .await;
    // Then the error names the label the failed query used.
    assert!(
        matches!(
            &result,
            Err(ClientError::DnsSrvLookup {
                realm: _,
                protocol: KdcProtocol::Tcp,
                message: _
            })
        ),
        "{result:?}"
    );
    Ok(())
}

/// FU-DSC-P05: unresolvable administrative targets fail as endpoints of the requested protocol.
#[tokio::test]
async fn unresolvable_admin_targets_fail_as_endpoints_of_the_requested_protocol()
-> Result<(), TestError> {
    // Given an administrative record whose target does not exist.
    let dns = Dns::start([
        ("_kpasswd._udp.test.gokrb5.", RecordType::SRV, Reply::NoData),
        (
            "_kerberos-adm._tcp.test.gokrb5.",
            RecordType::SRV,
            Reply::Records(vec![srv(0, 749, "missing.test.gokrb5.")?]),
        ),
    ])
    .await?;
    // When UDP servers are discovered.
    let result = via(&dns)?
        .discover_kpasswd_servers(&dns_config()?, REALM, KdcProtocol::Udp)
        .await;
    // Then the failure names the requested protocol.
    assert!(
        matches!(
            &result,
            Err(ClientError::KdcEndpointFailures {
                realm: _,
                protocol: KdcProtocol::Udp,
                failures: _
            })
        ),
        "{result:?}"
    );
    Ok(())
}
/// FU-DSC-P06: a zone id on a DNS server literal is refused, not dropped.
#[test]
fn a_dns_server_zone_id_is_refused() {
    for value in [
        "[fe80::1%2]:5353",
        "[fe80::1%0]:53",
        "[fe80::1%4294967295]:53",
    ] {
        assert!(
            matches!(
                Tokio::new().with_dns_server(value),
                Err(ClientError::DnsResolverConfig(_))
            ),
            "{value}"
        );
    }
}

/// FU-DSC-P07: one port rule, digits only, for configured endpoints and DNS servers.
#[test]
fn endpoint_and_dns_server_literals_share_one_port_rule() {
    for value in [
        "[a]:+88",
        "[a]:",
        "a:+88",
        "[::1]:+88",
        "[a]: 88",
        "[a]:88x",
    ] {
        assert!(
            matches!(
                KdcEndpoint::configured(KdcProtocol::Tcp, value),
                Err(ClientError::InvalidKdcEndpoint(_))
            ),
            "{value}"
        );
    }
    for value in ["[::1]:+53", "127.0.0.1:+53"] {
        assert!(
            matches!(
                Tokio::new().with_dns_server(value),
                Err(ClientError::DnsResolverConfig(_))
            ),
            "{value}"
        );
    }
}

/// FU-DSC-P07: a bracket inside a bracketed host is refused, so `authority()` cannot
/// produce an unterminated bracket.
#[test]
fn a_nested_bracket_is_refused() -> Result<(), TestError> {
    for value in ["[[a:b]", "[a[b]:88", "[a]b]"] {
        assert!(
            matches!(
                KdcEndpoint::configured(KdcProtocol::Tcp, value),
                Err(ClientError::InvalidKdcEndpoint(_))
            ),
            "{value}"
        );
    }
    // The accepted shapes keep their authority.
    for (value, authority) in [
        ("[fd00::1]:88", "[fd00::1]:88"),
        ("[fd00::1]", "[fd00::1]:88"),
        ("fd00::1", "[fd00::1]:88"),
        ("kdc.example:1088", "kdc.example:1088"),
    ] {
        assert_eq!(
            KdcEndpoint::configured(KdcProtocol::Tcp, value)?.authority(),
            authority
        );
    }
    Ok(())
}
