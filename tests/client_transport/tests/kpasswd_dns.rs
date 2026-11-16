//! Password change discovery through DNS: one MIT-shaped list for `KdcProtocol::Auto`.

use hickory_resolver::proto::op::ResponseCode;
use tokio::{
    sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel},
    task::JoinHandle,
};

use super::{
    kpasswd_order::{REQUEST, assert_no_datagram, closed_port, describe, shown, udp_responder},
    *,
};

/// Realm of every exchange in this module.
const REALM: &str = "TEST.GOKRB5";

/// SRV answers of one fixture name: `(port, target)`, the first with the best priority; the target `.` is the root name.
type Records = Vec<(u16, &'static str)>;

/// A fake DNS server and the questions it was asked, in order.
struct Dns {
    /// Address of the fixture, for `with_dns_server`.
    server: String,
    /// The serving task.
    task: JoinHandle<Result<(), TestError>>,
    /// Every question received, as `<type> <lower-case name>`.
    questions: UnboundedReceiver<String>,
}

impl Dns {
    /// Serve `zone`; every SRV name outside it is NXDOMAIN, every empty entry is NOERROR without answers.
    async fn start(zone: Vec<(&'static str, Records)>) -> Result<Self, TestError> {
        let socket = bind_udp_loopback().await?;
        let server = socket.local_addr()?.to_string();
        let (sender, questions) = unbounded_channel();
        let task = tokio::spawn(serve(socket, zone, sender));
        Ok(Self {
            server,
            task,
            questions,
        })
    }

    /// Transport that resolves through this fixture, with a deadline short for unanswered datagrams.
    fn transport(&self) -> Result<Tokio, TestError> {
        Ok(Tokio::new()
            .with_timeout(Duration::from_millis(300))
            .with_dns_server(&self.server)?)
    }

    /// Stop the fixture and return the questions it saw.
    async fn finish(mut self) -> Result<Vec<String>, TestError> {
        stop(self.task).await?;
        let mut seen = Vec::new();
        while let Ok(question) = self.questions.try_recv() {
            seen.push(question);
        }
        Ok(seen)
    }
}

/// Answer SRV questions from `zone` and log each question.
async fn serve(
    socket: UdpSocket,
    zone: Vec<(&'static str, Records)>,
    questions: UnboundedSender<String>,
) -> Result<(), TestError> {
    loop {
        let mut buffer = [0; 4096];
        let (length, peer) = bounded(
            Duration::from_secs(10),
            "DNS question",
            socket.recv_from(&mut buffer),
        )
        .await??;
        let request = Message::from_vec(buffer.get(..length).ok_or("DNS length")?)?;
        let query = request.queries.first().ok_or("DNS question")?;
        let name = query.name().to_utf8().to_ascii_lowercase();
        questions.send(format!("{} {name}", query.query_type()))?;
        let mut response = Message::response(request.metadata.id, request.metadata.op_code);
        response.metadata.authoritative = true;
        response.queries = request.queries.clone();
        match zone.iter().find(|(owner, _)| *owner == name) {
            Some((_, records)) if query.query_type() == RecordType::SRV => {
                for (priority, (port, host)) in (0_u16..).zip(records) {
                    let target = if *host == "." {
                        Name::root()
                    } else {
                        Name::from_ascii(host)?
                    };
                    response.answers.push(Record::from_rdata(
                        query.name().clone(),
                        60,
                        RData::SRV(SRV::new(priority, 0, *port, target)),
                    ));
                }
            }
            Some(_) | None => response.metadata.response_code = ResponseCode::NXDomain,
        }
        let _: usize = socket.send_to(&response.to_vec()?, peer).await?;
    }
}

/// Configuration that turns DNS discovery on and lists no server.
fn dns_config() -> Result<Config, TestError> {
    Ok(Config::parse("[libdefaults]\ndns_lookup_kdc = true\n")?)
}

/// A loopback port that is closed for TCP and UDP.
async fn closed_port_number() -> Result<u16, TestError> {
    Ok(closed_port().await?.parse::<SocketAddr>()?.port())
}

/// How often `fragment` occurs among the questions.
fn asked(questions: &[String], fragment: &str) -> usize {
    questions
        .iter()
        .filter(|question| question.contains(fragment))
        .count()
}

/// Assert that no connection reaches `listener` shortly after the exchange completed.
async fn assert_no_connection(listener: &TcpListener, what: &str) {
    assert!(
        timeout(Duration::from_millis(50), listener.accept())
            .await
            .is_err(),
        "{what}: a connection reached the TCP port"
    );
}

/// With only `_kpasswd._udp` published, `_kerberos-adm` is never asked and UDP gets one datagram.
#[test]
fn kpasswd_auto_udp_only_zone_never_asks_admin() -> Result<(), TestError> {
    runtime()?.block_on(async {
        // Given a zone that publishes `_kpasswd._udp` and `_kerberos-adm._tcp` (MIT's documented layout).
        let (listener, udp) = bind_tcp_and_udp_pair().await?;
        let port = udp.local_addr()?.port();
        let dns = Dns::start(vec![
            ("_kpasswd._udp.test.gokrb5.", vec![(port, "127.0.0.1.")]),
            ("_kerberos-adm._tcp.test.gokrb5.", vec![(749, "127.0.0.1.")]),
        ])
        .await?;
        let responder = udp_responder(udp, b"udp-reply");
        // When the Auto request runs.
        let result = dns
            .transport()?
            .send_to_kpasswd_realm(&dns_config()?, KdcProtocol::Auto, REALM, REQUEST)
            .await;
        let questions = dns.finish().await?;
        // Then the administration service was never asked about.
        assert_eq!(
            asked(&questions, "_kerberos-adm"),
            0,
            "questions: {questions:?}"
        );
        // And one datagram reached the UDP entry, which was never contacted over TCP.
        assert_eq!(shown(result)?, b"udp-reply");
        let (peer, length) =
            bounded(Duration::from_secs(10), "UDP responder", responder).await???;
        assert_eq!(length, REQUEST.len());
        assert_no_datagram(&peer, "retransmit").await;
        assert_no_connection(&listener, "UDP-only entry").await;
        Ok(())
    })
}

/// A root target contributes no endpoint: the other record set answers and `_kerberos-adm` is never asked about.
#[test]
fn kpasswd_auto_root_target_leaves_the_other_set_in_use() -> Result<(), TestError> {
    runtime()?.block_on(async {
        for root_in_tcp in [true, false] {
            // Given one record set answering the root name and the other a live endpoint.
            let (listener, udp) = bind_tcp_and_udp_pair().await?;
            let port = udp.local_addr()?.port();
            let live = vec![(port, "127.0.0.1.")];
            let root = vec![(0, ".")];
            let (udp_records, tcp_records) = if root_in_tcp {
                (live, root)
            } else {
                (root, live)
            };
            let dns = Dns::start(vec![
                ("_kpasswd._udp.test.gokrb5.", udp_records),
                ("_kpasswd._tcp.test.gokrb5.", tcp_records),
                ("_kerberos-adm._tcp.test.gokrb5.", vec![(749, "127.0.0.1.")]),
            ])
            .await?;
            let (udp_answer, tcp_answer) = if root_in_tcp {
                (Some(udp_responder(udp, b"udp-reply")), None)
            } else {
                let server = tokio::spawn(async move {
                    let (request, mut socket) = read_tcp_request(&listener).await?;
                    write_tcp_response(&mut socket, b"tcp-reply").await?;
                    Ok::<_, io::Error>(request)
                });
                (None, Some(server))
            };
            // When the Auto request runs.
            let result = dns
                .transport()?
                .send_to_kpasswd_realm(&dns_config()?, KdcProtocol::Auto, REALM, REQUEST)
                .await;
            let questions = dns.finish().await?;
            // Then both record sets were asked about and the administration service was not.
            assert_eq!(
                asked(&questions, "_kpasswd._udp"),
                1,
                "root in tcp: {root_in_tcp}: {questions:?}"
            );
            assert_eq!(
                asked(&questions, "_kpasswd._tcp"),
                1,
                "root in tcp: {root_in_tcp}: {questions:?}"
            );
            assert_eq!(
                asked(&questions, "_kerberos-adm"),
                0,
                "root in tcp: {root_in_tcp}: {questions:?}"
            );
            // And the live set answered.
            let reply = shown(result)?;
            if let Some(responder) = udp_answer {
                assert_eq!(reply, b"udp-reply");
                let (peer, length) =
                    bounded(Duration::from_secs(10), "UDP responder", responder).await???;
                assert_eq!(length, REQUEST.len());
                assert_no_datagram(&peer, "retransmit").await;
            }
            if let Some(server) = tcp_answer {
                assert_eq!(reply, b"tcp-reply");
                assert_eq!(
                    bounded(Duration::from_secs(10), "TCP peer", server).await???,
                    REQUEST
                );
            }
        }
        Ok(())
    })
}

/// A root target among real records of one set is skipped and the real records are used.
#[test]
fn kpasswd_auto_root_target_among_real_records_is_skipped() -> Result<(), TestError> {
    runtime()?.block_on(async {
        // Given a `_kpasswd._tcp` set holding a root record and a live endpoint, and a published administration host.
        let (listener, udp) = bind_tcp_and_udp_pair().await?;
        let dns = Dns::start(vec![
            (
                "_kpasswd._tcp.test.gokrb5.",
                vec![(0, "."), (listener.local_addr()?.port(), "127.0.0.1.")],
            ),
            ("_kerberos-adm._tcp.test.gokrb5.", vec![(749, "127.0.0.1.")]),
        ])
        .await?;
        let server = tokio::spawn(async move {
            let (request, mut socket) = read_tcp_request(&listener).await?;
            write_tcp_response(&mut socket, b"tcp-reply").await?;
            Ok::<_, io::Error>(request)
        });
        // When the Auto request runs.
        let result = dns
            .transport()?
            .send_to_kpasswd_realm(&dns_config()?, KdcProtocol::Auto, REALM, REQUEST)
            .await;
        let questions = dns.finish().await?;
        // Then the live TCP record answered and the administration service was never asked about.
        assert_eq!(shown(result)?, b"tcp-reply");
        assert_eq!(
            bounded(Duration::from_secs(10), "TCP peer", server).await???,
            REQUEST
        );
        assert_eq!(
            asked(&questions, "_kerberos-adm"),
            0,
            "questions: {questions:?}"
        );
        assert_no_datagram(&udp, "UDP entry").await;
        Ok(())
    })
}

/// Root targets only, in both sets: discovery fails before any I/O and `_kerberos-adm` is never asked about.
#[test]
fn kpasswd_auto_root_targets_only_are_unavailable() -> Result<(), TestError> {
    runtime()?.block_on(async {
        // Given both record sets answering only the root name, and a published administration host.
        let (listener, udp) = bind_tcp_and_udp_pair().await?;
        let dns = Dns::start(vec![
            ("_kpasswd._udp.test.gokrb5.", vec![(0, ".")]),
            ("_kpasswd._tcp.test.gokrb5.", vec![(0, ".")]),
            ("_kerberos-adm._tcp.test.gokrb5.", vec![(749, "127.0.0.1.")]),
        ])
        .await?;
        // When the Auto request runs.
        let result = dns
            .transport()?
            .send_to_kpasswd_realm(&dns_config()?, KdcProtocol::Auto, REALM, REQUEST)
            .await;
        let questions = dns.finish().await?;
        // Then both record sets were asked about and the call fails with the discovery error.
        assert_eq!(asked(&questions, "_kpasswd._udp"), 1, "{questions:?}");
        assert_eq!(asked(&questions, "_kpasswd._tcp"), 1, "{questions:?}");
        assert!(
            matches!(&result, Err(ClientError::DnsServiceUnavailable { service, realm })
                if service == "_kpasswd" && realm == REALM),
            "expected DnsServiceUnavailable, got {}",
            describe(&result)
        );
        // And the administration service was never asked about and nothing was sent.
        assert_eq!(
            asked(&questions, "_kerberos-adm"),
            0,
            "questions: {questions:?}"
        );
        assert_no_datagram(&udp, "root targets only").await;
        assert_no_connection(&listener, "root targets only").await;
        Ok(())
    })
}

/// A published `_kpasswd` record whose target does not resolve is a definite failure, not an absent service.
#[test]
fn kpasswd_auto_unresolvable_published_target_asks_no_admin() -> Result<(), TestError> {
    runtime()?.block_on(async {
        // Given a `_kpasswd._udp` record naming a host the DNS server cannot resolve, and a published administration host.
        let dns = Dns::start(vec![
            (
                "_kpasswd._udp.test.gokrb5.",
                vec![(464, "unresolvable.test.gokrb5.")],
            ),
            ("_kerberos-adm._tcp.test.gokrb5.", vec![(749, "127.0.0.1.")]),
        ])
        .await?;
        // When the Auto request runs.
        let result = dns
            .transport()?
            .send_to_kpasswd_realm(&dns_config()?, KdcProtocol::Auto, REALM, REQUEST)
            .await;
        let questions = dns.finish().await?;
        // Then the administration service was never asked about.
        assert_eq!(
            asked(&questions, "_kerberos-adm"),
            0,
            "questions: {questions:?}"
        );
        // And the call failed definitely as an endpoint failure, naming the target that did not resolve.
        assert!(
            matches!(&result, Err(ClientError::KdcEndpointFailures { realm: _, protocol: KdcProtocol::Auto, failures })
                if matches!(failures.as_slice(), [only] if only.contains("unresolvable.test.gokrb5"))),
            "expected the Auto KdcEndpointFailures of the unresolvable target, got {}",
            describe(&result)
        );
        Ok(())
    })
}

/// A set whose target does not resolve does not hide the live endpoints of the other set.
#[test]
fn kpasswd_auto_unresolvable_set_leaves_the_live_set_in_use() -> Result<(), TestError> {
    runtime()?.block_on(async {
        // Given an unresolvable target in `_kpasswd._udp`, a live endpoint in `_kpasswd._tcp` and an administration host.
        let (listener, udp) = bind_tcp_and_udp_pair().await?;
        let port = udp.local_addr()?.port();
        let dns = Dns::start(vec![
            (
                "_kpasswd._udp.test.gokrb5.",
                vec![(464, "unresolvable.test.gokrb5.")],
            ),
            ("_kpasswd._tcp.test.gokrb5.", vec![(port, "127.0.0.1.")]),
            ("_kerberos-adm._tcp.test.gokrb5.", vec![(749, "127.0.0.1.")]),
        ])
        .await?;
        let server = tokio::spawn(async move {
            let (request, mut socket) = read_tcp_request(&listener).await?;
            write_tcp_response(&mut socket, b"tcp-reply").await?;
            Ok::<_, io::Error>(request)
        });
        // When the Auto request runs.
        let result = dns
            .transport()?
            .send_to_kpasswd_realm(&dns_config()?, KdcProtocol::Auto, REALM, REQUEST)
            .await;
        let questions = dns.finish().await?;
        // Then the live TCP endpoint answered and the administration service was never asked about.
        assert_eq!(shown(result)?, b"tcp-reply");
        assert_eq!(
            bounded(Duration::from_secs(10), "TCP peer", server).await???,
            REQUEST
        );
        assert_eq!(
            asked(&questions, "_kerberos-adm"),
            0,
            "questions: {questions:?}"
        );
        assert_no_datagram(&udp, "unresolvable set").await;
        Ok(())
    })
}

/// With both sets unresolvable the failure of every set is reported, the UDP set first.
#[test]
fn kpasswd_auto_reports_every_unresolvable_set() -> Result<(), TestError> {
    runtime()?.block_on(async {
        // Given an unresolvable target in each record set.
        let dns = Dns::start(vec![
            (
                "_kpasswd._udp.test.gokrb5.",
                vec![(464, "udp-missing.test.gokrb5.")],
            ),
            (
                "_kpasswd._tcp.test.gokrb5.",
                vec![(464, "tcp-missing.test.gokrb5.")],
            ),
        ])
        .await?;
        // When the Auto request runs.
        let result = dns
            .transport()?
            .send_to_kpasswd_realm(&dns_config()?, KdcProtocol::Auto, REALM, REQUEST)
            .await;
        let _questions = dns.finish().await?;
        // Then the endpoint failures name the UDP set's target and then the TCP set's target.
        assert!(
            matches!(&result, Err(ClientError::KdcEndpointFailures { realm: _, protocol: KdcProtocol::Auto, failures })
                if matches!(failures.as_slice(), [udp, tcp]
                    if udp.contains("udp-missing.test.gokrb5") && tcp.contains("tcp-missing.test.gokrb5"))),
            "expected the Auto KdcEndpointFailures of both sets, UDP first, got {}",
            describe(&result)
        );
        Ok(())
    })
}

/// A published `_kpasswd` set of the requested protocol whose target does not resolve is a definite failure.
async fn explicit_unresolvable_published_target_asks_no_admin(
    protocol: KdcProtocol,
    set: &'static str,
) -> Result<(), TestError> {
    // Given a `_kpasswd` set of that protocol naming a host the DNS server cannot resolve, and a published administration host.
    let dns = Dns::start(vec![
        (set, vec![(464, "unresolvable.test.gokrb5.")]),
        ("_kerberos-adm._tcp.test.gokrb5.", vec![(749, "127.0.0.1.")]),
    ])
    .await?;
    // When the explicit request runs.
    let result = dns
        .transport()?
        .send_to_kpasswd_realm(&dns_config()?, protocol, REALM, REQUEST)
        .await;
    let questions = dns.finish().await?;
    // Then the administration service was never asked about.
    assert_eq!(
        asked(&questions, "_kerberos-adm"),
        0,
        "questions: {questions:?}"
    );
    // And the call failed definitely as an endpoint failure of that protocol naming the target.
    assert!(
        matches!(&result, Err(ClientError::KdcEndpointFailures { realm: _, protocol: reported, failures })
            if *reported == protocol
                && matches!(failures.as_slice(), [only] if only.contains("unresolvable.test.gokrb5"))),
        "expected the {protocol:?} KdcEndpointFailures of the unresolvable target, got {}",
        describe(&result)
    );
    Ok(())
}

/// The explicit TCP request does not fall back to `_kerberos-adm` when its `_kpasswd._tcp` target does not resolve.
#[test]
fn kpasswd_explicit_tcp_unresolvable_published_target_asks_no_admin() -> Result<(), TestError> {
    runtime()?.block_on(explicit_unresolvable_published_target_asks_no_admin(
        KdcProtocol::Tcp,
        "_kpasswd._tcp.test.gokrb5.",
    ))
}

/// The explicit UDP request does not fall back to `_kerberos-adm` when its `_kpasswd._udp` target does not resolve.
#[test]
fn kpasswd_explicit_udp_unresolvable_published_target_asks_no_admin() -> Result<(), TestError> {
    runtime()?.block_on(explicit_unresolvable_published_target_asks_no_admin(
        KdcProtocol::Udp,
        "_kpasswd._udp.test.gokrb5.",
    ))
}

/// A failed administration lookup is the error of the call, not an empty host list.
#[test]
fn kpasswd_auto_failing_admin_lookup_is_reported() -> Result<(), TestError> {
    runtime()?.block_on(async {
        // Given a zone that publishes neither `_kpasswd` set nor `_kerberos-adm`.
        let dns = Dns::start(Vec::new()).await?;
        // When the Auto request runs.
        let result = dns
            .transport()?
            .send_to_kpasswd_realm(&dns_config()?, KdcProtocol::Auto, REALM, REQUEST)
            .await;
        let questions = dns.finish().await?;
        // Then the administration service was asked about once and its lookup failure is the error.
        assert_eq!(
            asked(&questions, "_kerberos-adm._tcp"),
            1,
            "questions: {questions:?}"
        );
        assert!(
            matches!(
                &result,
                Err(ClientError::DnsSrvLookup {
                    realm: _,
                    protocol: KdcProtocol::Tcp,
                    message: _
                })
            ),
            "expected the DnsSrvLookup of the administration lookup, got {}",
            describe(&result)
        );
        Ok(())
    })
}

/// Only `_kpasswd._tcp` published and refused: no UDP pass, no administration lookup.
#[test]
fn kpasswd_auto_tcp_only_zone_failing_asks_no_admin() -> Result<(), TestError> {
    runtime()?.block_on(async {
        // Given a TCP entry whose port is closed and a published administration service.
        let port = closed_port_number().await?;
        let dns = Dns::start(vec![
            ("_kpasswd._tcp.test.gokrb5.", vec![(port, "127.0.0.1.")]),
            ("_kerberos-adm._tcp.test.gokrb5.", vec![(749, "127.0.0.1.")]),
        ])
        .await?;
        // When the Auto request runs.
        let result = dns
            .transport()?
            .send_to_kpasswd_realm(&dns_config()?, KdcProtocol::Auto, REALM, REQUEST)
            .await;
        let questions = dns.finish().await?;
        // Then the call fails definitely and the administration service was never asked about.
        assert_eq!(
            asked(&questions, "_kerberos-adm"),
            0,
            "questions: {questions:?}"
        );
        assert!(
            matches!(
                &result,
                Err(ClientError::KdcEndpointFailures {
                    realm: _,
                    protocol: KdcProtocol::Tcp,
                    failures: _
                })
            ),
            "expected the TCP KdcEndpointFailures, got {}",
            describe(&result)
        );
        Ok(())
    })
}

/// With both record sets published, discovery runs once and the TCP pass answers first.
#[test]
fn kpasswd_auto_both_record_sets_discovered_once_tcp_first() -> Result<(), TestError> {
    runtime()?.block_on(async {
        // Given a live UDP entry and a live TCP entry on different hosts of one zone.
        let (udp_listener, udp) = bind_tcp_and_udp_pair().await?;
        let (tcp_listener, tcp_udp) = bind_tcp_and_udp_pair().await?;
        let dns = Dns::start(vec![
            (
                "_kpasswd._udp.test.gokrb5.",
                vec![(udp.local_addr()?.port(), "127.0.0.1.")],
            ),
            (
                "_kpasswd._tcp.test.gokrb5.",
                vec![(tcp_listener.local_addr()?.port(), "127.0.0.1.")],
            ),
        ])
        .await?;
        let server = tokio::spawn(async move {
            let (request, mut socket) = read_tcp_request(&tcp_listener).await?;
            write_tcp_response(&mut socket, b"tcp-reply").await?;
            Ok::<_, io::Error>(request)
        });
        // When the Auto request runs.
        let result = dns
            .transport()?
            .send_to_kpasswd_realm(&dns_config()?, KdcProtocol::Auto, REALM, REQUEST)
            .await;
        let questions = dns.finish().await?;
        // Then each record set was asked about exactly once.
        assert_eq!(asked(&questions, "_kpasswd._udp"), 1, "{questions:?}");
        assert_eq!(asked(&questions, "_kpasswd._tcp"), 1, "{questions:?}");
        // And the TCP entry answered while no datagram was sent anywhere.
        assert_eq!(shown(result)?, b"tcp-reply");
        assert_eq!(
            bounded(Duration::from_secs(10), "TCP peer", server).await???,
            REQUEST
        );
        assert_no_datagram(&udp, "UDP entry").await;
        assert_no_datagram(&tcp_udp, "TCP entry").await;
        assert_no_connection(&udp_listener, "UDP entry").await;
        Ok(())
    })
}

/// After a definite TCP failure the UDP entries get one datagram each, from the same discovery.
#[test]
fn kpasswd_auto_udp_pass_follows_a_refused_tcp_pass() -> Result<(), TestError> {
    runtime()?.block_on(async {
        // Given a refused TCP entry and a live UDP entry.
        let tcp_port = closed_port_number().await?;
        let udp = bind_udp_with_closed_tcp().await?;
        let dns = Dns::start(vec![
            ("_kpasswd._tcp.test.gokrb5.", vec![(tcp_port, "127.0.0.1.")]),
            (
                "_kpasswd._udp.test.gokrb5.",
                vec![(udp.local_addr()?.port(), "127.0.0.1.")],
            ),
        ])
        .await?;
        let responder = udp_responder(udp, b"udp-reply");
        // When the Auto request runs.
        let result = dns
            .transport()?
            .send_to_kpasswd_realm(&dns_config()?, KdcProtocol::Auto, REALM, REQUEST)
            .await;
        let questions = dns.finish().await?;
        // Then UDP answers after a single datagram and each record set was asked about once.
        assert_eq!(asked(&questions, "_kpasswd._udp"), 1, "{questions:?}");
        assert_eq!(asked(&questions, "_kpasswd._tcp"), 1, "{questions:?}");
        assert_eq!(shown(result)?, b"udp-reply");
        let (peer, length) =
            bounded(Duration::from_secs(10), "UDP responder", responder).await???;
        assert_eq!(length, REQUEST.len());
        assert_no_datagram(&peer, "retransmit").await;
        Ok(())
    })
}

/// An empty `_kpasswd` list, by failure or by no records, asks for the administration service once.
#[test]
fn kpasswd_auto_empty_list_asks_admin_once_for_both_passes() -> Result<(), TestError> {
    runtime()?.block_on(async {
        for published_empty in [false, true] {
            // Given no usable `_kpasswd` record set and an administration host.
            let mut zone = vec![("_kerberos-adm._tcp.test.gokrb5.", vec![(749, "127.0.0.1.")])];
            if published_empty {
                zone.push(("_kpasswd._udp.test.gokrb5.", Vec::new()));
                zone.push(("_kpasswd._tcp.test.gokrb5.", Vec::new()));
            }
            let dns = Dns::start(zone).await?;
            // When the Auto request runs.
            let result = dns
                .transport()?
                .send_to_kpasswd_realm(&dns_config()?, KdcProtocol::Auto, REALM, REQUEST)
                .await;
            let questions = dns.finish().await?;
            // Then the administration service was asked about once, for both transports.
            assert_eq!(
                asked(&questions, "_kerberos-adm._tcp"),
                1,
                "empty record sets: {published_empty}: {questions:?}"
            );
            assert_eq!(asked(&questions, "_kerberos-adm._udp"), 0, "{questions:?}");
            // And the UDP pass tried the administration host at the kpasswd port.
            assert!(
                matches!(&result, Err(ClientError::KdcEndpointFailures {
                    realm: _,
                    protocol: KdcProtocol::Udp,
                    failures
                }) if failures.iter().any(|failure| failure.starts_with("127.0.0.1:464:"))),
                "empty record sets: {published_empty}: expected UDP failures at 127.0.0.1:464, got {}",
                describe(&result)
            );
        }
        Ok(())
    })
}

/// The TCP pass keeps the SRV priority order of the record set: the best entry answers, the next is never used.
#[test]
fn kpasswd_auto_tcp_pass_keeps_the_priority_order() -> Result<(), TestError> {
    runtime()?.block_on(async {
        // Given two live TCP entries of one record set, the second with the worse priority.
        let (first, _first_udp) = bind_tcp_and_udp_pair().await?;
        let (second, _second_udp) = bind_tcp_and_udp_pair().await?;
        let dns = Dns::start(vec![(
            "_kpasswd._tcp.test.gokrb5.",
            vec![
                (first.local_addr()?.port(), "127.0.0.1."),
                (second.local_addr()?.port(), "127.0.0.1."),
            ],
        )])
        .await?;
        let server = tokio::spawn(async move {
            let (request, mut socket) = read_tcp_request(&first).await?;
            write_tcp_response(&mut socket, b"tcp-reply").await?;
            Ok::<_, io::Error>(request)
        });
        // When the Auto request runs.
        let result = dns
            .transport()?
            .send_to_kpasswd_realm(&dns_config()?, KdcProtocol::Auto, REALM, REQUEST)
            .await;
        let _questions = dns.finish().await?;
        // Then the best entry answered and the other was never contacted.
        assert_eq!(shown(result)?, b"tcp-reply");
        assert_eq!(
            bounded(Duration::from_secs(10), "first TCP peer", server).await???,
            REQUEST
        );
        assert_no_connection(&second, "second TCP entry").await;
        Ok(())
    })
}
