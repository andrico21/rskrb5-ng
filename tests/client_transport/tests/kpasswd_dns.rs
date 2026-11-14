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

/// SRV answers of one fixture name: `(port, target)`; the target `.` is the root name.
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
        let socket = UdpSocket::bind("127.0.0.1:0").await?;
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
                for (port, host) in records {
                    let target = if *host == "." {
                        Name::root()
                    } else {
                        Name::from_ascii(host)?
                    };
                    response.answers.push(Record::from_rdata(
                        query.name().clone(),
                        60,
                        RData::SRV(SRV::new(0, 0, *port, target)),
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
        let (udp, listener) = bind_udp_and_tcp_pair().await?;
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

/// A root target in either `_kpasswd` record set aborts discovery: no fallback, no other pass.
#[test]
fn kpasswd_auto_root_target_aborts_without_the_other_pass() -> Result<(), TestError> {
    runtime()?.block_on(async {
        for root_in_tcp in [true, false] {
            // Given one record set answering the root name and the other a live endpoint.
            let (udp, listener) = bind_udp_and_tcp_pair().await?;
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
            let server = tokio::spawn(async move {
                let (request, mut socket) = read_tcp_request(&listener).await?;
                write_tcp_response(&mut socket, b"tcp-reply").await?;
                Ok::<_, io::Error>((request, listener))
            });
            // When the Auto request runs.
            let result = dns
                .transport()?
                .send_to_kpasswd_realm(&dns_config()?, KdcProtocol::Auto, REALM, REQUEST)
                .await;
            let questions = dns.finish().await?;
            // Then it fails with the discovery error and nothing was sent anywhere.
            assert!(
                matches!(&result, Err(ClientError::DnsServiceUnavailable { service, realm })
                    if service == "_kpasswd" && realm == REALM),
                "root in tcp: {root_in_tcp}: expected DnsServiceUnavailable, got {}",
                describe(&result)
            );
            assert_eq!(
                asked(&questions, "_kerberos-adm"),
                0,
                "questions: {questions:?}"
            );
            assert_no_datagram(&udp, "root target").await;
            assert!(
                timeout(Duration::from_millis(50), server).await.is_err(),
                "root in tcp: {root_in_tcp}: the TCP peer was contacted"
            );
        }
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
        let (udp, udp_listener) = bind_udp_and_tcp_pair().await?;
        let (tcp_udp, tcp_listener) = bind_udp_and_tcp_pair().await?;
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
        let (udp, listener) = bind_udp_and_tcp_pair().await?;
        drop(listener);
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
