//! Tokio KDC transport tests against in-process stub KDCs.
//!
//! The stubs speak RFC 4120 UDP datagrams and length-prefixed TCP frames, so
//! these tests pin the wire framing, configured KDC and kpasswd discovery, the
//! UDP-to-TCP fall-back, kpasswd result handling and TCP stream reuse without a
//! live KDC.
#![cfg(feature = "tokio")]

use core::{error::Error, time::Duration};

use rskrb5_ng::{
    client::{
        KRB_ERR_RESPONSE_TOO_BIG, PA_ETYPE_INFO2, build_tgt_as_req,
        options::AsReq,
        principal::Principal,
        transport::{KdcEndpoint, KdcEndpointSource, KdcProtocol, Tokio},
    },
    config::Config,
    error::{Client as ClientError, Kadmin as KadminError},
    kadmin::{KPASSWD_AUTHERROR, KPASSWD_SUCCESS, Request as KpasswdRequest},
};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::{TcpListener, UdpSocket},
};

/// Hex dump of a marshalled kpasswd request from the gokrb5 fixtures.
const MARSHALLED_KPASSWD_REQ: &str = include_str!("../fixtures/kpasswd-request.hex");
/// Length of the kpasswd reply header: message length, version, AP-REP length.
const KPASSWD_HEADER_LEN: usize = 6;

/// Tests of the Tokio KDC transport: UDP/TCP framing, configured KDC and
/// kpasswd discovery, fall-back, kpasswd results and TCP stream reuse.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    mod bounded;
    use bounded::{bounded, stop};

    use crate::ambient_guard::tests::access_violations;
    /// Configured preauthentication connection reuse.
    mod affinity;
    /// Live KDC probe exchange implementation.
    mod probe;
    use probe::probe_exchange;
    /// DNS protocol and target failover regressions.
    mod dns;
    /// Real-key kpasswd request and response fixtures.
    mod kpasswd_context;
    /// Checked password result regressions.
    mod password_results;
    /// Unsigned outcomes through both public checked helpers.
    mod unsigned;
    use core::{fmt, future::poll_fn, net::SocketAddr, pin::pin, task::Poll};
    use std::{
        env,
        io::{self, Write as _},
        time::{Instant, SystemTime},
    };

    use chrono::{DateTime, FixedOffset, Utc};
    use hickory_resolver::proto::{
        op::Message,
        rr::{
            Name, RData, Record, RecordType,
            rdata::{A, SRV},
        },
    };
    use rasn::{der, types::Integer};
    use rasn_kerberos::{KerberosString, KerberosTime, KrbError, PrincipalName, Realm};
    use tokio::{
        net::TcpStream,
        runtime::{Builder, Runtime},
        time::timeout,
    };

    use super::*;

    /// Error type of these tests; `Send` so stub KDC tasks can return it.
    type TestError = Box<dyn Error + Send + Sync>;

    /// A possibly committed TCP mutation must not be delivered to a second endpoint.
    #[test]
    fn kpasswd_lost_reply_does_not_retry_endpoint() -> Result<(), TestError> {
        runtime()?.block_on(async {
            let first = TcpListener::bind("127.0.0.1:0").await?;
            let second = TcpListener::bind("127.0.0.1:0").await?;
            let config = config_with_kpasswd_servers(
                [
                    first.local_addr()?.to_string(),
                    second.local_addr()?.to_string(),
                ],
                1,
            )?;
            let committed = tokio::spawn(async move {
                let (request, socket) = read_tcp_request(&first).await?;
                drop(socket);
                Ok::<_, io::Error>(request)
            });
            let transport = Tokio::new().with_timeout(Duration::from_secs(1));
            let result = bounded(
                Duration::from_secs(10),
                "password exchange and duplicate observation",
                without_connection(
                    &second,
                    transport.send_to_kpasswd_realm(
                        &config,
                        KdcProtocol::Tcp,
                        "TEST.GOKRB5",
                        b"mutation",
                    ),
                ),
            )
            .await??;
            assert_eq!(
                bounded(Duration::from_secs(10), "committed request task", committed).await???,
                b"mutation"
            );
            assert!(
                matches!(result, Err(ClientError::KpasswdOutcomeUnknown(_))),
                "lost reply must be outcome unknown"
            );
            Ok::<_, TestError>(())
        })
    }

    /// Auto password exchanges never resend a delivered UDP mutation over TCP.
    #[test]
    fn kpasswd_udp_timeout_does_not_retry_tcp() -> Result<(), TestError> {
        runtime()?.block_on(async {
            let (udp, tcp) = bind_udp_and_tcp_pair().await?;
            let config = config_with_kpasswd_servers([udp.local_addr()?.to_string()], 1465)?;
            let received = tokio::spawn(async move {
                let mut bytes = [0; 64];
                let (length, _) = bounded(
                    Duration::from_secs(10),
                    "password UDP delivery",
                    udp.recv_from(&mut bytes),
                )
                .await??;
                Ok::<_, io::Error>(length)
            });
            let transport = Tokio::new().with_timeout(Duration::from_millis(50));
            let result = bounded(
                Duration::from_secs(10),
                "UDP password exchange",
                without_connection(
                    &tcp,
                    transport.send_to_kpasswd_realm(
                        &config,
                        KdcProtocol::Auto,
                        "TEST.GOKRB5",
                        b"mutation",
                    ),
                ),
            )
            .await??;
            let length =
                bounded(Duration::from_secs(10), "password delivery task", received).await???;
            assert_eq!(length, 8);
            assert!(matches!(result, Err(ClientError::KpasswdOutcomeUnknown(_))));
            Ok::<_, TestError>(())
        })
    }

    /// Observe acceptance before polling the client and until its completion.
    async fn without_connection<F>(
        listener: &TcpListener,
        future: F,
    ) -> Result<F::Output, io::Error>
    where
        F: Future,
    {
        let mut exchange = pin!(future);
        poll_fn(|cx| {
            if let Poll::Ready(connection) = listener.poll_accept(cx) {
                drop(connection?);
                return Poll::Ready(Err(io::Error::other(
                    "duplicate connection during password exchange",
                )));
            }
            let result = exchange.as_mut().poll(cx);
            if result.is_ready()
                && let Poll::Ready(connection) = listener.poll_accept(cx)
            {
                drop(connection?);
                return Poll::Ready(Err(io::Error::other(
                    "duplicate connection at client completion",
                )));
            }
            result.map(Ok)
        })
        .await
    }

    /// KDC reserved high bits are rejected independently of the allocation cap.
    #[test]
    fn kdc_tcp_rejects_reserved_bit_before_body_read() -> Result<(), TestError> {
        runtime()?.block_on(async {
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let addr = listener.local_addr()?;
            let task = tokio::spawn(async move {
                let (_, mut socket) = read_tcp_request(&listener).await?;
                socket.write_all(&0x8000_0000_u32.to_be_bytes()).await?;
                Ok::<_, io::Error>(())
            });
            let error = Tokio::new()
                .with_tcp_response_limit(0)
                .send_tcp(addr, b"request")
                .await
                .err()
                .ok_or("reserved bit rejected")?;
            bounded(Duration::from_secs(10), "TCP peer task", task).await???;
            assert!(
                !matches!(
                    error,
                    ClientError::TcpResponseTooLarge {
                        actual: _,
                        limit: _
                    }
                ),
                "reserved bit must be a protocol error, not an allocation limit"
            );
            assert!(
                !matches!(error, ClientError::Io(_)),
                "reject before reading body"
            );
            Ok::<_, TestError>(())
        })
    }

    /// Administration DNS fallback supplies hosts but never its service port.
    #[test]
    fn kpasswd_dns_admin_fallback_uses_port_464() -> Result<(), TestError> {
        runtime()?.block_on(async {
            let socket = UdpSocket::bind("127.0.0.1:0").await?;
            let server = socket.local_addr()?;
            let task = tokio::spawn(dns_admin_fixture(socket, None));
            let config = Config::parse("[libdefaults]\n dns_lookup_kdc = true\n")?;
            let result = Tokio::new()
                .with_dns_server(&server.to_string())?
                .discover_kpasswd_servers(&config, "TEST.GOKRB5", KdcProtocol::Tcp)
                .await;
            stop(task).await?;
            let endpoints = result?;
            assert_eq!(
                endpoints
                    .iter()
                    .map(|endpoint| endpoint.port)
                    .collect::<Vec<_>>(),
                [464]
            );
            Ok::<_, TestError>(())
        })
    }

    /// An authoritative root target prohibits administration fallback.
    #[test]
    fn kpasswd_dns_unavailable_stops_fallback() -> Result<(), TestError> {
        runtime()?.block_on(async {
            let socket = UdpSocket::bind("127.0.0.1:0").await?;
            let server = socket.local_addr()?;
            let task = tokio::spawn(dns_admin_fixture(socket, Some(Name::root())));
            let config = Config::parse("[libdefaults]\n dns_lookup_kdc = true\n")?;
            let result = Tokio::new()
                .with_dns_server(&server.to_string())?
                .discover_kpasswd_servers(&config, "TEST.GOKRB5", KdcProtocol::Tcp)
                .await;
            stop(task).await?;
            assert!(
                result.err().is_some(),
                "explicit unavailability must stop discovery"
            );
            Ok::<_, TestError>(())
        })
    }

    /// Explicit DNS discovery retains all addresses of a password service target.
    #[test]
    fn kpasswd_dns_retains_all_target_addresses() -> Result<(), TestError> {
        runtime()?.block_on(async {
            let socket = UdpSocket::bind("127.0.0.1:0").await?;
            let server = socket.local_addr()?;
            let task = tokio::spawn(dns_admin_fixture(
                socket,
                Some(Name::from_ascii("multiple.test.gokrb5.")?),
            ));
            let config = Config::parse("[libdefaults]\n dns_lookup_kdc = true\n")?;
            let result = Tokio::new()
                .with_dns_server(&server.to_string())?
                .discover_kpasswd_servers(&config, "TEST.GOKRB5", KdcProtocol::Tcp)
                .await;
            stop(task).await?;
            let mut authorities = result?
                .iter()
                .map(KdcEndpoint::authority)
                .collect::<Vec<_>>();
            authorities.sort();
            assert_eq!(authorities, ["127.0.0.1:1464", "127.0.0.2:1464"]);
            Ok::<_, TestError>(())
        })
    }

    /// Serve selected kpasswd records and a conventional administration service.
    async fn dns_admin_fixture(socket: UdpSocket, kpasswd: Option<Name>) -> Result<(), TestError> {
        loop {
            let mut buffer = [0; 4096];
            let (len, peer) = bounded(
                Duration::from_secs(10),
                "DNS request",
                socket.recv_from(&mut buffer),
            )
            .await??;
            let request = Message::from_vec(buffer.get(..len).ok_or("DNS length")?)?;
            let query = request.queries.first().ok_or("DNS question")?;
            let mut response = Message::response(request.metadata.id, request.metadata.op_code);
            response.metadata.authoritative = true;
            response.metadata.recursion_available = true;
            response.queries = request.queries.clone();
            if query.query_type() == RecordType::SRV
                && query.name().to_utf8().starts_with("_kpasswd.")
                && let Some(target) = &kpasswd
            {
                response.answers.push(Record::from_rdata(
                    query.name().clone(),
                    60,
                    RData::SRV(SRV::new(0, 0, 1464, target.clone())),
                ));
            }
            if query.query_type() == RecordType::SRV
                && query.name().to_utf8().starts_with("_kerberos-adm.")
            {
                response.answers.push(Record::from_rdata(
                    query.name().clone(),
                    60,
                    RData::SRV(SRV::new(0, 0, 749, Name::from_ascii("admin.test.gokrb5.")?)),
                ));
            }
            if query.query_type() == RecordType::A {
                if query.name().to_utf8().starts_with("multiple.") {
                    response.answers.push(Record::from_rdata(
                        query.name().clone(),
                        60,
                        RData::A(A::new(127, 0, 0, 2)),
                    ));
                }
                response.answers.push(Record::from_rdata(
                    query.name().clone(),
                    60,
                    RData::A(A::new(127, 0, 0, 1)),
                ));
            }
            let _: usize = socket.send_to(&response.to_vec()?, peer).await?;
        }
    }

    /// Library transport discovery must not read process environment overrides.
    #[test]
    fn transport_dns_has_no_ambient_environment_reads() {
        assert!(
            access_violations(
                "src/client/transport.rs",
                include_str!("../../src/client/transport.rs"),
            )
            .is_empty(),
            "DNS configuration must be explicitly supplied"
        );
    }

    /// Alternate environment reader spellings must not evade transport confinement.
    #[test]
    fn transport_ambient_check_rejects_alternate_spellings() {
        // Given: readers the former substring check admitted.
        assert!(
            [
                "use std::env::var as read; fn hidden() { read(\"HOME\"); }",
                "fn hidden() { std::env::var_os(\"HOME\"); }",
                "fn hidden() { std::env::vars().collect::<Vec<_>>(); }",
                "fn hidden() { std::env::vars_os(); }",
                "fn hidden() { env::\nvar\n(\"HOME\"); }",
            ]
            .iter()
            .all(|source| {
                // When: the transport check classifies the fixture.
                // Then: each ambient discovery is rejected.
                !access_violations("src/client/transport.rs", source).is_empty()
            }),
            "alternate environment spellings must be rejected"
        );
    }

    /// Bare IPv6 literals retain every address component and the service default port.
    #[test]
    fn configured_endpoint_preserves_bare_ipv6() -> Result<(), TestError> {
        // Given a final decimal-looking IPv6 component, not an authority port.
        let host = "2001:db8::1:2";
        for default_port in [88, 464] {
            // When the endpoint is parsed for either Kerberos service.
            let endpoint =
                KdcEndpoint::configured_with_default_port(KdcProtocol::Tcp, host, default_port)?;
            // Then the whole literal is the host and the default still applies.
            assert_eq!(endpoint.host, host);
            assert_eq!(endpoint.port, default_port);
        }
        Ok(())
    }

    /// Administrative IPv6 authorities supply a complete host, never the administration port.
    #[test]
    fn kpasswd_admin_fallback_preserves_ipv6() -> Result<(), TestError> {
        // Given bracketed, bare IPv6 and hostname administration endpoints.
        let config = Config::parse(
            "[libdefaults]\n dns_lookup_kdc = false\n[realms]\n TEST.GOKRB5 = {\n admin_server = [2001:db8::1]:749\n admin_server = 2001:db8::1:2\n admin_server = admin.example:1749\n }\n",
        )?;
        // When password-change discovery derives its configuration fallback.
        let endpoints = runtime()?.block_on(Tokio::new().discover_kpasswd_servers(
            &config,
            "TEST.GOKRB5",
            KdcProtocol::Tcp,
        ))?;
        // Then every complete host is retained with the password-change port.
        let authorities: Vec<_> = endpoints.iter().map(KdcEndpoint::authority).collect();
        assert_eq!(
            authorities,
            [
                "[2001:db8::1]:464",
                "[2001:db8::1:2]:464",
                "admin.example:464"
            ]
        );
        Ok(())
    }

    /// IPv6-only UDP peers can receive a request without a TCP fallback.
    #[test]
    fn udp_transport_reaches_ipv6_loopback() -> Result<(), TestError> {
        runtime()?.block_on(async {
            // Given a live IPv6-only UDP peer on an ephemeral port.
            let server = UdpSocket::bind("[::1]:0").await?;
            let addr = server.local_addr()?;
            let task = tokio::spawn(async move {
                let mut request = [0; 64];
                let (len, peer) = bounded(
                    Duration::from_secs(10),
                    "IPv6 UDP request",
                    server.recv_from(&mut request),
                )
                .await??;
                assert_eq!(request.get(..len), Some(b"ipv6-request".as_slice()));
                let _: usize = server.send_to(b"ipv6-response", peer).await?;
                Ok::<_, io::Error>(())
            });
            // When the direct UDP transport sends to that address.
            let result = Tokio::new()
                .with_timeout(Duration::from_secs(2))
                .send_udp(addr, b"ipv6-request")
                .await;
            // Then a complete UDP reply is returned.
            let response = result?;
            bounded(Duration::from_secs(10), "IPv6 UDP peer task", task).await???;
            assert_eq!(response, b"ipv6-response");
            Ok::<_, TestError>(())
        })
    }

    /// Oversized datagrams must not be reported as successful prefixes.
    #[test]
    fn udp_transport_rejects_truncated_datagram() -> Result<(), TestError> {
        runtime()?.block_on(async {
            // Given a peer whose response exceeds the four-byte acceptance limit.
            let server = UdpSocket::bind("127.0.0.1:0").await?;
            let addr = server.local_addr()?;
            let task = tokio::spawn(async move {
                let mut request = [0; 64];
                let (_, peer) = bounded(
                    Duration::from_secs(10),
                    "UDP request",
                    server.recv_from(&mut request),
                )
                .await??;
                let _: usize = server.send_to(b"ABCDEFGH", peer).await?;
                Ok::<_, io::Error>(())
            });
            // When the transport receives that datagram.
            let response = Tokio::new()
                .with_udp_response_limit(4)
                .send_udp(addr, b"request")
                .await;
            bounded(Duration::from_secs(10), "oversized UDP peer task", task).await???;
            // Then no incomplete response is returned as success.
            assert!(
                response.err().is_some(),
                "oversized datagram must be rejected"
            );
            Ok::<_, TestError>(())
        })
    }

    /// UDP limits accept an exact-sized datagram, including an unrestricted caller cap.
    #[test]
    fn udp_transport_accepts_exact_limit() -> Result<(), TestError> {
        runtime()?.block_on(async {
            for limit in [8, usize::MAX] {
                let server = UdpSocket::bind("127.0.0.1:0").await?;
                let addr = server.local_addr()?;
                let task = tokio::spawn(async move {
                    let mut request = [0; 64];
                    let (_, peer) = bounded(
                        Duration::from_secs(10),
                        "UDP request",
                        server.recv_from(&mut request),
                    )
                    .await??;
                    let _: usize = server.send_to(b"ABCDEFGH", peer).await?;
                    Ok::<_, io::Error>(())
                });
                let response = Tokio::new()
                    .with_udp_response_limit(limit)
                    .send_udp(addr, b"request")
                    .await?;
                bounded(Duration::from_secs(10), "exact UDP peer task", task).await???;
                assert_eq!(response, b"ABCDEFGH");
            }
            Ok::<_, TestError>(())
        })
    }

    /// Pins that a UDP send transmits the raw request datagram and returns the reply datagram.
    #[test]
    fn tokio_transport_sends_udp_datagram() -> Result<(), TestError> {
        runtime()?.block_on(async {
            let server = UdpSocket::bind("127.0.0.1:0").await?;
            let addr = server.local_addr()?;
            let task = tokio::spawn(async move {
                let mut request = [0_u8; 64];
                let (len, peer) = bounded(
                    Duration::from_secs(10),
                    "UDP AS request",
                    server.recv_from(&mut request),
                )
                .await??;
                assert_eq!(request.get(..len), Some(b"udp-as-req".as_slice()));
                let _: usize = server.send_to(b"udp-as-rep", peer).await?;
                Ok::<_, io::Error>(())
            });

            let response = Tokio::new()
                .with_timeout(Duration::from_secs(2))
                .send(KdcProtocol::Udp, addr, b"udp-as-req")
                .await?;

            bounded(Duration::from_secs(10), "UDP peer task", task).await???;
            assert_eq!(response, b"udp-as-rep");
            Ok::<_, TestError>(())
        })
    }

    /// UDP accepts its maximum request size and rejects one byte above it.
    #[test]
    fn udp_request_size_boundaries() -> Result<(), TestError> {
        runtime()?.block_on(async {
            let peer = UdpSocket::bind("127.0.0.1:0").await?;
            let addr = peer.local_addr()?;
            let transport = Tokio::new().with_timeout(Duration::from_secs(2));
            let oversized = vec![42; 65_508];
            let result = transport.send_udp(addr, &oversized).await;
            assert!(matches!(
                result,
                Err(ClientError::UdpRequestTooLarge {
                    actual: 65_508,
                    limit: 65_507
                })
            ));
            // macOS refuses loopback datagrams above `net.inet.udp.maxdgram`
            // (9216 bytes by default), so the accepted maximum is sent elsewhere.
            #[cfg(not(target_os = "macos"))]
            {
                let server = async {
                    let mut bytes = vec![0; 65_507];
                    let (length, client) = bounded(
                        Duration::from_secs(10),
                        "maximum UDP request",
                        peer.recv_from(&mut bytes),
                    )
                    .await??;
                    assert_eq!(length, 65_507);
                    let _: usize = peer.send_to(&[17], client).await?;
                    Ok::<_, TestError>(())
                };
                let request = vec![42; 65_507];
                let (sent, response) = tokio::join!(server, transport.send_udp(addr, &request));
                sent?;
                assert_eq!(response?, [17]);
            }
            Ok(())
        })
    }

    /// Password UDP preserves the exact datagram bound and uncertainty taxonomy.
    #[test]
    fn password_udp_request_size_boundaries() -> Result<(), TestError> {
        runtime()?.block_on(async {
            let peer = UdpSocket::bind("127.0.0.1:0").await?;
            let addr = peer.local_addr()?;
            let config = config_with_kpasswd_servers([addr.to_string()], 1465)?;
            let transport = Tokio::new().with_timeout(Duration::from_secs(2));
            let oversized = vec![42; 65_508];
            assert!(matches!(
                transport
                    .send_to_kpasswd_realm(&config, KdcProtocol::Udp, "TEST.GOKRB5", &oversized)
                    .await,
                Err(ClientError::KdcEndpointFailures {
                    realm: _,
                    protocol: _,
                    failures: _
                })
            ));
            // macOS refuses loopback datagrams above `net.inet.udp.maxdgram`
            // (9216 bytes by default), so the accepted maximum is sent elsewhere.
            #[cfg(not(target_os = "macos"))]
            {
                let server = async {
                    let mut bytes = vec![0; 65_507];
                    let (length, client) = bounded(
                        Duration::from_secs(10),
                        "maximum password UDP request",
                        peer.recv_from(&mut bytes),
                    )
                    .await??;
                    assert_eq!(length, 65_507);
                    let _: usize = peer.send_to(&[17], client).await?;
                    Ok::<_, TestError>(())
                };
                let request = vec![42; 65_507];
                let (sent, response) = tokio::join!(
                    server,
                    transport.send_to_kpasswd_realm(
                        &config,
                        KdcProtocol::Udp,
                        "TEST.GOKRB5",
                        &request
                    )
                );
                sent?;
                assert_eq!(response?, [17]);
            }
            Ok(())
        })
    }

    /// Auto fallback occurs only for UDP response-too-big, retaining ordinary replies.
    #[test]
    fn configured_auto_classifies_protocol_and_reply() -> Result<(), TestError> {
        runtime()?.block_on(async {
            for tcp_first in [false, true] {
                for too_big in [false, true] {
                    let (udp, tcp) = bind_udp_and_tcp_pair().await?;
                    let addr = udp.local_addr()?;
                    let config = config_with_kdcs_and_udp_limit(
                        [addr.to_string()],
                        if tcp_first { 1 } else { 1465 },
                    )?;
                    let response = if too_big {
                        response_too_big_error()?
                    } else {
                        b"ordinary".to_vec()
                    };
                    let expected = if !tcp_first && too_big {
                        b"fallback".to_vec()
                    } else {
                        response.clone()
                    };
                    let server = async {
                        if tcp_first {
                            let (_, mut stream) = read_tcp_request(&tcp).await?;
                            write_tcp_response(&mut stream, &response).await?;
                        } else {
                            let mut request = [0; 64];
                            let (_, client) = bounded(
                                Duration::from_secs(10),
                                "configured Auto UDP request",
                                udp.recv_from(&mut request),
                            )
                            .await??;
                            let _: usize = udp.send_to(&response, client).await?;
                            if too_big {
                                let (_, mut stream) = read_tcp_request(&tcp).await?;
                                write_tcp_response(&mut stream, b"fallback").await?;
                            }
                        }
                        Ok::<_, TestError>(())
                    };
                    let transport = Tokio::new().with_timeout(Duration::from_millis(200));
                    let (sent, result) = tokio::join!(
                        server,
                        transport.send_to_realm(
                            &config,
                            KdcProtocol::Auto,
                            "TEST.GOKRB5",
                            b"request"
                        )
                    );
                    sent?;
                    assert_eq!(result?, expected);
                }
            }
            Ok(())
        })
    }

    /// Direct Auto retains ordinary UDP replies and falls back only on response-too-big.
    #[test]
    fn direct_auto_classifies_udp_reply() -> Result<(), TestError> {
        runtime()?.block_on(async {
            for too_big in [false, true] {
                let (udp, tcp) = bind_udp_and_tcp_pair().await?;
                let addr = udp.local_addr()?;
                let response = if too_big {
                    response_too_big_error()?
                } else {
                    b"ordinary".to_vec()
                };
                let server = async {
                    let mut request = [0; 64];
                    let (_, client) = bounded(
                        Duration::from_secs(10),
                        "pinned Auto UDP request",
                        udp.recv_from(&mut request),
                    )
                    .await??;
                    let _: usize = udp.send_to(&response, client).await?;
                    if too_big {
                        let (_, mut stream) = read_tcp_request(&tcp).await?;
                        write_tcp_response(&mut stream, b"fallback").await?;
                    }
                    Ok::<_, TestError>(())
                };
                let transport = Tokio::new().with_timeout(Duration::from_millis(200));
                let (sent, result) =
                    tokio::join!(server, transport.send(KdcProtocol::Auto, addr, b"request"));
                sent?;
                assert_eq!(
                    result?,
                    if too_big {
                        b"fallback".as_slice()
                    } else {
                        b"ordinary".as_slice()
                    }
                );
            }
            Ok(())
        })
    }

    /// Pins that a TCP send frames the request and reads the reply with a four-byte length prefix.
    #[test]
    fn tokio_transport_uses_tcp_length_prefix() -> Result<(), TestError> {
        runtime()?.block_on(async {
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let addr = listener.local_addr()?;
            let task = tokio::spawn(async move {
                let (request, mut socket) = read_tcp_request(&listener).await?;
                assert_eq!(request, b"tcp-as-req");

                socket.write_all(&10_u32.to_be_bytes()).await?;
                socket.write_all(b"tcp-as-rep").await?;
                Ok::<_, io::Error>(())
            });

            let response = Tokio::new()
                .with_timeout(Duration::from_secs(2))
                .send_tcp(addr, b"tcp-as-req")
                .await?;

            bounded(Duration::from_secs(10), "TCP peer task", task).await???;
            assert_eq!(response, b"tcp-as-rep");
            Ok::<_, TestError>(())
        })
    }

    /// Pins how configured KDC authorities parse: host, port, default ports and IPv6 literals.
    #[test]
    fn configured_kdc_endpoint_parses_authorities() -> Result<(), TestError> {
        let host = KdcEndpoint::configured(KdcProtocol::Tcp, "kdc.test.gokrb5:88")?;
        assert_eq!(host.protocol, KdcProtocol::Tcp);
        assert_eq!(host.host, "kdc.test.gokrb5");
        assert_eq!(host.port, 88);
        assert_eq!(host.source, KdcEndpointSource::Config);
        assert_eq!(host.authority(), "kdc.test.gokrb5:88");

        let default_port = KdcEndpoint::configured(KdcProtocol::Udp, "kdc.test.gokrb5")?;
        assert_eq!(default_port.port, 88);

        let kpasswd_default_port = KdcEndpoint::configured_with_default_port(
            KdcProtocol::Tcp,
            "kpasswd.test.gokrb5",
            464,
        )?;
        assert_eq!(kpasswd_default_port.host, "kpasswd.test.gokrb5");
        assert_eq!(kpasswd_default_port.port, 464);

        let ipv6 = KdcEndpoint::configured(KdcProtocol::Tcp, "[::1]:1088")?;
        assert_eq!(ipv6.host, "::1");
        assert_eq!(ipv6.port, 1088);
        assert_eq!(ipv6.authority(), "[::1]:1088");

        let bare_ipv6 = KdcEndpoint::configured(KdcProtocol::Tcp, "::1")?;
        assert_eq!(bare_ipv6.host, "::1");
        assert_eq!(bare_ipv6.port, 88);

        let rejected = KdcEndpoint::configured(KdcProtocol::Tcp, "kdc.test.gokrb5:not-a-port");
        assert!(
            rejected.err().is_some(),
            "a non-numeric port must be rejected"
        );
        Ok(())
    }

    /// Pins that a realm send over UDP reaches the KDC named in the configuration.
    #[test]
    fn tokio_transport_sends_udp_to_configured_realm_kdc() -> Result<(), TestError> {
        runtime()?.block_on(async {
            let server = UdpSocket::bind("127.0.0.1:0").await?;
            let addr = server.local_addr()?;
            let config = config_with_kdcs([addr.to_string()])?;
            let task = tokio::spawn(async move {
                let mut request = [0_u8; 64];
                let (len, peer) = bounded(
                    Duration::from_secs(10),
                    "configured UDP AS request",
                    server.recv_from(&mut request),
                )
                .await??;
                assert_eq!(
                    request.get(..len),
                    Some(b"configured-udp-as-req".as_slice())
                );
                let _: usize = server.send_to(b"configured-udp-as-rep", peer).await?;
                Ok::<_, io::Error>(())
            });

            let response = Tokio::new()
                .with_timeout(Duration::from_secs(2))
                .send_to_realm(
                    &config,
                    KdcProtocol::Udp,
                    "TEST.GOKRB5",
                    b"configured-udp-as-req",
                )
                .await?;

            bounded(Duration::from_secs(10), "configured UDP peer task", task).await???;
            assert_eq!(response, b"configured-udp-as-rep");
            Ok::<_, TestError>(())
        })
    }

    /// Pins that a realm send over TCP reaches the KDC named in the configuration.
    #[test]
    fn tokio_transport_sends_tcp_to_configured_realm_kdc() -> Result<(), TestError> {
        runtime()?.block_on(async {
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let addr = listener.local_addr()?;
            let config = config_with_kdcs([addr.to_string()])?;
            let task = tokio::spawn(async move {
                let (request, mut socket) = read_tcp_request(&listener).await?;
                assert_eq!(request, b"configured-tcp-as-req");

                socket.write_all(&21_u32.to_be_bytes()).await?;
                socket.write_all(b"configured-tcp-as-rep").await?;
                Ok::<_, io::Error>(())
            });

            let response = Tokio::new()
                .with_timeout(Duration::from_secs(2))
                .send_to_realm(
                    &config,
                    KdcProtocol::Tcp,
                    "TEST.GOKRB5",
                    b"configured-tcp-as-req",
                )
                .await?;

            bounded(Duration::from_secs(10), "configured TCP peer task", task).await???;
            assert_eq!(response, b"configured-tcp-as-rep");
            Ok::<_, TestError>(())
        })
    }

    /// Pins that configured kpasswd servers are discovered in order with the kpasswd default port.
    #[test]
    fn tokio_transport_discovers_configured_kpasswd_servers() -> Result<(), TestError> {
        runtime()?.block_on(async {
            let config = config_with_kpasswd_servers(
                ["kpasswd.test.gokrb5".to_owned(), "[::1]:7464".to_owned()],
                1465,
            )?;

            let endpoints = Tokio::new()
                .discover_kpasswd_servers(&config, "TEST.GOKRB5", KdcProtocol::Tcp)
                .await?;

            assert_eq!(endpoints.len(), 2);
            let [first, second] = endpoints.as_slice() else {
                return Err("two kpasswd endpoints are discovered".into());
            };
            assert_eq!(first.protocol, KdcProtocol::Tcp);
            assert_eq!(first.host, "kpasswd.test.gokrb5");
            assert_eq!(first.port, 464);
            assert_eq!(first.source, KdcEndpointSource::Config);
            assert_eq!(second.host, "::1");
            assert_eq!(second.port, 7464);
            Ok::<_, TestError>(())
        })
    }

    /// Pins that configured kpasswd servers win over DNS discovery when DNS lookup is enabled.
    #[test]
    fn tokio_transport_prefers_configured_kpasswd_servers_when_dns_enabled() -> Result<(), TestError>
    {
        runtime()?.block_on(async {
            let mut config = config_with_kpasswd_servers(["kpasswd.test.gokrb5".to_owned()], 1465)?;
            config.libdefaults.dns_lookup_kdc = true.into();

            let endpoints = Tokio::new()
                .discover_kpasswd_servers(&config, "TEST.GOKRB5", KdcProtocol::Udp)
                .await?;

            assert_eq!(endpoints.len(), 1);
            let [first] = endpoints.as_slice() else {
                return Err("one kpasswd endpoint is discovered".into());
            };
            assert_eq!(first.protocol, KdcProtocol::Udp);
            assert_eq!(first.host, "kpasswd.test.gokrb5");
            assert_eq!(first.port, 464);
            assert_eq!(first.source, KdcEndpointSource::Config);
            Ok::<_, TestError>(())
        })
    }

    /// Pins that a kpasswd realm send over TCP reaches the configured kpasswd server.
    #[test]
    fn tokio_transport_sends_tcp_to_configured_kpasswd_server() -> Result<(), TestError> {
        runtime()?.block_on(async {
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let addr = listener.local_addr()?;
            let config = config_with_kpasswd_servers([addr.to_string()], 1465)?;
            let task = tokio::spawn(async move {
                let (request, mut socket) = read_tcp_request(&listener).await?;
                assert_eq!(request, b"kpasswd-tcp-req");
                write_tcp_response(&mut socket, b"kpasswd-tcp-rep").await
            });

            let response = Tokio::new()
                .with_timeout(Duration::from_secs(2))
                .send_to_kpasswd_realm(&config, KdcProtocol::Tcp, "TEST.GOKRB5", b"kpasswd-tcp-req")
                .await?;

            bounded(Duration::from_secs(10), "password TCP peer task", task).await???;
            assert_eq!(response, b"kpasswd-tcp-rep");
            Ok::<_, TestError>(())
        })
    }

    /// Pins that a configured kpasswd exchange sends the encoded request and parses a KRB-ERROR reply.
    #[test]
    fn tokio_transport_exchanges_configured_kpasswd_request() -> Result<(), TestError> {
        runtime()?.block_on(async {
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let addr = listener.local_addr()?;
            let config = config_with_kpasswd_servers([addr.to_string()], 1465)?;
            let request = KpasswdRequest::parse(&decode_hex(MARSHALLED_KPASSWD_REQ)?)?;
            let expected_request = request.encode()?;
            let response = kpasswd_reply_frame(0, &response_too_big_error()?)?;
            let expected_response_len = response.len();
            let task = tokio::spawn(async move {
                let (received, mut socket) = read_tcp_request(&listener).await?;
                assert_eq!(received, expected_request);
                write_tcp_response(&mut socket, &response).await
            });

            let reply = Tokio::new()
                .with_timeout(Duration::from_secs(2))
                .exchange_kpasswd_request_with_config(
                    &config,
                    KdcProtocol::Tcp,
                    "TEST.GOKRB5",
                    &request,
                )
                .await?;

            bounded(Duration::from_secs(10), "password exchange peer task", task).await???;
            assert!(reply.is_krb_error());
            assert_eq!(usize::from(reply.message_length), expected_response_len);
            assert_eq!(
                reply.krb_error.ok_or("KRB-ERROR parsed")?.error_code,
                KRB_ERR_RESPONSE_TOO_BIG
            );
            Ok::<_, TestError>(())
        })
    }

    /// Pins that a realm send over TCP moves on to the next configured KDC when the first refuses.
    #[test]
    fn tokio_transport_tries_next_configured_kdc_after_tcp_failure() -> Result<(), TestError> {
        runtime()?.block_on(async {
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let addr = listener.local_addr()?;
            let config = config_with_kdcs(["127.0.0.1:9".to_owned(), addr.to_string()])?;
            let task = tokio::spawn(async move {
                let (request, mut socket) = read_tcp_request(&listener).await?;
                assert_eq!(request, b"fallback-tcp-as-req");

                socket.write_all(&19_u32.to_be_bytes()).await?;
                socket.write_all(b"fallback-tcp-as-rep").await?;
                Ok::<_, io::Error>(())
            });

            let response = Tokio::new()
                .with_timeout(Duration::from_secs(2))
                .send_to_realm(
                    &config,
                    KdcProtocol::Tcp,
                    "TEST.GOKRB5",
                    b"fallback-tcp-as-req",
                )
                .await?;

            bounded(Duration::from_secs(10), "fallback TCP peer task", task).await???;
            assert_eq!(response, b"fallback-tcp-as-rep");
            Ok::<_, TestError>(())
        })
    }

    /// Pins that the Auto protocol retries over TCP after a UDP `KRB_ERR_RESPONSE_TOO_BIG` reply.
    #[test]
    fn tokio_transport_auto_retries_tcp_after_udp_response_too_big() -> Result<(), TestError> {
        runtime()?.block_on(async {
            let (udp, listener) = bind_udp_and_tcp_pair().await?;
            let addr = udp.local_addr()?;
            let too_big = response_too_big_error()?;

            let udp_task = tokio::spawn(async move {
                let mut request = [0_u8; 64];
                let (len, peer) = bounded(
                    Duration::from_secs(10),
                    "Auto UDP AS request",
                    udp.recv_from(&mut request),
                )
                .await??;
                assert_eq!(request.get(..len), Some(b"auto-as-req".as_slice()));
                let _: usize = udp.send_to(&too_big, peer).await?;
                Ok::<_, io::Error>(())
            });
            let tcp_task = tokio::spawn(async move {
                let (request, mut socket) = read_tcp_request(&listener).await?;
                assert_eq!(request, b"auto-as-req");
                write_tcp_response(&mut socket, b"auto-tcp-as-rep").await
            });

            let response = Tokio::new()
                .with_timeout(Duration::from_secs(2))
                .send(KdcProtocol::Auto, addr, b"auto-as-req")
                .await?;

            bounded(Duration::from_secs(10), "Auto UDP peer task", udp_task).await???;
            bounded(Duration::from_secs(10), "Auto TCP peer task", tcp_task).await???;
            assert_eq!(response, b"auto-tcp-as-rep");
            Ok::<_, TestError>(())
        })
    }

    /// Pins that an Auto kpasswd send goes straight to TCP under `udp_preference_limit = 1`.
    #[test]
    fn tokio_transport_auto_kpasswd_honors_tcp_only_udp_preference_limit() -> Result<(), TestError>
    {
        runtime()?.block_on(async {
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let addr = listener.local_addr()?;
            let config = config_with_kpasswd_servers([addr.to_string()], 1)?;
            let task = tokio::spawn(async move {
                let (request, mut socket) = read_tcp_request(&listener).await?;
                assert_eq!(request, b"auto-kpasswd-req");
                write_tcp_response(&mut socket, b"auto-kpasswd-tcp-rep").await
            });

            let response = Tokio::new()
                .with_timeout(Duration::from_secs(2))
                .send_to_kpasswd_realm(
                    &config,
                    KdcProtocol::Auto,
                    "TEST.GOKRB5",
                    b"auto-kpasswd-req",
                )
                .await?;

            bounded(Duration::from_secs(10), "Auto password peer task", task).await???;
            assert_eq!(response, b"auto-kpasswd-tcp-rep");
            Ok::<_, TestError>(())
        })
    }

    /// Builds a configuration whose `TEST.GOKRB5` realm lists `kdcs`, with DNS lookup off.
    fn config_with_kdcs<I>(kdcs: I) -> Result<Config, TestError>
    where
        I: IntoIterator<Item = String>,
    {
        config_with_kdcs_and_udp_limit(kdcs, 1465)
    }

    /// Builds a configuration whose `TEST.GOKRB5` realm lists `kdcs`, with the given UDP limit.
    fn config_with_kdcs_and_udp_limit<I>(
        kdcs: I,
        udp_preference_limit: i32,
    ) -> Result<Config, TestError>
    where
        I: IntoIterator<Item = String>,
    {
        let mut input = String::from(
            "
[libdefaults]
 dns_lookup_kdc = false
",
        );
        input.push_str(" udp_preference_limit = ");
        input.push_str(&udp_preference_limit.to_string());
        input.push_str(
            "

[realms]
 TEST.GOKRB5 = {
",
        );
        for kdc in kdcs {
            input.push_str("  kdc = ");
            input.push_str(&kdc);
            input.push('\n');
        }
        input.push_str(" }\n");
        Ok(Config::parse(&input)?)
    }

    /// Builds a configuration whose `TEST.GOKRB5` realm lists `servers` as kpasswd servers.
    fn config_with_kpasswd_servers<I>(
        servers: I,
        udp_preference_limit: i32,
    ) -> Result<Config, TestError>
    where
        I: IntoIterator<Item = String>,
    {
        let mut input = String::from(
            "
[libdefaults]
 dns_lookup_kdc = false
",
        );
        input.push_str(" udp_preference_limit = ");
        input.push_str(&udp_preference_limit.to_string());
        input.push_str(
            "

[realms]
 TEST.GOKRB5 = {
",
        );
        for server in servers {
            input.push_str("  kpasswd_server = ");
            input.push_str(&server);
            input.push('\n');
        }
        input.push_str(" }\n");
        Ok(Config::parse(&input)?)
    }

    /// Binds a UDP socket and a TCP listener on the same loopback port.
    ///
    /// The kernel picks a free UDP port, but that number may already be taken
    /// for TCP by another socket or excluded for TCP (Windows reports that as
    /// `PermissionDenied`), so either error retries on a fresh port.
    async fn bind_udp_and_tcp_pair() -> io::Result<(UdpSocket, TcpListener)> {
        for _ in 0_u8..16 {
            let udp = UdpSocket::bind("127.0.0.1:0").await?;
            match TcpListener::bind(udp.local_addr()?).await {
                Ok(listener) => return Ok((udp, listener)),
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::AddrInUse | io::ErrorKind::PermissionDenied
                    ) => {}
                Err(error) => return Err(error),
            }
        }
        Err(io::Error::from(io::ErrorKind::AddrInUse))
    }

    /// Accepts one connection and reads one length-prefixed request from it.
    async fn read_tcp_request(listener: &TcpListener) -> io::Result<(Vec<u8>, TcpStream)> {
        let (mut socket, _) = bounded(
            Duration::from_secs(10),
            "TCP request connection",
            listener.accept(),
        )
        .await??;
        let mut header = [0_u8; 4];
        let _: usize = bounded(
            Duration::from_secs(10),
            "TCP request header",
            socket.read_exact(&mut header),
        )
        .await??;
        let request_len = usize::try_from(u32::from_be_bytes(header)).map_err(io::Error::other)?;
        let mut request = vec![0_u8; request_len];
        let _: usize = bounded(
            Duration::from_secs(10),
            "TCP request body",
            socket.read_exact(&mut request),
        )
        .await??;
        Ok((request, socket))
    }

    /// Writes one length-prefixed response to a stub KDC connection.
    async fn write_tcp_response(socket: &mut TcpStream, response: &[u8]) -> io::Result<()> {
        let response_len = u32::try_from(response.len()).map_err(io::Error::other)?;
        bounded(
            Duration::from_secs(10),
            "TCP response header",
            socket.write_all(&response_len.to_be_bytes()),
        )
        .await??;
        bounded(
            Duration::from_secs(10),
            "TCP response body",
            socket.write_all(response),
        )
        .await?
    }

    /// Encodes the KRB-ERROR `KRB_ERR_RESPONSE_TOO_BIG` that pushes a UDP client to TCP.
    fn response_too_big_error() -> Result<Vec<u8>, TestError> {
        let error = KrbError {
            pvno: Integer::from(5_i32),
            msg_type: Integer::from(30_i32),
            ctime: None,
            cusec: None,
            stime: kerberos_time(1_893_553_440)?,
            susec: Integer::from(0_i32),
            error_code: KRB_ERR_RESPONSE_TOO_BIG,
            crealm: None,
            cname: None,
            realm: realm("TEST.GOKRB5")?,
            sname: rasn_principal(&["krbtgt", "TEST.GOKRB5"])?,
            e_text: Some(kerberos_string("response too big")?),
            e_data: None,
        };
        Ok(der::encode(&error).map_err(|cause| format!("KRB-ERROR encodes: {cause}"))?)
    }

    /// Encodes an unsigned KRB-ERROR whose `e-data` carries the kpasswd result `code` and `text`.
    fn kpasswd_result_krb_error(code: u16, text: &str) -> Result<Vec<u8>, TestError> {
        let mut e_data = Vec::with_capacity(text.len().saturating_add(2));
        e_data.extend_from_slice(&code.to_be_bytes());
        e_data.extend_from_slice(text.as_bytes());

        let error = KrbError {
            pvno: Integer::from(5_i32),
            msg_type: Integer::from(30_i32),
            ctime: None,
            cusec: None,
            stime: kerberos_time(1_893_553_440)?,
            susec: Integer::from(0_i32),
            error_code: KRB_ERR_RESPONSE_TOO_BIG,
            crealm: None,
            cname: None,
            realm: realm("TEST.GOKRB5")?,
            sname: rasn_principal(&["kadmin", "changepw"])?,
            e_text: Some(kerberos_string(text)?),
            e_data: Some(e_data.into()),
        };
        Ok(der::encode(&error).map_err(|cause| format!("KRB-ERROR encodes: {cause}"))?)
    }

    /// Frames `body` as a kpasswd reply with the given AP-REP length.
    fn kpasswd_reply_frame(ap_rep_length: u16, body: &[u8]) -> Result<Vec<u8>, TestError> {
        let message_length = KPASSWD_HEADER_LEN
            .checked_add(body.len())
            .ok_or("kpasswd reply length overflows")?;
        let length_field = u16::try_from(message_length)?;

        let mut frame = Vec::with_capacity(message_length);
        frame.extend_from_slice(&length_field.to_be_bytes());
        frame.extend_from_slice(&1_u16.to_be_bytes());
        frame.extend_from_slice(&ap_rep_length.to_be_bytes());
        frame.extend_from_slice(body);
        Ok(frame)
    }

    /// Decodes a hex fixture, ignoring surrounding whitespace.
    fn decode_hex(input: &str) -> Result<Vec<u8>, TestError> {
        let trimmed = input.trim();
        assert!(trimmed.len().is_multiple_of(2), "hex input has even length");
        trimmed
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|&[hi, lo]| {
                let byte = hex_nibble(hi)?
                    .saturating_mul(16)
                    .saturating_add(hex_nibble(lo)?);
                Ok(u8::try_from(byte)?)
            })
            .collect()
    }

    /// Returns the value of one hex digit.
    fn hex_nibble(value: u8) -> Result<u32, TestError> {
        Ok(char::from(value)
            .to_digit(16)
            .ok_or_else(|| format!("invalid hex digit: {value}"))?)
    }

    /// Converts Unix seconds into a UTC `KerberosTime`.
    fn kerberos_time(seconds: i64) -> Result<KerberosTime, TestError> {
        let utc = DateTime::<Utc>::from_timestamp(seconds, 0).ok_or("valid time")?;
        let offset = FixedOffset::east_opt(0).ok_or("UTC offset exists")?;
        Ok(KerberosTime(utc.with_timezone(&offset)))
    }

    /// Builds an `NT-SRV-INST` principal name from its components.
    fn rasn_principal(components: &[&str]) -> Result<PrincipalName, TestError> {
        Ok(PrincipalName {
            r#type: 2,
            string: components
                .iter()
                .map(|component| kerberos_string(component))
                .collect::<Result<_, _>>()?,
        })
    }

    /// Builds a realm name.
    fn realm(value: &str) -> Result<Realm, TestError> {
        kerberos_string(value)
    }

    /// Builds a `KerberosString`, which must be IA5.
    fn kerberos_string(value: &str) -> Result<KerberosString, TestError> {
        Ok(KerberosString::try_from(value)
            .map_err(|cause| format!("valid KerberosString: {cause}"))?)
    }

    /// Builds the current-thread Tokio runtime the tests run on.
    fn runtime() -> io::Result<Runtime> {
        Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
    }

    /// Pins that a TCP login sends the preauthentication retry on the first connection.
    #[test]
    fn tcp_login_reuses_one_connection_for_the_preauth_retry() -> Result<(), TestError> {
        runtime()?.block_on(async {
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let addr = listener.local_addr()?;
            let server = tokio::spawn(async move {
                let (mut socket, _) = bounded(
                    Duration::from_secs(10),
                    "preauthentication TCP connection",
                    listener.accept(),
                )
                .await??;
                let first = read_framed(&mut socket).await?;
                write_framed(&mut socket, &preauth_required_error()?).await?;
                let second = read_framed(&mut socket).await?;
                write_framed(&mut socket, b"not-an-as-rep").await?;
                let reconnected = timeout(Duration::from_millis(250), listener.accept())
                    .await
                    .is_ok();
                Ok::<_, TestError>((first.len(), second.len(), reconnected))
            });

            // The stub second reply is not a decodable AS-REP, so the login fails.
            // The connection count is what is under test, not the login outcome.
            drop(login_over_tcp(addr).await.err());

            let (first_len, second_len, reconnected) =
                bounded(Duration::from_secs(10), "preauth peer task", server).await???;
            assert!(first_len > 0, "KDC received the bare AS-REQ");
            assert!(
                second_len > 0,
                "KDC received the preauth retry on the same connection"
            );
            assert!(
                !reconnected,
                "preauth retry must not open a second connection"
            );
            Ok::<_, TestError>(())
        })
    }

    /// Pins that after the UDP fall-back to TCP the preauthentication retry reuses that stream.
    #[test]
    fn auto_login_reuses_the_stream_after_the_udp_fall_back_to_tcp() -> Result<(), TestError> {
        runtime()?.block_on(async {
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let addr = listener.local_addr()?;
            let server = tokio::spawn(async move {
                let (mut socket, _) = bounded(
                    Duration::from_secs(10),
                    "Auto TCP connection",
                    listener.accept(),
                )
                .await??;
                let first = read_framed(&mut socket).await?;
                write_framed(&mut socket, &preauth_required_error()?).await?;
                let second = read_framed(&mut socket).await?;
                write_framed(&mut socket, b"not-an-as-rep").await?;
                let reconnected = timeout(Duration::from_millis(250), listener.accept())
                    .await
                    .is_ok();
                Ok::<_, TestError>((first.len(), second.len(), reconnected))
            });

            // No UDP socket answers on this port, so the Auto leg falls back to
            // TCP; the retry must ride that same connection.
            drop(login_over(addr, KdcProtocol::Auto).await.err());

            let (first_len, second_len, reconnected) =
                bounded(Duration::from_secs(10), "Auto preauth peer task", server).await???;
            assert!(
                first_len > 0,
                "KDC received the AS-REQ after the UDP fallback"
            );
            assert!(second_len > 0, "preauth retry must ride the pinned stream");
            assert!(
                !reconnected,
                "preauth retry must not open a second connection"
            );
            Ok::<_, TestError>(())
        })
    }

    /// Pins that a retry after the KDC closed the stream opens a fresh connection.
    #[test]
    fn tcp_login_reconnects_when_the_kdc_closes_the_stream() -> Result<(), TestError> {
        runtime()?.block_on(async {
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let addr = listener.local_addr()?;
            let server = tokio::spawn(async move {
                let (mut socket, _) = bounded(
                    Duration::from_secs(10),
                    "initial TCP connection",
                    listener.accept(),
                )
                .await??;
                drop(read_framed(&mut socket).await?);
                write_framed(&mut socket, &preauth_required_error()?).await?;
                // RFC 4120 section 7.2.2 allows the KDC to close here.
                drop(socket);

                let (mut retry_socket, _) = bounded(
                    Duration::from_secs(10),
                    "retry TCP connection",
                    listener.accept(),
                )
                .await??;
                let retry = read_framed(&mut retry_socket).await?;
                write_framed(&mut retry_socket, b"not-an-as-rep").await?;
                Ok::<_, TestError>(retry.len())
            });

            drop(login_over_tcp(addr).await.err());

            let retry_len =
                bounded(Duration::from_secs(10), "reconnect peer task", server).await???;
            assert!(
                retry_len > 0,
                "closed stream must be retried on a fresh connection"
            );
            Ok::<_, TestError>(())
        })
    }

    /// Probe whether a live KDC leaves the TCP stream open for a follow-up request.
    ///
    /// RFC 4120 section 7.2.2 permits a KDC either to close the stream after a
    /// response or to keep it open for a follow-up, so the behaviour of any given
    /// KDC has to be measured. Sends two bare AS-REQs on one stream and reports
    /// whether the second is answered.
    ///
    /// Gated on `TEST_KDC_REUSE=1`. Reads `TEST_KDC_ADDR`, `TEST_KDC_PORT`,
    /// `TEST_KDC_REALM` and `TEST_KDC_USER`. Needs no credentials: a bare AS-REQ
    /// carries no preauthentication data and is answered with KRB-ERROR.
    #[test]
    fn live_kdc_tcp_stream_reuse_probe() -> Result<(), TestError> {
        if env::var("TEST_KDC_REUSE").as_deref() != Ok("1") {
            return Ok(());
        }

        let host = env::var("TEST_KDC_ADDR").map_err(|cause| format!("TEST_KDC_ADDR: {cause}"))?;
        let port: u16 = env::var("TEST_KDC_PORT")
            .unwrap_or_else(|_| "88".to_owned())
            .parse()?;
        let realm =
            env::var("TEST_KDC_REALM").map_err(|cause| format!("TEST_KDC_REALM: {cause}"))?;
        let user = env::var("TEST_KDC_USER").map_err(|cause| format!("TEST_KDC_USER: {cause}"))?;

        runtime()?.block_on(async {
            let connect_start = Instant::now();
            let mut stream = timeout(probe::PROBE_TIMEOUT, TcpStream::connect((host.as_str(), port))).await??;
            stream.set_nodelay(true)?;
            writeln!(
                io::stdout(),
                "handshake: {} ms",
                connect_start.elapsed().as_millis()
            )?;

            let first_start = Instant::now();
            let first = probe_exchange(&mut stream, &realm, &user, 1).await?;
            writeln!(
                io::stdout(),
                "request 1: {first} in {} ms",
                first_start.elapsed().as_millis()
            )?;
            assert!(
                matches!(
                    first,
                    ProbeOutcome::Answered {
                        len: _,
                        error_code: _
                    }
                ),
                "first exchange must reach the KDC: {first}"
            );

            let second_start = Instant::now();
            let second = probe_exchange(&mut stream, &realm, &user, 2).await?;
            writeln!(
                io::stdout(),
                "request 2: {second} in {} ms",
                second_start.elapsed().as_millis()
            )?;
            match &second {
                ProbeOutcome::Answered {
                    len: _,
                    error_code: _,
                } => writeln!(
                    io::stdout(),
                    "VERDICT: KDC reuses the stream; pinning the connection is worthwhile"
                )?,
                ProbeOutcome::Closed(reason) => writeln!(
                    io::stdout(),
                    "VERDICT: KDC closed the stream ({reason}); pinning gains nothing against this KDC"
                )?,
            }
            Ok::<_, TestError>(())
        })
    }

    /// Drive a password TGT login over TCP against a stub KDC.
    async fn login_over_tcp(addr: SocketAddr) -> Result<(), ClientError> {
        login_over(addr, KdcProtocol::Tcp).await
    }

    /// Drive a password TGT login over the given protocol against a stub KDC.
    async fn login_over(addr: SocketAddr, protocol: KdcProtocol) -> Result<(), ClientError> {
        let options = AsReq::new(SystemTime::now(), 1);
        Tokio::new()
            .with_timeout(Duration::from_secs(2))
            .login_tgt_with_password(
                protocol,
                addr,
                Principal::user("TEST.GOKRB5", "testuser1"),
                b"password",
                options,
            )
            .await
            .map(|_| ())
    }

    /// Read one RFC 4120 framed message from a stub KDC connection.
    async fn read_framed(socket: &mut TcpStream) -> Result<Vec<u8>, TestError> {
        let mut header = [0; 4];
        let _: usize = bounded(
            Duration::from_secs(10),
            "framed header",
            socket.read_exact(&mut header),
        )
        .await??;
        let mut body = vec![0; usize::try_from(u32::from_be_bytes(header))?];
        let _: usize = bounded(
            Duration::from_secs(10),
            "framed body",
            socket.read_exact(&mut body),
        )
        .await??;
        Ok(body)
    }

    /// Write one RFC 4120 framed message from a stub KDC connection.
    async fn write_framed(socket: &mut TcpStream, body: &[u8]) -> Result<(), TestError> {
        bounded(
            Duration::from_secs(10),
            "framed response header",
            socket.write_all(&u32::try_from(body.len())?.to_be_bytes()),
        )
        .await??;
        bounded(
            Duration::from_secs(10),
            "framed response body",
            socket.write_all(body),
        )
        .await??;
        Ok(())
    }

    /// Build a `KDC_ERR_PREAUTH_REQUIRED` carrying an ETYPE-INFO2 hint for AES256.
    ///
    /// Drives the client into the second phase of the AS exchange, which is the
    /// request that should reuse the connection.
    fn preauth_required_error() -> Result<Vec<u8>, TestError> {
        let etype_info2 = rasn_kerberos::EtypeInfo2::from([rasn_kerberos::EtypeInfo2Entry {
            etype: 18,
            salt: Some(kerberos_string("TEST.GOKRB5testuser1")?),
            s2kparams: None,
        }]);
        let method_data = rasn_kerberos::MethodData::from([rasn_kerberos::PaData {
            r#type: PA_ETYPE_INFO2,
            value: der::encode(&etype_info2)
                .map_err(|cause| format!("ETYPE-INFO2 encodes: {cause}"))?
                .into(),
        }]);
        let error = KrbError {
            pvno: Integer::from(5_i32),
            msg_type: Integer::from(30_i32),
            ctime: None,
            cusec: None,
            stime: kerberos_time(1_893_553_440)?,
            susec: Integer::from(0_i32),
            error_code: 25,
            crealm: Some(realm("TEST.GOKRB5")?),
            cname: Some(rasn_principal(&["testuser1"])?),
            realm: realm("TEST.GOKRB5")?,
            sname: rasn_principal(&["krbtgt", "TEST.GOKRB5"])?,
            e_text: None,
            e_data: Some(
                der::encode(&method_data)
                    .map_err(|cause| format!("METHOD-DATA encodes: {cause}"))?
                    .into(),
            ),
        };
        Ok(der::encode(&error).map_err(|cause| format!("KRB-ERROR encodes: {cause}"))?)
    }

    /// Result of one framed request/response attempt against a live KDC.
    enum ProbeOutcome {
        /// KDC answered. Carries the response length and KRB-ERROR code when present.
        Answered { len: usize, error_code: Option<i32> },
        /// KDC did not answer and the stream is unusable.
        Closed(String),
    }

    impl fmt::Display for ProbeOutcome {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::Answered {
                    len,
                    error_code: Some(code),
                } => write!(f, "answered, {len} bytes, error code {code}"),
                Self::Answered {
                    len,
                    error_code: None,
                } => write!(f, "answered, {len} bytes, no error code"),
                Self::Closed(reason) => write!(f, "closed: {reason}"),
            }
        }
    }

    /// Read the `error-code` field out of a DER-encoded KRB-ERROR, if the response is one.
    fn krb_error_code(response: &[u8]) -> Option<i32> {
        der::decode::<KrbError>(response)
            .ok()
            .map(|error| error.error_code)
    }
}
