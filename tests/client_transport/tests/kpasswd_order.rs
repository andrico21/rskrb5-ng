//! Password change transport order: TCP first, UDP only after a definite TCP failure.

use tokio::task::JoinHandle;

use super::*;

/// Request bytes of every exchange in this module.
const REQUEST: &[u8] = b"mutation";

/// Render a transport result for assertion messages (`Debug` redacts the error).
fn describe<T>(result: &Result<T, ClientError>) -> String {
    result
        .as_ref()
        .map_or_else(ToString::to_string, |_| "Ok".to_owned())
}

/// Convert a transport error into a displayable test error.
fn shown<T>(result: Result<T, ClientError>) -> Result<T, TestError> {
    result.map_err(|error| error.to_string().into())
}

/// Transport with a deadline short enough for the unanswered-datagram cases.
fn transport() -> Tokio {
    Tokio::new().with_timeout(Duration::from_millis(300))
}

/// A UDP socket and a TCP listener whose shared loopback port is then closed for both.
async fn closed_port() -> Result<String, TestError> {
    let (udp, listener) = bind_udp_and_tcp_pair().await?;
    let addr = udp.local_addr()?.to_string();
    drop((udp, listener));
    Ok(addr)
}

/// Assert that no datagram reaches `udp` shortly after the exchange completed.
async fn assert_no_datagram(udp: &UdpSocket, what: &str) {
    let mut datagram = [0; 64];
    assert!(
        timeout(Duration::from_millis(50), udp.recv(&mut datagram))
            .await
            .is_err(),
        "{what}: a datagram reached the UDP port"
    );
}

/// Answer exactly one datagram and report how many bytes it carried.
fn udp_responder(
    udp: UdpSocket,
    reply: impl AsRef<[u8]> + Send + 'static,
) -> JoinHandle<io::Result<(UdpSocket, usize)>> {
    tokio::spawn(async move {
        // Larger than any request here: Windows fails a receive into a smaller buffer.
        let mut bytes = [0; 2048];
        let (length, client) = bounded(
            Duration::from_secs(10),
            "password UDP datagram",
            udp.recv_from(&mut bytes),
        )
        .await??;
        let _: usize = udp.send_to(reply.as_ref(), client).await?;
        Ok((udp, length))
    })
}

/// A live TCP server is used and the UDP port never sees a datagram.
#[test]
fn kpasswd_auto_uses_tcp_first_and_sends_no_datagram() -> Result<(), TestError> {
    runtime()?.block_on(async {
        // Given a live TCP server and an observed UDP port on the same address.
        let (udp, listener) = bind_udp_and_tcp_pair().await?;
        let config = config_with_kpasswd_servers([udp.local_addr()?.to_string()], 1465)?;
        let server = tokio::spawn(async move {
            let (request, mut socket) = read_tcp_request(&listener).await?;
            write_tcp_response(&mut socket, b"tcp-reply").await?;
            Ok::<_, io::Error>(request)
        });
        // When an Auto password request is small enough for UDP to be preferred.
        let result = transport()
            .send_to_kpasswd_realm(&config, KdcProtocol::Auto, "TEST.GOKRB5", REQUEST)
            .await;
        // Then TCP delivers it and no datagram is sent.
        assert_eq!(shown(result)?, b"tcp-reply");
        assert_eq!(
            bounded(Duration::from_secs(10), "TCP peer", server).await???,
            REQUEST
        );
        assert_no_datagram(&udp, "TCP success").await;
        Ok(())
    })
}

/// A refused TCP connection is definite, so exactly one datagram goes over UDP.
#[test]
fn kpasswd_auto_falls_back_to_one_datagram_after_tcp_refusal() -> Result<(), TestError> {
    runtime()?.block_on(async {
        // Given a closed TCP port and a live UDP responder.
        let (udp, listener) = bind_udp_and_tcp_pair().await?;
        drop(listener);
        let config = config_with_kpasswd_servers([udp.local_addr()?.to_string()], 1465)?;
        let responder = udp_responder(udp, b"udp-reply");
        // When the Auto request runs.
        let result = transport()
            .send_to_kpasswd_realm(&config, KdcProtocol::Auto, "TEST.GOKRB5", REQUEST)
            .await;
        // Then UDP answers after a single datagram and no retransmit follows.
        assert_eq!(shown(result)?, b"udp-reply");
        let (peer, length) =
            bounded(Duration::from_secs(10), "UDP responder", responder).await???;
        assert_eq!(length, REQUEST.len());
        assert_no_datagram(&peer, "retransmit").await;
        Ok(())
    })
}

/// Every endpoint refusing both protocols is a definite, retryable failure.
#[test]
fn kpasswd_auto_both_protocols_refused_is_endpoint_failures() -> Result<(), TestError> {
    runtime()?.block_on(async {
        // Given a port closed for TCP and UDP.
        let config = config_with_kpasswd_servers([closed_port().await?], 1465)?;
        // When the Auto request runs.
        let result = transport()
            .send_to_kpasswd_realm(&config, KdcProtocol::Auto, "TEST.GOKRB5", REQUEST)
            .await;
        // Then the failure is definite, not an unknown outcome.
        assert!(
            matches!(
                result,
                Err(ClientError::KdcEndpointFailures {
                    realm: _,
                    protocol: _,
                    failures: _
                })
            ),
            "expected KdcEndpointFailures, got {}",
            describe(&result)
        );
        Ok(())
    })
}

/// A TCP request that may have been delivered is never repeated over UDP.
#[test]
fn kpasswd_auto_unknown_tcp_outcome_never_tries_udp() -> Result<(), TestError> {
    runtime()?.block_on(async {
        // Given a TCP server that reads the request and drops the connection.
        let (udp, listener) = bind_udp_and_tcp_pair().await?;
        let config = config_with_kpasswd_servers([udp.local_addr()?.to_string()], 1465)?;
        let server = tokio::spawn(async move {
            let (request, socket) = read_tcp_request(&listener).await?;
            drop(socket);
            Ok::<_, io::Error>(request)
        });
        // When the Auto request runs.
        let result = transport()
            .send_to_kpasswd_realm(&config, KdcProtocol::Auto, "TEST.GOKRB5", REQUEST)
            .await;
        // Then the outcome is unknown and the UDP socket received nothing.
        assert!(
            matches!(result, Err(ClientError::KpasswdOutcomeUnknown(_))),
            "expected KpasswdOutcomeUnknown, got {}",
            describe(&result)
        );
        assert_no_datagram(&udp, "unknown TCP outcome").await;
        assert_eq!(
            bounded(Duration::from_secs(10), "TCP peer", server).await???,
            REQUEST
        );
        Ok(())
    })
}

/// A UDP peer that never answers leaves the outcome unknown, after one datagram.
#[test]
fn kpasswd_auto_silent_udp_peer_is_unknown() -> Result<(), TestError> {
    runtime()?.block_on(async {
        // Given a closed TCP port and a UDP peer that reads but never replies.
        let (udp, listener) = bind_udp_and_tcp_pair().await?;
        drop(listener);
        let config = config_with_kpasswd_servers([udp.local_addr()?.to_string()], 1465)?;
        // When the Auto request runs.
        let result = transport()
            .send_to_kpasswd_realm(&config, KdcProtocol::Auto, "TEST.GOKRB5", REQUEST)
            .await;
        // Then the single datagram arrived and the outcome is unknown.
        assert!(
            matches!(result, Err(ClientError::KpasswdOutcomeUnknown(_))),
            "expected KpasswdOutcomeUnknown, got {}",
            describe(&result)
        );
        let mut datagram = [0; 64];
        let length = bounded(
            Duration::from_secs(10),
            "UDP datagram",
            udp.recv(&mut datagram),
        )
        .await??;
        assert_eq!(length, REQUEST.len());
        assert_no_datagram(&udp, "retransmit").await;
        Ok(())
    })
}

/// An explicit UDP request to a closed port is a definite endpoint failure.
#[test]
fn kpasswd_explicit_udp_refusal_is_definite() -> Result<(), TestError> {
    runtime()?.block_on(async {
        // Given a port closed for UDP.
        let config = config_with_kpasswd_servers([closed_port().await?], 1465)?;
        // When the explicit UDP request runs.
        let result = transport()
            .send_to_kpasswd_realm(&config, KdcProtocol::Udp, "TEST.GOKRB5", REQUEST)
            .await;
        // Then the port-unreachable reply is a plain endpoint failure.
        assert!(
            matches!(
                result,
                Err(ClientError::KdcEndpointFailures {
                    realm: _,
                    protocol: _,
                    failures: _
                })
            ),
            "expected KdcEndpointFailures, got {}",
            describe(&result)
        );
        Ok(())
    })
}

/// All TCP endpoints are tried before any UDP endpoint.
#[test]
fn kpasswd_auto_tries_all_tcp_endpoints_before_udp() -> Result<(), TestError> {
    runtime()?.block_on(async {
        // Given endpoint one with TCP closed and UDP live, and endpoint two with TCP live.
        let (udp_one, listener_one) = bind_udp_and_tcp_pair().await?;
        drop(listener_one);
        let (udp_two, listener_two) = bind_udp_and_tcp_pair().await?;
        let config = config_with_kpasswd_servers(
            [
                udp_one.local_addr()?.to_string(),
                udp_two.local_addr()?.to_string(),
            ],
            1465,
        )?;
        let server = tokio::spawn(async move {
            let (request, mut socket) = read_tcp_request(&listener_two).await?;
            write_tcp_response(&mut socket, b"tcp-two").await?;
            Ok::<_, io::Error>(request)
        });
        // When the Auto request runs.
        let result = transport()
            .send_to_kpasswd_realm(&config, KdcProtocol::Auto, "TEST.GOKRB5", REQUEST)
            .await;
        // Then endpoint two answers over TCP and no UDP port is used.
        assert_eq!(shown(result)?, b"tcp-two");
        assert_eq!(
            bounded(Duration::from_secs(10), "TCP peer", server).await???,
            REQUEST
        );
        assert_no_datagram(&udp_one, "first endpoint").await;
        assert_no_datagram(&udp_two, "second endpoint").await;
        Ok(())
    })
}

/// The explicit-address Auto arm is TCP first as well.
#[test]
fn kpasswd_explicit_address_auto_uses_tcp_first() -> Result<(), TestError> {
    runtime()?.block_on(async {
        // Given a live TCP server and an observed UDP port on the same address.
        let (udp, listener) = bind_udp_and_tcp_pair().await?;
        let addr = udp.local_addr()?;
        let request = KpasswdRequest::parse(&decode_hex(MARSHALLED_KPASSWD_REQ)?)?;
        let reply = kpasswd_reply_frame(0, &response_too_big_error()?)?;
        let server = tokio::spawn(async move {
            let (_request, mut socket) = read_tcp_request(&listener).await?;
            write_tcp_response(&mut socket, &reply).await
        });
        // When an Auto request goes to the explicit address.
        let result = transport()
            .exchange_kpasswd_request(KdcProtocol::Auto, addr, &request)
            .await;
        // Then TCP answers and no datagram is sent.
        assert!(shown(result)?.is_krb_error());
        bounded(Duration::from_secs(10), "TCP peer", server).await???;
        assert_no_datagram(&udp, "explicit TCP success").await;
        Ok(())
    })
}

/// A refused TCP connection to an explicit address is definite, so one datagram goes over UDP.
#[test]
fn kpasswd_explicit_address_auto_falls_back_to_udp_after_tcp_refusal() -> Result<(), TestError> {
    runtime()?.block_on(async {
        // Given a closed TCP port and a live UDP responder on the same address.
        let (udp, listener) = bind_udp_and_tcp_pair().await?;
        drop(listener);
        let addr = udp.local_addr()?;
        let request = KpasswdRequest::parse(&decode_hex(MARSHALLED_KPASSWD_REQ)?)?;
        let responder = udp_responder(udp, kpasswd_reply_frame(0, &response_too_big_error()?)?);
        // When an Auto request goes to the explicit address.
        let result = transport()
            .exchange_kpasswd_request(KdcProtocol::Auto, addr, &request)
            .await;
        // Then UDP answers after a single datagram and no retransmit follows.
        assert!(shown(result)?.is_krb_error());
        let (peer, length) =
            bounded(Duration::from_secs(10), "UDP responder", responder).await???;
        assert_eq!(length, request.encode()?.len());
        assert_no_datagram(&peer, "explicit UDP fallback retransmit").await;
        Ok(())
    })
}

/// An explicit-address Auto request never repeats a possibly delivered TCP request over UDP.
#[test]
fn kpasswd_explicit_address_auto_unknown_tcp_outcome_never_tries_udp() -> Result<(), TestError> {
    runtime()?.block_on(async {
        // Given a TCP server that reads the request and drops the connection, and an observed UDP port.
        let (udp, listener) = bind_udp_and_tcp_pair().await?;
        let addr = udp.local_addr()?;
        let request = KpasswdRequest::parse(&decode_hex(MARSHALLED_KPASSWD_REQ)?)?;
        let server = tokio::spawn(async move {
            let (_request, socket) = read_tcp_request(&listener).await?;
            drop(socket);
            Ok::<_, io::Error>(())
        });
        // When an Auto request goes to the explicit address.
        let result = transport()
            .exchange_kpasswd_request(KdcProtocol::Auto, addr, &request)
            .await;
        // Then the outcome is unknown and the UDP socket received nothing.
        assert!(
            matches!(result, Err(ClientError::KpasswdOutcomeUnknown(_))),
            "expected KpasswdOutcomeUnknown, got {}",
            describe(&result)
        );
        bounded(Duration::from_secs(10), "TCP peer", server).await???;
        assert_no_datagram(&udp, "explicit unknown TCP outcome").await;
        Ok(())
    })
}

/// The explicit-address Auto arm reports a definite failure when both protocols refuse.
#[test]
fn kpasswd_explicit_address_auto_both_refused_is_definite() -> Result<(), TestError> {
    runtime()?.block_on(async {
        // Given a port closed for TCP and UDP.
        let addr = closed_port().await?;
        let request = KpasswdRequest::parse(&decode_hex(MARSHALLED_KPASSWD_REQ)?)?;
        // When the explicit-address Auto request runs.
        let result = transport()
            .exchange_kpasswd_request(KdcProtocol::Auto, addr, &request)
            .await;
        // Then the failure is a plain I/O error, not an unknown outcome.
        assert!(
            matches!(result, Err(ClientError::Io(_))),
            "expected Io, got {}",
            describe(&result)
        );
        Ok(())
    })
}
