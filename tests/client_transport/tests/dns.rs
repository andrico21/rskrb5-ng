//! DNS protocol and target failover regressions.

use hickory_resolver::proto::op::ResponseCode;

use super::*;

/// Root SRV targets produce the precise unavailable-service error.
#[test]
fn root_srv_error_is_precise() -> Result<(), TestError> {
    runtime()?.block_on(async {
        // Given an authoritative root target for password service discovery.
        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        let server = socket.local_addr()?;
        let task = tokio::spawn(dns_admin_fixture(socket, Some(Name::root())));
        let config = Config::parse("[libdefaults]\ndns_lookup_kdc = true\n")?;
        // When discovery runs, then it reports unavailable, not a generic lookup failure.
        let result = Tokio::new()
            .with_dns_server(&server.to_string())?
            .discover_kpasswd_servers(&config, "TEST.GOKRB5", KdcProtocol::Tcp)
            .await;
        stop(task).await?;
        assert!(
            matches!(result, Err(ClientError::DnsServiceUnavailable { service, realm })
            if service == "_kpasswd" && realm == "TEST.GOKRB5")
        );
        Ok(())
    })
}

/// Reserved KDC record marks are classified before attempting a body read.
#[test]
fn reserved_record_error_is_precise() -> Result<(), TestError> {
    runtime()?.block_on(async {
        // Given a peer advertising a reserved-bit response length.
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let peer = async {
            let (_request, mut stream) = read_tcp_request(&listener).await?;
            stream.write_all(&0x8000_0001_u32.to_be_bytes()).await?;
            Ok::<_, TestError>(())
        };
        let transport = Tokio::new();
        // When the transport reads the mark, then it returns the named framing error.
        let (sent, result) = tokio::join!(peer, transport.send_tcp(addr, &[1]));
        sent?;
        assert!(matches!(result, Err(ClientError::TcpReservedBitSet)));
        Ok(())
    })
}

/// A failed SRV target does not suppress another usable target in either service.
#[test]
fn srv_target_failure_keeps_usable_peers() -> Result<(), TestError> {
    runtime()?.block_on(async {
        for bad_first in [false, true] {
            for password in [false, true] {
                // Given ordered SRV records with one NXDOMAIN target and one usable literal.
                let socket = UdpSocket::bind("127.0.0.1:0").await?;
                let server = socket.local_addr()?;
                let fixture = tokio::spawn(async move {
                    for _ in 0_u8..16 {
                        let mut buffer = [0; 4096];
                        let (length, peer) = bounded(
                            Duration::from_secs(10),
                            "SRV fixture query",
                            socket.recv_from(&mut buffer),
                        )
                        .await??;
                        let request = Message::from_vec(buffer.get(..length).ok_or("DNS length")?)?;
                        let query = request.queries.first().ok_or("DNS question")?;
                        let mut response =
                            Message::response(request.metadata.id, request.metadata.op_code);
                        response.metadata.authoritative = true;
                        response.queries = request.queries.clone();
                        if query.query_type() == RecordType::SRV {
                            for (priority, target) in [
                                (u16::from(!bad_first), "missing.test.gokrb5."),
                                (u16::from(bad_first), "127.0.0.1."),
                            ] {
                                response.answers.push(Record::from_rdata(
                                    query.name().clone(),
                                    60,
                                    RData::SRV(SRV::new(
                                        priority,
                                        0,
                                        1464,
                                        Name::from_ascii(target)?,
                                    )),
                                ));
                            }
                        } else {
                            response.metadata.response_code = ResponseCode::NXDomain;
                        }
                        let _: usize = socket.send_to(&response.to_vec()?, peer).await?;
                    }
                    Ok::<(), TestError>(())
                });
                let config = Config::parse("[libdefaults]\ndns_lookup_kdc = true\n")?;
                let transport = Tokio::new().with_dns_server(&server.to_string())?;
                // When discovery resolves the ordered targets for either service.
                let operation = async {
                    if password {
                        transport
                            .discover_kpasswd_servers(&config, "TEST.GOKRB5", KdcProtocol::Tcp)
                            .await
                    } else {
                        transport
                            .discover_kdcs(&config, "TEST.GOKRB5", KdcProtocol::Tcp)
                            .await
                    }
                };
                let result = timeout(Duration::from_secs(2), operation).await;
                stop(fixture).await?;
                // Then the usable target remains available regardless of selected order.
                let endpoints = result??;
                assert_eq!(endpoints.len(), 1);
                assert_eq!(
                    endpoints.first().ok_or("usable endpoint")?.authority(),
                    "127.0.0.1:1464"
                );
            }
        }
        Ok(())
    })
}

/// UDP password discovery uses the administrative service's TCP SRV record.
#[test]
fn udp_password_discovers_admin_tcp_service() -> Result<(), TestError> {
    runtime()?.block_on(async {
        // Given a DNS peer that advertises only the administrative TCP service.
        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        let server = socket.local_addr()?;
        let fixture = tokio::spawn(async move {
            for _ in 0_u8..8 {
                let mut buffer = [0; 4096];
                let (length, peer) = bounded(
                    Duration::from_secs(10),
                    "admin DNS query",
                    socket.recv_from(&mut buffer),
                )
                .await??;
                let request = Message::from_vec(buffer.get(..length).ok_or("DNS length")?)?;
                let query = request.queries.first().ok_or("DNS question")?;
                let mut response = Message::response(request.metadata.id, request.metadata.op_code);
                response.metadata.authoritative = true;
                response.queries = request.queries.clone();
                assert!(
                    !query
                        .name()
                        .to_utf8()
                        .eq_ignore_ascii_case("_kerberos-adm._udp.TEST.GOKRB5."),
                    "administration has no UDP service"
                );
                if query.query_type() == RecordType::SRV
                    && query
                        .name()
                        .to_utf8()
                        .eq_ignore_ascii_case("_kerberos-adm._tcp.TEST.GOKRB5.")
                {
                    response.answers.push(Record::from_rdata(
                        query.name().clone(),
                        60,
                        RData::SRV(SRV::new(0, 0, 749, Name::from_ascii("127.0.0.1.")?)),
                    ));
                }
                let _: usize = socket.send_to(&response.to_vec()?, peer).await?;
            }
            Ok::<(), TestError>(())
        });
        let config = Config::parse("[libdefaults]\ndns_lookup_kdc = true\n")?;
        let transport = Tokio::new().with_dns_server(&server.to_string())?;
        // When UDP password discovery falls back to administration SRV.
        let result = timeout(
            Duration::from_secs(2),
            transport.discover_kpasswd_servers(&config, "TEST.GOKRB5", KdcProtocol::Udp),
        )
        .await;
        stop(fixture).await?;
        let outcome = result??;
        // Then the host is retained but the password port and protocol are selected.
        assert_eq!(outcome.len(), 1);
        let endpoint = outcome.first().ok_or("password endpoint")?;
        assert_eq!(endpoint.authority(), "127.0.0.1:464");
        assert_eq!(endpoint.protocol, KdcProtocol::Udp);
        Ok(())
    })
}
