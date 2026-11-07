//! Configured preauthentication connection reuse.

use rskrb5_ng::keytab::{Keytab, Principal as KeytabPrincipal};

use super::*;

/// Pins that the Auto protocol goes straight to TCP under `udp_preference_limit = 1`.
#[test]
fn tokio_transport_auto_honors_tcp_first_udp_preference_limit() -> Result<(), TestError> {
    runtime()?.block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let udp = UdpSocket::bind(addr).await?;
        let config = config_with_kdcs_and_udp_limit([addr.to_string()], 1)?;
        let task = tokio::spawn(async move {
            let (request, mut socket) = read_tcp_request(&listener).await?;
            assert_eq!(request, b"auto-config-as-req");
            write_tcp_response(&mut socket, b"auto-config-tcp-as-rep").await
        });

        let response = Tokio::new()
            .with_timeout(Duration::from_secs(2))
            .send_to_realm(
                &config,
                KdcProtocol::Auto,
                "TEST.GOKRB5",
                b"auto-config-as-req",
            )
            .await?;

        bounded(Duration::from_secs(10), "TCP-first peer task", task).await???;
        assert_eq!(response, b"auto-config-tcp-as-rep");
        let mut datagram = [0; 64];
        assert!(
            timeout(Duration::from_millis(20), udp.recv(&mut datagram))
                .await
                .is_err(),
            "TCP-first request unexpectedly probed UDP"
        );
        Ok::<_, TestError>(())
    })
}

/// Configured password and keytab Auto logins reuse the TCP winner on both preference paths.
#[test]
fn configured_auto_logins_reuse_connection() -> Result<(), TestError> {
    runtime()?.block_on(async {
        for limit in [1_u16, 1465] {
            for keytab in [false, true] {
                // Given a TCP KDC requiring a second AS request and no UDP listener.
                let listener = TcpListener::bind("127.0.0.1:0").await?;
                let addr = listener.local_addr()?;
                let config = Config::parse(&format!("[libdefaults]\ndns_lookup_kdc = false\nudp_preference_limit = {limit}\n[realms]\nTEST.GOKRB5 = {{\nkdc = {addr}\n}}\n"))?;
                let transport = Tokio::new().with_timeout(Duration::from_millis(200));
                let fixture = async {
                    let (mut stream, _) = bounded(Duration::from_secs(10), "configured login connection", listener.accept()).await??;
                    drop(read_framed(&mut stream).await?);
                    write_framed(&mut stream, &preauth_required_error()?).await?;
                    let second = timeout(Duration::from_secs(1), read_framed(&mut stream)).await??;
                    write_framed(&mut stream, b"invalid-as-rep").await?;
                    assert!(!second.is_empty(), "preauthentication request missing");
                    assert!(timeout(Duration::from_millis(20), listener.accept()).await.is_err(), "second connection opened");
                    Ok::<_, TestError>(())
                };
                // When the configured login runs through either credential path.
                let login = async {
                    let principal = Principal::user("TEST.GOKRB5", "testuser1");
                    let options = AsReq::new(SystemTime::now(), 1);
                    if keytab {
                        let mut keys = Keytab::new();
                        keys.add_entry_from_password(
                            KeytabPrincipal::new("TEST.GOKRB5", 1, ["testuser1"]),
                            b"password".to_vec().into(), SystemTime::now(), 1, 18,
                        )?;
                        drop(transport.login_tgt_with_keytab_config(&config, KdcProtocol::Auto, principal, &keys, options).await);
                    } else {
                        drop(transport.login_tgt_with_password_config(&config, KdcProtocol::Auto, principal, b"password", options).await);
                    }
                    Ok::<_, TestError>(())
                };
                // Then the peer sees the follow-up on the original stream.
                let (exchange, result) = tokio::join!(fixture, login);
                exchange?;
                result?;
            }
        }
        Ok(())
    })
}
