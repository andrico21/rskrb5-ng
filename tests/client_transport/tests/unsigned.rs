//! Unsigned outcomes through both public checked helpers.

use super::*;

/// Bare and framed unsigned results remain unknown after exactly one delivery.
#[test]
fn unsigned_results_are_unknown_on_both_helpers() -> Result<(), TestError> {
    runtime()?.block_on(async {
        for configured in [false, true] {
            for framed in [false, true] {
                for code in [KPASSWD_SUCCESS, KPASSWD_AUTHERROR] {
                    // Given a peer replying with an unsigned success or refusal.
                    let listener = TcpListener::bind("127.0.0.1:0").await?;
                    let addr = listener.local_addr()?;
                    let config = config_with_kpasswd_servers([addr.to_string()], 1)?;
                    let (built, options) = kpasswd_context::request()?;
                    let bare = kpasswd_result_krb_error(code, "diagnostic text")?;
                    let response = if framed {
                        kpasswd_reply_frame(0, &bare)?
                    } else {
                        bare
                    };
                    let transport = Tokio::new().with_timeout(Duration::from_secs(1));
                    let server = async {
                        let (request, mut stream) = read_tcp_request(&listener).await?;
                        assert_eq!(request, built.der());
                        write_tcp_response(&mut stream, &response).await
                    };
                    // When either checked API receives the unauthenticated response.
                    let client = async {
                        if configured {
                            transport
                                .exchange_kpasswd_result_with_config(
                                    &config,
                                    KdcProtocol::Tcp,
                                    "TEST.GOKRB5",
                                    &built,
                                    &options,
                                )
                                .await
                        } else {
                            transport
                                .exchange_kpasswd_result(KdcProtocol::Tcp, addr, &built, &options)
                                .await
                        }
                    };
                    let (delivery, outcome) = tokio::join!(server, client);
                    delivery?;
                    // Then the immediate cause remains diagnostic, never a definite rejection.
                    match outcome {
                        Err(ClientError::KpasswdOutcomeUnknown(source)) => {
                            if code == KPASSWD_SUCCESS {
                                assert!(matches!(*source, ClientError::Kadmin(KadminError::UnauthenticatedSuccess)));
                            } else {
                                assert!(matches!(*source,
                                    ClientError::Kadmin(KadminError::UnauthenticatedRejection { code: actual, text_raw })
                                        if actual == code && text_raw == b"diagnostic text"));
                            }
                        }
                        other => {
                            return Err(format!("unsigned result was definite: {other:?}").into());
                        }
                    }
                    assert!(
                        timeout(Duration::from_millis(20), listener.accept())
                            .await
                            .is_err(),
                        "mutation repeated"
                    );
                }
            }
        }
        Ok(())
    })
}
