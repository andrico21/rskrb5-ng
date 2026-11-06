//! Checked password result regressions.

use super::*;

/// A generic resolver input does not need the obsolete Clone bound.
#[test]
fn password_address_bound_is_resolver_only() -> Result<(), TestError> {
    // Given an address constrained only by ToSocketAddrs, compile both APIs without sending.
    kpasswd_context::address_contract("127.0.0.1:464")
}

/// Both checked transport helpers must reject invalid contexts after one delivery.
#[test]
fn checked_helpers_reject_invalid_contexts() -> Result<(), TestError> {
    runtime()?.block_on(async {
        use super::kpasswd_context::{self, ReplyCase};
        for configured in [false, true] {
            for case in [ReplyCase::BadApRep, ReplyCase::WrongApRepTime, ReplyCase::MissingFreshness,
                ReplyCase::WrongSequence, ReplyCase::WrongAddress, ReplyCase::StaleTime,
                ReplyCase::WrongKey, ReplyCase::Reflection] {
                // Given a peer returning one independently corrupted reply.
                let listener = TcpListener::bind("127.0.0.1:0").await?;
                let addr = listener.local_addr()?;
                let config = config_with_kpasswd_servers([addr.to_string()], 1)?;
                let (built, options) = kpasswd_context::request()?;
                let response = kpasswd_context::reply(&built, case)?;
                let transport = Tokio::new().with_timeout(Duration::from_secs(1));
                let server = async {
                    let (_request, mut stream) = read_tcp_request(&listener).await?;
                    write_tcp_response(&mut stream, &response).await?;
                    Ok::<_, TestError>(())
                };
                // When either public checked helper consumes the delivered response.
                let client = async {
                    if configured {
                        transport.exchange_kpasswd_result_with_config(&config, KdcProtocol::Tcp, "TEST.GOKRB5", &built, &options).await
                    } else {
                        transport.exchange_kpasswd_result(KdcProtocol::Tcp, addr, &built, &options).await
                    }
                };
                let (delivery, result) = tokio::join!(server, client);
                delivery?;
                // Then exactly one unknown-outcome wrapper replaces any credential verdict.
                let error = result.err().ok_or("invalid checked context accepted")?;
                assert!(matches!(&error, ClientError::KpasswdOutcomeUnknown(source) if !matches!(**source, ClientError::KpasswdOutcomeUnknown(_))));
                assert!(!format!("{error} {error:?}").contains("reflection-password-canary"));
                assert!(timeout(Duration::from_millis(20), listener.accept()).await.is_err(), "mutation retried");
            }
        }
        Ok(())
    })
}

/// Valid contextual replies and server-selected subkeys remain usable.
#[test]
fn checked_reply_fixtures_are_valid() -> Result<(), TestError> {
    use super::kpasswd_context::{self, ReplyCase};
    runtime()?.block_on(async {
        for configured in [false, true] {
            for case in [ReplyCase::Subkey, ReplyCase::Rejected] {
                // Given authenticated success or rejection with valid contextual controls.
                let (built, options) = kpasswd_context::request()?;
                let response = kpasswd_context::reply(&built, case)?;
                let listener = TcpListener::bind("127.0.0.1:0").await?;
                let addr = listener.local_addr()?;
                let config = config_with_kpasswd_servers([addr.to_string()], 1)?;
                let transport = Tokio::new().with_timeout(Duration::from_secs(1));
                let server = async {
                    let (_request, mut stream) = read_tcp_request(&listener).await?;
                    write_tcp_response(&mut stream, &response).await
                };
                // When either checked helper receives the reply.
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
                let (delivery, result) = tokio::join!(server, client);
                delivery?;
                // Then the authenticated result is definite, including server-subkey success.
                match case {
                    ReplyCase::Subkey => assert_eq!(result?.code, KPASSWD_SUCCESS),
                    ReplyCase::Rejected => assert!(matches!(
                        result,
                        Err(ClientError::Kadmin(KadminError::PasswordChangeFailed {
                            code: 4,
                            text: _,
                            text_raw: _
                        }))
                    )),
                    ReplyCase::BadApRep
                    | ReplyCase::WrongApRepTime
                    | ReplyCase::MissingFreshness
                    | ReplyCase::WrongSequence
                    | ReplyCase::WrongAddress
                    | ReplyCase::StaleTime
                    | ReplyCase::WrongKey
                    | ReplyCase::Reflection => return Err("invalid success fixture".into()),
                }
            }
        }
        Ok(())
    })
}

/// Pins that a kpasswd KRB-ERROR carrying a success result code is rejected as unauthenticated.
#[test]
fn tokio_transport_rejects_unauthenticated_kpasswd_success_result() -> Result<(), TestError> {
    runtime()?.block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let config = config_with_kpasswd_servers([addr.to_string()], 1465)?;
        let (request, options) = kpasswd_context::request()?;
        let expected_request = request.request.encode()?;
        let response = kpasswd_reply_frame(
            0,
            &kpasswd_result_krb_error(KPASSWD_SUCCESS, "password changed")?,
        )?;
        let task = tokio::spawn(async move {
            let (received, mut socket) = read_tcp_request(&listener).await?;
            assert_eq!(received, expected_request);
            write_tcp_response(&mut socket, &response).await
        });

        let error = Tokio::new()
            .with_timeout(Duration::from_secs(2))
            .exchange_kpasswd_result_with_config(
                &config,
                KdcProtocol::Tcp,
                "TEST.GOKRB5",
                &request,
                &options,
            )
            .await
            .err()
            .ok_or("unsigned success result rejected")?;

        bounded(Duration::from_secs(10), "unsigned success peer task", task).await???;
        assert!(matches!(
            error,
            ClientError::KpasswdOutcomeUnknown(source)
                if matches!(*source, ClientError::Kadmin(KadminError::UnauthenticatedSuccess))
        ));
        Ok::<_, TestError>(())
    })
}

/// Pins that a configured kpasswd exchange returns the server failure result with its raw text.
#[test]
fn tokio_transport_exchanges_configured_kpasswd_failure_result() -> Result<(), TestError> {
    runtime()?.block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let config = config_with_kpasswd_servers([addr.to_string()], 1465)?;
        let (request, options) = kpasswd_context::request()?;
        let expected_request = request.request.encode()?;
        let response = kpasswd_reply_frame(
            0,
            &kpasswd_result_krb_error(KPASSWD_AUTHERROR, "authentication failed")?,
        )?;
        let task = tokio::spawn(async move {
            let (received, mut socket) = read_tcp_request(&listener).await?;
            assert_eq!(received, expected_request);
            write_tcp_response(&mut socket, &response).await
        });

        let error = Tokio::new()
            .with_timeout(Duration::from_secs(2))
            .exchange_kpasswd_result_with_config(
                &config,
                KdcProtocol::Tcp,
                "TEST.GOKRB5",
                &request,
                &options,
            )
            .await
            .err()
            .ok_or("non-zero kpasswd result returns error")?;

        bounded(Duration::from_secs(10), "unsigned failure peer task", task).await???;
        assert!(matches!(
            error,
            ClientError::KpasswdOutcomeUnknown(source)
                if matches!(&*source, ClientError::Kadmin(KadminError::UnauthenticatedRejection { code, text_raw })
                    if *code == KPASSWD_AUTHERROR && text_raw == b"authentication failed")
        ));
        Ok::<_, TestError>(())
    })
}
