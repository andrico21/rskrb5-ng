//! Checked password result regressions.

use super::*;

/// Authenticated legacy subkeys require explicit permission at the checked reply boundary.
#[test]
fn checked_replies_enforce_legacy_policy() -> Result<(), TestError> {
    use rskrb5_ng::{
        config::Toggle,
        crypto::Use,
        error::{Crypto, Policy},
    };
    runtime()?.block_on(async {
        for id in [16_i32, 23_i32] {
            for permitted in [false, true] {
                let (built, options) = kpasswd_context::request()?;
                let response = kpasswd_context::reply(&built, kpasswd_context::ReplyCase::LegacySubkey(id))?;
                let listener = TcpListener::bind("127.0.0.1:0").await?;
                let addr = listener.local_addr()?;
                let mut config = config_with_kpasswd_servers([addr.to_string()], 1)?;
                if permitted {
                    config.libdefaults.allow_rc4 = Toggle::from(true);
                    config.libdefaults.allow_des3 = Toggle::from(true);
                    config.libdefaults.permitted_enctypes = vec!["DEFAULT".to_owned(), "rc4".to_owned(), "des3".to_owned()];
                }
                let transport = Tokio::new().with_timeout(Duration::from_secs(1));
                let server = async {
                    let (_, mut stream) = read_tcp_request(&listener).await?;
                    write_tcp_response(&mut stream, &response).await
                };
                let client = transport.exchange_kpasswd_result_with_config(&config, KdcProtocol::Tcp, "TEST.GOKRB5", &built, &options);
                let (delivery, result) = tokio::join!(server, client);
                delivery?;
                if permitted {
                    assert_eq!(result?.code, KPASSWD_SUCCESS);
                } else {
                    assert!(matches!(result, Err(ClientError::KpasswdOutcomeUnknown(source)) if matches!(*source, ClientError::Crypto(Crypto::Policy(Policy::EnctypeNotPermitted { etype, usage: Use::SessionKey })) if etype == id)));
                }
            }
        }
        Ok(())
    })
}

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
                ReplyCase::WrongKey, ReplyCase::Reflection, ReplyCase::ExcessiveUsec] {
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
            for case in [
                ReplyCase::Subkey,
                ReplyCase::Rejected,
                ReplyCase::SkewBoundary,
                ReplyCase::MaximumUsec,
            ] {
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
                    ReplyCase::Subkey | ReplyCase::SkewBoundary | ReplyCase::MaximumUsec => {
                        assert_eq!(result?.code, KPASSWD_SUCCESS);
                    }
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
                    | ReplyCase::ExcessiveUsec
                    | ReplyCase::WrongKey
                    | ReplyCase::Reflection => return Err("invalid success fixture".into()),
                    ReplyCase::LegacySubkey(_) => {
                        return Err("legacy fixture needs explicit policy".into());
                    }
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
