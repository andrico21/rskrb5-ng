use super::*;

/// Optimistic encrypted-timestamp recovery is hint-guided and bounded.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use rasn::der;
    use rskrb5_ng::client::PA_FX_COOKIE;

    use super::*;

    /// Scripted KDC records every request and rejects any third exchange.
    struct Script {
        /// Requests observed in this conversation.
        calls: usize,
        /// Key that the hinted retry must use.
        key: EncryptionKey,
        /// Encoded error24 challenge.
        challenge: Vec<u8>,
        /// Whether the second reply repeats error24.
        reject_retry: bool,
    }

    impl KdcTransport for Script {
        fn send(&mut self, _: &str, request: &[u8]) -> Result<Vec<u8>, Error> {
            self.reply(request)
                .map_err(|error| Error::Transport(error.to_string()))
        }
    }

    impl Script {
        /// Validate the emitted preauth mechanism and answer one bounded exchange.
        fn reply(&mut self, bytes: &[u8]) -> Result<Vec<u8>, TestError> {
            self.calls = self.calls.checked_add(1).context("count")?;
            assert!(self.calls <= 2, "optimistic recovery must never loop");
            let request: rasn_kerberos::AsReq = der::decode(bytes)?;
            let padata = request.0.padata.as_deref().unwrap_or_default();
            if self.calls == 2 && !padata.iter().any(|pa| pa.r#type == PA_ENC_TIMESTAMP) {
                assert!(padata.iter().all(|pa| pa.r#type == PA_FX_COOKIE));
                return Ok(self.challenge.clone());
            }
            let encrypted = padata
                .iter()
                .find(|pa| pa.r#type == PA_ENC_TIMESTAMP)
                .context("timestamp")?;
            let timestamp: rasn_kerberos::EncryptedData = der::decode(encrypted.value.as_ref())?;
            assert_eq!(timestamp.etype, 18_i32);
            if self.calls == 1 {
                return Ok(self.challenge.clone());
            }
            let mut types = padata.iter().map(|pa| pa.r#type).collect::<Vec<_>>();
            types.sort_unstable();
            let mut expected = vec![PA_ENC_TIMESTAMP, PA_FX_COOKIE, PA_REQ_ENC_PA_REP];
            expected.sort_unstable();
            assert_eq!(
                types, expected,
                "no weaker mechanism or unrelated KDC padata"
            );
            assert_eq!(
                padata
                    .iter()
                    .find(|pa| pa.r#type == PA_FX_COOKIE)
                    .context("cookie")?
                    .value
                    .as_ref(),
                b"fresh\0cookie"
            );
            let etype = KerberosEtype::from_etype_id(18).context("AES")?;
            let plaintext = etype.decrypt_message(
                self.key.value(),
                timestamp.cipher.as_ref(),
                AS_REQ_PA_ENC_TIMESTAMP_USAGE,
            )?;
            let _timestamp: rasn_kerberos::PaEncTsEnc = der::decode(&plaintext)?;
            if self.reject_retry {
                return Ok(self.challenge.clone());
            }
            let built = built_request_from_der(request, bytes)?;
            synthetic_as_rep_with_reply_key(&built, built.nonce(), built.service(), &self.key)
        }
    }

    /// Nondefault salt and parameters ensure retry derivation really uses METHOD-DATA.
    fn setup(keytab: bool, reject_retry: bool) -> Result<(Script, AsReq), TestError> {
        let client = Principal::user("TEST.GOKRB5", "testuser1");
        let info = PreauthKeyInfo::new(18)
            .with_salt(Some("nondefault-salt".to_owned()))
            .with_s2kparams(Some(8192_u32.to_be_bytes().to_vec()));
        let key = if keytab {
            reply_key()?
        } else {
            derive_password_reply_key(&client, TESTUSER_PASSWORD, &info)?
        };
        let hints = rasn_kerberos::EtypeInfo2::from([rasn_kerberos::EtypeInfo2Entry {
            etype: 18,
            salt: Some(kerberos_string("nondefault-salt")?),
            s2kparams: Some(8192_u32.to_be_bytes().to_vec().into()),
        }]);
        let data = vec![
            rasn_kerberos::PaData {
                r#type: PA_ETYPE_INFO2,
                value: der::encode(&hints)?.into(),
            },
            rasn_kerberos::PaData {
                r#type: PA_FX_COOKIE,
                value: b"fresh\0cookie".to_vec().into(),
            },
            rasn_kerberos::PaData {
                r#type: 777,
                value: b"do-not-echo".to_vec().into(),
            },
        ];
        let mut challenge: rasn_kerberos::KrbError =
            der::decode(&synthetic_preauth_required_error()?)?;
        challenge.error_code = 24_i32;
        challenge.e_data = Some(der::encode(&data)?.into());
        let options = AsReq::new(timestamp(1_893_553_447)?, 42)
            .with_etypes(vec![18_i32])
            .with_assume_preauthentication(true);
        Ok((
            Script {
                calls: 0,
                key,
                challenge: der::encode(&challenge)?,
                reject_retry,
            },
            options,
        ))
    }

    /// Both credential modes recover exactly once, and repeated error24 is terminal.
    #[test]
    fn optimistic_error24_recovers_once_with_hints() -> Result<(), TestError> {
        for keytab in [false, true] {
            for reject_retry in [false, true] {
                // Given an optimistic request followed by a hinted error24.
                let (mut kdc, options) = setup(keytab, reject_retry)?;
                let principal = Principal::user("TEST.GOKRB5", "testuser1");
                // When login runs, it must retain encrypted timestamp and use the fresh hints.
                let result = if keytab {
                    login_tgt_with_keytab(
                        &mut kdc,
                        principal.clone(),
                        &keytab_with_reply_key(3)?,
                        options,
                    )
                } else {
                    login_tgt_with_password(&mut kdc, principal.clone(), TESTUSER_PASSWORD, options)
                };
                // Then one retry succeeds or returns the second error, never a third request.
                if reject_retry {
                    assert!(
                        matches!(result, Err(Error::Kdc(error)) if error.error_code() == 24_i32)
                    );
                } else {
                    assert_eq!(result?.client(), &principal);
                }
                assert_eq!(kdc.calls, 2);
            }
        }
        Ok(())
    }

    /// Error24 is not retryable when the failed exchange was not optimistic.
    #[test]
    fn nonoptimistic_error24_is_terminal() -> Result<(), TestError> {
        let (mut kdc, initial_options) = setup(false, false)?;
        // Given a request explicitly carrying preauth but without optimistic authorization.
        let options = initial_options
            .with_assume_preauthentication(false)
            .with_padata(vec![rasn_kerberos::PaData {
                r#type: PA_ENC_TIMESTAMP,
                value: der::encode(&rasn_kerberos::EncryptedData {
                    etype: 18,
                    kvno: None,
                    cipher: vec![0].into(),
                })?
                .into(),
            }]);
        // When the server returns error24, then no recovery request is sent.
        let result = login_tgt_with_password(
            &mut kdc,
            Principal::user("TEST.GOKRB5", "testuser1"),
            TESTUSER_PASSWORD,
            options,
        );
        assert!(matches!(result, Err(Error::Kdc(error)) if error.error_code() == 24_i32));
        assert_eq!(kdc.calls, 1);
        Ok(())
    }

    /// Missing or unsupported hints allow discovery but never another guessed-password request.
    #[test]
    fn unusable_error24_hints_stop_after_failed_discovery() -> Result<(), TestError> {
        // Given optimistic password/keytab requests and unusable METHOD-DATA.
        for keytab in [false, true] {
            for unsupported in [false, true] {
                let (mut kdc, options) = setup(keytab, false)?;
                let mut error: rasn_kerberos::KrbError = der::decode(&kdc.challenge)?;
                error.e_data = if unsupported {
                    let hints = rasn_kerberos::EtypeInfo2::from([rasn_kerberos::EtypeInfo2Entry {
                        etype: 23,
                        salt: None,
                        s2kparams: None,
                    }]);
                    Some(
                        der::encode(&vec![rasn_kerberos::PaData {
                            r#type: PA_ETYPE_INFO2,
                            value: der::encode(&hints)?.into(),
                        }])?
                        .into(),
                    )
                } else {
                    None
                };
                kdc.challenge = der::encode(&error)?;
                let principal = Principal::user("TEST.GOKRB5", "testuser1");
                // When discovery repeats error24, then recovery terminates without fallback.
                let result = if keytab {
                    login_tgt_with_keytab(&mut kdc, principal, &keytab_with_reply_key(3)?, options)
                } else {
                    login_tgt_with_password(&mut kdc, principal, TESTUSER_PASSWORD, options)
                };
                assert!(
                    matches!(result, Err(Error::Kdc(rejection)) if rejection.error_code() == 24_i32)
                );
                assert_eq!(kdc.calls, 2);
            }
        }
        Ok(())
    }

    /// Tokio configured logins preserve the same TCP connection and binary cookie on recovery.
    #[cfg(feature = "tokio")]
    #[test]
    fn optimistic_recovery_preserves_tcp_affinity() -> Result<(), TestError> {
        use tokio::{task::JoinSet, time::timeout};

        runtime()?.block_on(async {
            for keytab in [false, true] {
                // Given one scripted KDC connection serving exactly two requests.
                let (mut script, options) = setup(keytab, false)?;
                let listener = TcpListener::bind("127.0.0.1:0").await?;
                let config = Config::parse(&format!("[libdefaults]\n dns_lookup_kdc = false\n[realms]\n TEST.GOKRB5 = {{\n kdc = {}\n }}\n", listener.local_addr()?))?;
                let mut peers = JoinSet::new();
                drop(peers.spawn(async move {
                    let (first, mut socket) = read_tcp_kdc_request(&listener).await?;
                    write_tcp_kdc_response(&mut socket, &script.reply(&first)?).await?;
                    let length = usize::try_from(socket.read_u32().await?)?;
                    (length <= 0x0010_0000).ok_or("oversized request")?;
                    let mut second = vec![0; length];
                    let _: usize = socket.read_exact(&mut second).await?;
                    write_tcp_kdc_response(&mut socket, &script.reply(&second)?).await?;
                    assert_eq!(script.calls, 2);
                    Ok::<(), TestError>(())
                }));
                let transport = TokioKdcTransport::new();
                let principal = Principal::user("TEST.GOKRB5", "testuser1");
                // When the shared challenge helper admits the hinted optimistic failure.
                let session = if keytab { timeout(Duration::from_secs(5), transport.login_tgt_with_keytab_config(&config, KdcProtocol::Tcp, principal.clone(), &keytab_with_reply_key(3)?, options)).await?? } else { timeout(Duration::from_secs(5), transport.login_tgt_with_password_config(&config, KdcProtocol::Tcp, principal.clone(), TESTUSER_PASSWORD, options)).await?? };
                // Then successful retry required both affinity and the exact hinted preauth.
                assert_eq!(session.client(), &principal);
                peers.join_next().await.context("peer")???;
            }
            Ok(())
        })
    }
}
