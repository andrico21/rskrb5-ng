use super::*;

/// Bounded hint discovery after an optimistic encrypted-timestamp failure.
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

    /// Peer transcript and terminal-reply controls.
    struct Script {
        /// Requests received.
        calls: usize,
        /// Hinted reply and timestamp key.
        key: EncryptionKey,
        /// Discovery response code.
        discovery_code: i32,
        /// Whether discovery supplies supported key hints.
        hints: bool,
        /// Whether the guided request is rejected again.
        reject_final: bool,
        /// Explicit malformed or unsupported discovery reply for negative cases.
        discovery_override: Option<Vec<u8>>,
    }

    /// Encode error24/25 with exact cookie and optional nondefault key hints.
    fn challenge(code: i32, hints: bool, cookie: &[u8]) -> Result<Vec<u8>, TestError> {
        let mut error: rasn_kerberos::KrbError = der::decode(&synthetic_preauth_required_error()?)?;
        error.error_code = code;
        let mut data = vec![rasn_kerberos::PaData {
            r#type: PA_FX_COOKIE,
            value: cookie.to_vec().into(),
        }];
        if hints {
            let info = rasn_kerberos::EtypeInfo2::from([rasn_kerberos::EtypeInfo2Entry {
                etype: 18,
                salt: Some(kerberos_string("discovered-salt")?),
                s2kparams: Some(8192_u32.to_be_bytes().to_vec().into()),
            }]);
            data.push(rasn_kerberos::PaData {
                r#type: PA_ETYPE_INFO2,
                value: der::encode(&info)?.into(),
            });
        }
        error.e_data = Some(der::encode(&data)?.into());
        Ok(der::encode(&error)?)
    }

    impl KdcTransport for Script {
        fn send(&mut self, _: &str, request: &[u8]) -> Result<Vec<u8>, Error> {
            self.reply(request)
                .map_err(|error| Error::Transport(error.to_string()))
        }
    }

    impl Script {
        /// Check each request's mechanism and cookie before generating the response.
        fn reply(&mut self, bytes: &[u8]) -> Result<Vec<u8>, TestError> {
            self.calls = self.calls.checked_add(1).context("count")?;
            assert!(self.calls <= 3, "discovery must never loop");
            let request: rasn_kerberos::AsReq = der::decode(bytes)?;
            assert_eq!(request.0.req_body.etype, vec![18_i32]);
            let data = request.0.padata.as_deref().unwrap_or_default();
            let stamp = data.iter().find(|pa| pa.r#type == PA_ENC_TIMESTAMP);
            if self.calls == 1 {
                assert!(stamp.is_some());
                return challenge(24, false, b"probe\0cookie");
            }
            let cookie = data
                .iter()
                .find(|pa| pa.r#type == PA_FX_COOKIE)
                .context("cookie")?
                .value
                .as_ref();
            if self.calls == 2 {
                assert!(stamp.is_none(), "discovery must carry no encrypted preauth");
                assert!(
                    data.iter().all(|pa| pa.r#type == PA_FX_COOKIE),
                    "probe may only carry conversation cookie"
                );
                assert_eq!(cookie, b"probe\0cookie");
                if let Some(response) = &self.discovery_override {
                    return Ok(response.clone());
                }
                return challenge(self.discovery_code, self.hints, b"guided\0cookie");
            }
            assert_eq!(cookie, b"guided\0cookie");
            let mut types = data.iter().map(|pa| pa.r#type).collect::<Vec<_>>();
            types.sort_unstable();
            let mut expected = vec![PA_ENC_TIMESTAMP, PA_FX_COOKIE, PA_REQ_ENC_PA_REP];
            expected.sort_unstable();
            assert_eq!(types, expected);
            let encrypted: rasn_kerberos::EncryptedData =
                der::decode(stamp.context("guided timestamp")?.value.as_ref())?;
            assert_eq!(encrypted.etype, 18_i32);
            let etype = KerberosEtype::from_etype_id(18).context("AES")?;
            let plaintext = etype.decrypt_message(
                self.key.value(),
                encrypted.cipher.as_ref(),
                AS_REQ_PA_ENC_TIMESTAMP_USAGE,
            )?;
            let _timestamp: rasn_kerberos::PaEncTsEnc = der::decode(&plaintext)?;
            if self.reject_final {
                return challenge(24, false, b"terminal");
            }
            let built = built_request_from_der(request, bytes)?;
            synthetic_as_rep_with_reply_key(&built, built.nonce(), built.service(), &self.key)
        }
    }

    /// Build a password/keytab peer using independent nondefault salt and parameters.
    fn setup(keytab: bool) -> Result<(Script, AsReq), TestError> {
        let principal = Principal::user("TEST.GOKRB5", "testuser1");
        let info = PreauthKeyInfo::new(18)
            .with_salt(Some("discovered-salt".to_owned()))
            .with_s2kparams(Some(8192_u32.to_be_bytes().to_vec()));
        let key = if keytab {
            reply_key()?
        } else {
            derive_password_reply_key(&principal, TESTUSER_PASSWORD, &info)?
        };
        Ok((
            Script {
                calls: 0,
                key,
                discovery_code: 25,
                hints: true,
                reject_final: false,
                discovery_override: None,
            },
            AsReq::new(timestamp(1_893_553_447)?, 42)
                .with_etypes(vec![18_i32])
                .with_assume_preauthentication(true),
        ))
    }

    /// Exactly three requests recover or return a terminal final error for both credentials.
    #[test]
    fn hint_free_discovery_is_bounded() -> Result<(), TestError> {
        for keytab in [false, true] {
            for reject_final in [false, true] {
                // Given optimistic error24, then a usable error25 discovery response.
                let (mut script, options) = setup(keytab)?;
                script.reject_final = reject_final;
                let principal = Principal::user("TEST.GOKRB5", "testuser1");
                // When login performs the bounded discovery sequence.
                let result = if keytab {
                    login_tgt_with_keytab(
                        &mut script,
                        principal.clone(),
                        &keytab_with_reply_key(3)?,
                        options,
                    )
                } else {
                    login_tgt_with_password(
                        &mut script,
                        principal.clone(),
                        TESTUSER_PASSWORD,
                        options,
                    )
                };
                // Then the guided response is final, even when it is another hint-free error24.
                if reject_final {
                    assert!(
                        matches!(result, Err(Error::Kdc(error)) if error.error_code() == 24_i32)
                    );
                } else {
                    assert_eq!(result?.client(), &principal);
                }
                assert_eq!(script.calls, 3);
            }
        }
        Ok(())
    }

    /// Repeated failure, unrelated errors and missing discovery hints stop before a third send.
    #[test]
    fn discovery_response_must_be_usable_error25() -> Result<(), TestError> {
        for keytab in [false, true] {
            for (code, hints) in [(24_i32, true), (6_i32, true), (25_i32, false)] {
                // Given an unusable discovery response.
                let (mut script, options) = setup(keytab)?;
                script.discovery_code = code;
                script.hints = hints;
                let principal = Principal::user("TEST.GOKRB5", "testuser1");
                // When it is received, then no guessed or weaker preauth request follows.
                let result = if keytab {
                    login_tgt_with_keytab(
                        &mut script,
                        principal,
                        &keytab_with_reply_key(3)?,
                        options,
                    )
                } else {
                    login_tgt_with_password(&mut script, principal, TESTUSER_PASSWORD, options)
                };
                assert!(matches!(result, Err(Error::Kdc(error)) if error.error_code() == code));
                assert_eq!(script.calls, 2);
            }
        }
        Ok(())
    }

    /// Malformed or unrequested discovery hints cannot trigger default-key fallback.
    #[test]
    fn invalid_discovery_hints_fail_closed() -> Result<(), TestError> {
        for keytab in [false, true] {
            for malformed in [false, true] {
                // Given a discovery reply with invalid DER or only unrequested RC4 hints.
                let (mut script, options) = setup(keytab)?;
                let mut error: rasn_kerberos::KrbError =
                    der::decode(&challenge(25, true, b"ignored")?)?;
                error.e_data = Some(if malformed {
                    vec![0xff].into()
                } else {
                    let hints = rasn_kerberos::EtypeInfo2::from([rasn_kerberos::EtypeInfo2Entry {
                        etype: 23,
                        salt: None,
                        s2kparams: None,
                    }]);
                    der::encode(&vec![rasn_kerberos::PaData {
                        r#type: PA_ETYPE_INFO2,
                        value: der::encode(&hints)?.into(),
                    }])?
                    .into()
                });
                script.discovery_override = Some(der::encode(&error)?);
                let principal = Principal::user("TEST.GOKRB5", "testuser1");
                // When discovery is validated, then no third request may be sent.
                let result = if keytab {
                    login_tgt_with_keytab(
                        &mut script,
                        principal,
                        &keytab_with_reply_key(3)?,
                        options,
                    )
                } else {
                    login_tgt_with_password(&mut script, principal, TESTUSER_PASSWORD, options)
                };
                if malformed {
                    assert!(matches!(
                        result,
                        Err(Error::Decode {
                            target: "METHOD-DATA",
                            message: _
                        })
                    ));
                } else {
                    assert!(
                        matches!(result, Err(Error::Kdc(rejection)) if rejection.error_code() == 25_i32)
                    );
                }
                assert_eq!(script.calls, 2);
            }
        }
        Ok(())
    }

    /// Direct/configured Tokio password/keytab paths keep all three exchanges on one socket.
    #[cfg(feature = "tokio")]
    #[test]
    fn discovery_preserves_tcp_affinity() -> Result<(), TestError> {
        use tokio::{task::JoinSet, time::timeout};
        runtime()?.block_on(async {
            for keytab in [false, true] {
                for configured in [false, true] {
                    // Given a server accepting exactly one connection for three requests.
                    let (mut script, options) = setup(keytab)?;
                    let listener = TcpListener::bind("127.0.0.1:0").await?;
                    let addr = listener.local_addr()?;
                    let config = Config::parse(&format!("[libdefaults]\n dns_lookup_kdc = false\n[realms]\n TEST.GOKRB5 = {{\n kdc = {addr}\n }}\n"))?;
                    let mut peers = JoinSet::new();
                    drop(peers.spawn(async move {
                        let (mut socket, _addr) = listener.accept().await?;
                        for _ in 0_u8..3_u8 {
                            let length = usize::try_from(socket.read_u32().await?)?;
                            (length <= 0x0010_0000).ok_or("oversized request")?;
                            let mut bytes = vec![0; length];
                            let _: usize = socket.read_exact(&mut bytes).await?;
                            write_tcp_kdc_response(&mut socket, &script.reply(&bytes)?).await?;
                        }
                        Ok::<(), TestError>(())
                    }));
                    let transport = TokioKdcTransport::new();
                    let principal = Principal::user("TEST.GOKRB5", "testuser1");
                    let keys = keytab_with_reply_key(3)?;
                    // When each public transport variant executes the same bounded state machine.
                    let session = timeout(Duration::from_secs(5), async {
                        match (keytab, configured) {
                            (true, true) => transport.login_tgt_with_keytab_config(&config, KdcProtocol::Tcp, principal.clone(), &keys, options).await,
                            (true, false) => transport.login_tgt_with_keytab(KdcProtocol::Tcp, addr, principal.clone(), &keys, options).await,
                            (false, true) => transport.login_tgt_with_password_config(&config, KdcProtocol::Tcp, principal.clone(), TESTUSER_PASSWORD, options).await,
                            (false, false) => transport.login_tgt_with_password(KdcProtocol::Tcp, addr, principal.clone(), TESTUSER_PASSWORD, options).await,
                        }
                    }).await??;
                    // Then success proves affinity, cookies, mechanisms and nondefault hints.
                    assert_eq!(session.client(), &principal);
                    peers.join_next().await.context("peer")???;
                }
            }
            Ok(())
        })
    }
}
