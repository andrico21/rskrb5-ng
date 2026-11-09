use super::*;

/// Cookie conversation regression tests.
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
    struct CookieKdc {
        calls: usize,
        key: EncryptionKey,
        cookie: Option<&'static [u8]>,
    }

    impl KdcTransport for CookieKdc {
        fn send(&mut self, _: &str, request: &[u8]) -> Result<Vec<u8>, Error> {
            self.reply(request)
                .map_err(|cause| Error::Transport(cause.to_string()))
        }
    }

    impl CookieKdc {
        fn reply(&mut self, request: &[u8]) -> Result<Vec<u8>, TestError> {
            let decoded: rasn_kerberos::AsReq = der::decode(request)?;
            self.calls = self.calls.checked_add(1).context("call count")?;
            if self.calls == 1 {
                let mut challenge: rasn_kerberos::KrbError =
                    der::decode(&synthetic_preauth_required_error()?)?;
                let mut data: rasn_kerberos::MethodData =
                    der::decode(challenge.e_data.as_ref().context("method data")?.as_ref())?;
                data.push(rasn_kerberos::PaData {
                    r#type: 777_i32,
                    value: b"challenge-only".to_vec().into(),
                });
                if let Some(cookie) = self.cookie {
                    data.push(rasn_kerberos::PaData {
                        r#type: PA_FX_COOKIE,
                        value: cookie.to_vec().into(),
                    });
                }
                challenge.e_data = Some(der::encode(&data)?.into());
                return Ok(der::encode(&challenge)?);
            }
            let padata = decoded.0.padata.as_ref().context("retry padata")?;
            let mut types = padata.iter().map(|pa| pa.r#type).collect::<Vec<_>>();
            types.sort_unstable();
            let mut expected = vec![PA_ENC_TIMESTAMP, PA_REQ_ENC_PA_REP, 778_i32];
            if self.cookie.is_some() {
                expected.push(PA_FX_COOKIE);
            }
            expected.sort_unstable();
            assert_eq!(
                types, expected,
                "only intended client data and cookies are echoed"
            );
            assert_eq!(
                padata
                    .iter()
                    .find(|pa| pa.r#type == 778_i32)
                    .context("client data")?
                    .value
                    .as_ref(),
                b"client-only"
            );
            let cookies = padata
                .iter()
                .filter(|pa| pa.r#type == PA_FX_COOKIE)
                .map(|pa| pa.value.as_ref())
                .collect::<Vec<_>>();
            assert_eq!(cookies, self.cookie.into_iter().collect::<Vec<_>>());
            let built = built_request_from_der(decoded, request)?;
            synthetic_as_rep_with_reply_key(&built, built.nonce(), built.service(), &self.key)
        }
    }

    /// Seed stale conversation state alongside intentional client padata.
    fn cookie_options() -> Result<AsReq, TestError> {
        Ok(AsReq::new(timestamp(1_893_553_447)?, 42)
            .with_etypes(vec![18_i32])
            .with_padata(vec![
                rasn_kerberos::PaData {
                    r#type: PA_FX_COOKIE,
                    value: b"stale".to_vec().into(),
                },
                rasn_kerberos::PaData {
                    r#type: 778_i32,
                    value: b"client-only".to_vec().into(),
                },
            ]))
    }

    /// Password retries replace stale cookies with the exact challenge value.
    #[test]
    fn password_retry_echoes_latest_cookie() -> Result<(), TestError> {
        // Given a stale cookie and a challenge with unrelated data.
        let request = sample_request()?;
        let mut kdc = CookieKdc {
            calls: 0,
            key: derive_password_reply_key(
                request.client(),
                TESTUSER_PASSWORD,
                &password_key_info(),
            )?,
            cookie: Some(b"fresh\0cookie"),
        };
        // When login retries the challenge.
        let session = login_tgt_with_password(
            &mut kdc,
            request.client().clone(),
            TESTUSER_PASSWORD,
            cookie_options()?,
        )?;
        // Then the KDC observes exactly the permitted retry data and completes login.
        assert_eq!(session.client(), request.client());
        assert_eq!(kdc.calls, 2);
        Ok(())
    }

    /// Keytab retries copy cookies without echoing unrelated challenge data.
    #[test]
    fn keytab_retry_echoes_latest_cookie() -> Result<(), TestError> {
        // Given stale state for a keytab-backed client too.
        let request = sample_request()?;
        let mut kdc = CookieKdc {
            calls: 0,
            key: reply_key()?,
            cookie: Some(b"fresh\0cookie"),
        };
        // When login retries the challenge.
        let session = login_tgt_with_keytab(
            &mut kdc,
            request.client().clone(),
            &keytab_with_reply_key(3)?,
            cookie_options()?,
        )?;
        // Then only the fresh cookie and intended client data reach the KDC.
        assert_eq!(session.client(), request.client());
        assert_eq!(kdc.calls, 2);
        Ok(())
    }

    /// An absent challenge cookie clears password conversation state.
    #[test]
    fn password_retry_removes_cookie_when_challenge_omits_it() -> Result<(), TestError> {
        // Given stale state and a cookie-free challenge.
        let request = sample_request()?;
        let mut kdc = CookieKdc {
            calls: 0,
            key: derive_password_reply_key(
                request.client(),
                TESTUSER_PASSWORD,
                &password_key_info(),
            )?,
            cookie: None,
        };
        // When login retries.
        let session = login_tgt_with_password(
            &mut kdc,
            request.client().clone(),
            TESTUSER_PASSWORD,
            cookie_options()?,
        )?;
        // Then the exact retry-set check observes no cookie.
        assert_eq!(session.client(), request.client());
        assert_eq!(kdc.calls, 2);
        Ok(())
    }

    /// An absent challenge cookie clears keytab conversation state.
    #[test]
    fn keytab_retry_removes_cookie_when_challenge_omits_it() -> Result<(), TestError> {
        // Given stale state and a cookie-free challenge.
        let request = sample_request()?;
        let mut kdc = CookieKdc {
            calls: 0,
            key: reply_key()?,
            cookie: None,
        };
        // When login retries.
        let session = login_tgt_with_keytab(
            &mut kdc,
            request.client().clone(),
            &keytab_with_reply_key(3)?,
            cookie_options()?,
        )?;
        // Then the exact retry-set check observes no cookie.
        assert_eq!(session.client(), request.client());
        assert_eq!(kdc.calls, 2);
        Ok(())
    }
}
