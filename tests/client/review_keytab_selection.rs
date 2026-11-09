use super::*;

/// Keytab challenge selection intersects request preference, KDC offers and actual keys.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use rasn::der;

    use super::*;

    /// Two-exchange KDC with explicit advertised enctypes and an AES256-SHA1 reply key.
    struct Offered {
        /// Requests received, including any unexpected retry.
        calls: usize,
        /// Enctypes advertised independently of the client's preference order.
        etypes: Vec<i32>,
    }

    impl KdcTransport for Offered {
        fn send(&mut self, _: &str, request: &[u8]) -> Result<Vec<u8>, Error> {
            self.reply(request)
                .map_err(|error| Error::Transport(error.to_string()))
        }
    }

    impl Offered {
        /// Advertise the offered set, then require a decryptable timestamp under the available key.
        fn reply(&mut self, bytes: &[u8]) -> Result<Vec<u8>, TestError> {
            self.calls = self.calls.checked_add(1).context("count")?;
            assert!(self.calls <= 2);
            if self.calls == 1 {
                let hints: rasn_kerberos::EtypeInfo2 = self
                    .etypes
                    .iter()
                    .map(|etype| rasn_kerberos::EtypeInfo2Entry {
                        etype: *etype,
                        salt: None,
                        s2kparams: None,
                    })
                    .collect();
                let data = vec![rasn_kerberos::PaData {
                    r#type: PA_ETYPE_INFO2,
                    value: der::encode(&hints)?.into(),
                }];
                let mut error: rasn_kerberos::KrbError =
                    der::decode(&synthetic_preauth_required_error()?)?;
                error.e_data = Some(der::encode(&data)?.into());
                return Ok(der::encode(&error)?);
            }
            let request: rasn_kerberos::AsReq = der::decode(bytes)?;
            let data = request.0.padata.as_ref().context("retry padata")?;
            let stamp = data
                .iter()
                .find(|pa| pa.r#type == PA_ENC_TIMESTAMP)
                .context("timestamp")?;
            let encrypted: rasn_kerberos::EncryptedData = der::decode(stamp.value.as_ref())?;
            assert_eq!(encrypted.etype, 18_i32);
            assert_eq!(encrypted.kvno, Some(3));
            let key = reply_key()?;
            let plain = KerberosEtype::from_etype_id(18)
                .context("AES")?
                .decrypt_message(
                    key.value(),
                    encrypted.cipher.as_ref(),
                    AS_REQ_PA_ENC_TIMESTAMP_USAGE,
                )?;
            let _timestamp: rasn_kerberos::PaEncTsEnc = der::decode(&plain)?;
            let built = built_request_from_der(request, bytes)?;
            synthetic_as_rep_with_reply_key(&built, built.nonce(), built.service(), &key)
        }
    }

    /// An unavailable first offer must not mask a later offered key in the exact-principal keytab.
    #[test]
    fn challenge_uses_available_key_intersection() -> Result<(), TestError> {
        // Given requested/offered [20,18], but only a matching key18.
        let mut peer = Offered {
            calls: 0,
            etypes: vec![20_i32, 18_i32],
        };
        let principal = Principal::user("TEST.GOKRB5", "testuser1");
        // When the challenge selects the key, then it sends key18 and completes login.
        let session = login_tgt_with_keytab(
            &mut peer,
            principal.clone(),
            &keytab_with_reply_key(3)?,
            AsReq::new(timestamp(1_893_553_447)?, 42).with_etypes(vec![20_i32, 18_i32]),
        )?;
        assert_eq!(session.client(), &principal);
        assert_eq!(peer.calls, 2);
        Ok(())
    }

    /// No common requested/offered key or wrong principal/realm must stop before encrypted retry.
    #[test]
    fn challenge_without_matching_key_fails_closed() -> Result<(), TestError> {
        for (offered, requested, principal) in [
            (
                vec![20_i32],
                vec![20_i32, 18_i32],
                Principal::user("TEST.GOKRB5", "testuser1"),
            ),
            (
                vec![18_i32],
                vec![20_i32],
                Principal::user("TEST.GOKRB5", "testuser1"),
            ),
            (
                vec![20_i32, 18_i32],
                vec![20_i32, 18_i32],
                Principal::user("TEST.GOKRB5", "another-user"),
            ),
            (
                vec![20_i32, 18_i32],
                vec![20_i32, 18_i32],
                Principal::user("OTHER.GOKRB5", "testuser1"),
            ),
        ] {
            // Given no intersection, including keys owned by an unrelated identity.
            let mut peer = Offered {
                calls: 0,
                etypes: offered,
            };
            // When handling the challenge, then a typed selection error prevents any retry.
            let result = login_tgt_with_keytab(
                &mut peer,
                principal,
                &keytab_with_reply_key(3)?,
                AsReq::new(timestamp(1_893_553_447)?, 42).with_etypes(requested),
            );
            assert!(matches!(
                result,
                Err(Error::NoSupportedPreauthEtype { requested: _ })
            ));
            assert_eq!(peer.calls, 1);
        }
        Ok(())
    }

    /// Request preference wins over the KDC's order when both keys are present.
    #[test]
    fn challenge_preserves_request_preference() -> Result<(), TestError> {
        // Given both keys, KDC preference20 first and client preference18 first.
        let mut keytab = keytab_with_reply_key(3)?;
        keytab.entries_mut().push(KeytabEntry::new(
            KeytabPrincipal::new("TEST.GOKRB5", 1, vec!["testuser1".to_owned()]),
            1_893_553_440,
            4,
            EncryptionKey::new(20, vec![0x55; 32]),
            4,
        ));
        let mut peer = Offered {
            calls: 0,
            etypes: vec![20_i32, 18_i32],
        };
        // When selecting, then the peer must decrypt the preferred key18 timestamp.
        let session = login_tgt_with_keytab(
            &mut peer,
            Principal::user("TEST.GOKRB5", "testuser1"),
            &keytab,
            AsReq::new(timestamp(1_893_553_447)?, 42).with_etypes(vec![18_i32, 20_i32]),
        )?;
        assert_eq!(
            session.client(),
            &Principal::user("TEST.GOKRB5", "testuser1")
        );
        assert_eq!(peer.calls, 2);
        Ok(())
    }
}
