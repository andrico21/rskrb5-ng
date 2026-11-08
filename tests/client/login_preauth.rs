use super::*;

/// Login tests: password and keytab pre-authentication and AS-REP session keys.
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

    /// Both inner hint encodings reject trailing values and garbage inside valid errors.
    #[test]
    fn preauth_hints_require_complete_der() -> Result<(), TestError> {
        for kind in [11_i32, 19_i32] {
            let hint = if kind == 19_i32 {
                der::encode(&rasn_kerberos::EtypeInfo2::from([
                    rasn_kerberos::EtypeInfo2Entry {
                        etype: 18,
                        salt: None,
                        s2kparams: None,
                    },
                ]))?
            } else {
                der::encode(&rasn_kerberos::EtypeInfo::from([
                    rasn_kerberos::EtypeInfoEntry {
                        etype: 18,
                        salt: None,
                    },
                ]))?
            };
            for suffix in [&[][..], &[0x05, 0x00][..], &[0xff][..], &[0x00][..]] {
                let mut bytes = hint.clone();
                bytes.extend_from_slice(suffix);
                let mut error: rasn_kerberos::KrbError =
                    der::decode(&synthetic_preauth_required_error()?)?;
                error.e_data = Some(
                    der::encode(&rasn_kerberos::MethodData::from([rasn_kerberos::PaData {
                        r#type: kind,
                        value: bytes.into(),
                    }]))?
                    .into(),
                );
                let result = process_kdc_error(&der::encode(&error)?);
                if suffix.is_empty() {
                    assert_eq!(
                        result?.preauth_key_info.first().ok_or("hint")?.etype,
                        18_i32
                    );
                } else {
                    assert!(
                        matches!(
                            result,
                            Err(Error::Decode {
                                target: "ETYPE-INFO" | "ETYPE-INFO2",
                                message: _
                            })
                        ),
                        "trailing hint DER accepted"
                    );
                }
            }
        }
        Ok(())
    }

    /// Pins that a `PREAUTH_REQUIRED` error is parsed and its ETYPE-INFO2 entry selected.
    #[test]
    fn parses_kdc_preauth_required_error_and_selects_etype_info2() -> Result<(), TestError> {
        let error_bytes = synthetic_preauth_required_error()?;

        let error = process_kdc_error(&error_bytes).context("KRB-ERROR decodes")?;

        assert_eq!(error.error_code, KDC_ERR_PREAUTH_REQUIRED);
        assert_eq!(error.ctime, None);
        assert_eq!(error.cusec, None);
        assert_eq!(error.stime, timestamp(1_893_553_440)?);
        assert_eq!(error.susec, 0);
        assert_eq!(
            error.client,
            Some(Principal::user("TEST.GOKRB5", "testuser1"))
        );
        assert_eq!(error.service, Principal::tgt_service("TEST.GOKRB5"));
        assert_eq!(error.method_data.len(), 1);
        assert_eq!(
            error.preauth_key_info,
            vec![
                PreauthKeyInfo::new(18)
                    .with_salt(Some(TESTUSER_SALT.to_owned()))
                    .with_s2kparams(Some(vec![0, 0, 16, 0]))
            ]
        );

        let selected = select_preauth_key_info(&error, &[17_i32, 18_i32])
            .context("supported hint is selected")?;
        assert_eq!(selected.etype, 18_i32);
        assert_eq!(
            default_password_salt(&Principal::user("TEST.GOKRB5", "testuser1")),
            TESTUSER_SALT
        );
        Ok(())
    }

    /// Pins the selection and key derivation of an RC4-HMAC pre-authentication entry.
    #[test]
    fn selects_and_derives_rc4_hmac_preauth_key_info() -> Result<(), TestError> {
        let client = Principal::user("TEST.GOKRB5", "testuser1");
        let error = KdcError::new(
            timestamp(1_893_553_440)?,
            0,
            KDC_ERR_PREAUTH_REQUIRED,
            Principal::tgt_service("TEST.GOKRB5"),
        )
        .with_ctime(None)
        .with_cusec(None)
        .with_text(None)
        .with_client(Some(client.clone()))
        .with_e_data(None)
        .with_method_data(Vec::new())
        .with_preauth_key_info(vec![
            PreauthKeyInfo::new(23)
                .with_salt(Some("ignored-by-rc4".to_owned()))
                .with_s2kparams(None),
        ]);

        let selected =
            select_preauth_key_info(&error, &[18_i32, 23_i32]).context("RC4 hint is selected")?;
        assert_eq!(selected.etype, 23_i32);

        let reply_key = derive_password_reply_key(&client, b"foo", &selected)
            .context("RC4 reply key derives")?;
        assert_eq!(reply_key.etype, 23_i32);
        assert_eq!(
            reply_key.value.as_slice(),
            decode_hex("ac8e657f83df82beea5d43bdaf7800cc")?
        );
        Ok(())
    }

    /// Pins that a password login retries with PA-ENC-TIMESTAMP after `PREAUTH_REQUIRED`.
    #[test]
    fn login_tgt_with_password_retries_after_preauth_required() -> Result<(), TestError> {
        let client = Principal::user("TEST.GOKRB5", "testuser1");
        let options = AsReq::new(timestamp(1_893_553_447)?, 0x1122_3344).with_etypes(vec![18_i32]);
        let key_info = password_key_info();
        let reply_key = derive_password_reply_key(&client, TESTUSER_PASSWORD, &key_info)
            .context("password key derives")?;
        let mut transport = PreauthTransport::new(reply_key, None);

        let session =
            login_tgt_with_password(&mut transport, client.clone(), TESTUSER_PASSWORD, options)
                .context("password login succeeds")?;

        assert_eq!(transport.calls, 2);
        assert_eq!(session.client, client);
        assert_eq!(session.service, Principal::tgt_service("TEST.GOKRB5"));
        Ok(())
    }

    /// Pins that a password login can omit the FAST negotiation marker.
    #[test]
    fn login_tgt_with_password_can_disable_fast_negotiation_marker() -> Result<(), TestError> {
        let client = Principal::user("TEST.GOKRB5", "testuser1");
        let options = AsReq::new(timestamp(1_893_553_447)?, 0x1122_3344)
            .with_etypes(vec![18_i32])
            .with_fast_negotiation(false);
        let key_info = password_key_info();
        let reply_key = derive_password_reply_key(&client, TESTUSER_PASSWORD, &key_info)
            .context("password key derives")?;
        let mut transport = PreauthTransport::new(reply_key, None).with_fast_negotiation(false);

        let session =
            login_tgt_with_password(&mut transport, client.clone(), TESTUSER_PASSWORD, options)
                .context("password login succeeds")?;

        assert_eq!(transport.calls, 2);
        assert_eq!(session.client, client);
        assert_eq!(session.service, Principal::tgt_service("TEST.GOKRB5"));
        Ok(())
    }

    /// Pins that a password login for an explicit service retries after `PREAUTH_REQUIRED`.
    #[test]
    fn login_as_service_with_password_retries_for_explicit_service() -> Result<(), TestError> {
        let client = Principal::user("TEST.GOKRB5", "testuser1");
        let service = change_password_principal();
        let options = AsReq::new(timestamp(1_893_553_447)?, 0x1122_3344).with_etypes(vec![18_i32]);
        let key_info = password_key_info();
        let reply_key = derive_password_reply_key(&client, TESTUSER_PASSWORD, &key_info)
            .context("password key derives")?;
        let mut transport = PreauthTransport::new(reply_key, None);

        let session = login_as_service_with_password(
            &mut transport,
            client.clone(),
            service.clone(),
            TESTUSER_PASSWORD,
            options,
        )
        .context("password login succeeds")?;

        assert_eq!(transport.calls, 2);
        assert_eq!(session.client, client);
        assert_eq!(session.service, service);
        Ok(())
    }

    /// Pins that a password login can send PA-ENC-TIMESTAMP up front, in one KDC call.
    #[test]
    fn login_tgt_with_password_can_assume_preauthentication() -> Result<(), TestError> {
        let client = Principal::user("TEST.GOKRB5", "testuser1");
        let options = AsReq::new(timestamp(1_893_553_447)?, 0x1122_3344)
            .with_etypes(vec![18_i32])
            .with_assume_preauthentication(true);
        let key_info = PreauthKeyInfo::new(18).with_salt(None).with_s2kparams(None);
        let reply_key = derive_password_reply_key(&client, TESTUSER_PASSWORD, &key_info)
            .context("password key derives")?;
        let mut transport = AssumedPreauthTransport::new(reply_key, None);

        let session =
            login_tgt_with_password(&mut transport, client.clone(), TESTUSER_PASSWORD, options)
                .context("password login succeeds")?;

        assert_eq!(transport.calls, 1);
        assert_eq!(session.client, client);
        assert_eq!(session.service, Principal::tgt_service("TEST.GOKRB5"));
        Ok(())
    }

    /// Pins that a keytab login retries with the key version of the selected keytab entry.
    #[test]
    fn login_tgt_with_keytab_retries_with_selected_keytab_kvno() -> Result<(), TestError> {
        let client = Principal::user("TEST.GOKRB5", "testuser1");
        let options = AsReq::new(timestamp(1_893_553_447)?, 0x1122_3344).with_etypes(vec![18_i32]);
        let keytab = keytab_with_reply_key(7)?;
        let mut transport = PreauthTransport::new(reply_key()?, Some(7));

        let session = login_tgt_with_keytab(&mut transport, client.clone(), &keytab, options)
            .context("keytab login succeeds")?;

        assert_eq!(transport.calls, 2);
        assert_eq!(session.client, client);
        assert_eq!(session.service, Principal::tgt_service("TEST.GOKRB5"));
        Ok(())
    }

    /// Pins that a keytab login can omit the FAST negotiation marker.
    #[test]
    fn login_tgt_with_keytab_can_disable_fast_negotiation_marker() -> Result<(), TestError> {
        let client = Principal::user("TEST.GOKRB5", "testuser1");
        let options = AsReq::new(timestamp(1_893_553_447)?, 0x1122_3344)
            .with_etypes(vec![18_i32])
            .with_fast_negotiation(false);
        let keytab = keytab_with_reply_key(7)?;
        let mut transport =
            PreauthTransport::new(reply_key()?, Some(7)).with_fast_negotiation(false);

        let session = login_tgt_with_keytab(&mut transport, client.clone(), &keytab, options)
            .context("keytab login succeeds")?;

        assert_eq!(transport.calls, 2);
        assert_eq!(session.client, client);
        assert_eq!(session.service, Principal::tgt_service("TEST.GOKRB5"));
        Ok(())
    }

    /// Pins that a keytab login for an explicit service retries after `PREAUTH_REQUIRED`.
    #[test]
    fn login_as_service_with_keytab_retries_for_explicit_service() -> Result<(), TestError> {
        let client = Principal::user("TEST.GOKRB5", "testuser1");
        let service = change_password_principal();
        let options = AsReq::new(timestamp(1_893_553_447)?, 0x1122_3344).with_etypes(vec![18_i32]);
        let keytab = keytab_with_reply_key(7)?;
        let mut transport = PreauthTransport::new(reply_key()?, Some(7));

        let session = login_as_service_with_keytab(
            &mut transport,
            client.clone(),
            service.clone(),
            &keytab,
            options,
        )
        .context("keytab login succeeds")?;

        assert_eq!(transport.calls, 2);
        assert_eq!(session.client, client);
        assert_eq!(session.service, service);
        Ok(())
    }

    /// Pins that a keytab login can send PA-ENC-TIMESTAMP up front, in one KDC call.
    #[test]
    fn login_tgt_with_keytab_can_assume_preauthentication() -> Result<(), TestError> {
        let client = Principal::user("TEST.GOKRB5", "testuser1");
        let options = AsReq::new(timestamp(1_893_553_447)?, 0x1122_3344)
            .with_etypes(vec![20_i32, 18_i32])
            .with_assume_preauthentication(true);
        let keytab = keytab_with_reply_key(3)?;
        let mut transport = AssumedPreauthTransport::new(reply_key()?, Some(3));

        let session = login_tgt_with_keytab(&mut transport, client.clone(), &keytab, options)
            .context("keytab login succeeds")?;

        assert_eq!(transport.calls, 1);
        assert_eq!(session.client, client);
        assert_eq!(session.service, Principal::tgt_service("TEST.GOKRB5"));
        Ok(())
    }

    /// Pins that a password login rejects an assumed-preauth AS-REP keyed outside the requested etypes.
    #[test]
    fn initial_as_rep_outside_requested_enctypes_is_rejected() -> Result<(), TestError> {
        let client = Principal::user("TEST.GOKRB5", "testuser1");
        let options = AsReq::new(timestamp(1_893_553_447)?, 0x1122_3344)
            .with_etypes(vec![18_i32])
            .with_assume_preauthentication(true);
        let aes128_key_info = PreauthKeyInfo::new(17).with_salt(None).with_s2kparams(None);
        let aes128_reply_key =
            derive_password_reply_key(&client, TESTUSER_PASSWORD, &aes128_key_info)?;
        let mut transport = AssumedPreauthTransport::new(aes128_reply_key, None);

        let Err(error) =
            login_tgt_with_password(&mut transport, client, TESTUSER_PASSWORD, options)
        else {
            return Err("an AS-REP outside the requested enctypes must be rejected".into());
        };
        assert!(matches!(error, Error::EnctypeNotRequested(17_i32)));
        assert_eq!(transport.calls, 1);
        Ok(())
    }

    /// An initial AS reply's legacy salt selects the password key without a challenge.
    #[test]
    fn initial_as_reply_uses_legacy_password_salt() -> Result<(), TestError> {
        use rasn::der;
        let client = Principal::user("TEST.GOKRB5", "testuser1");
        let request = build_tgt_as_req(client.clone(), AsReq::new(timestamp(1_893_553_447)?, 42))?;
        let key = derive_password_reply_key(
            &client,
            TESTUSER_PASSWORD,
            &PreauthKeyInfo::new(18).with_salt(Some("alternate-salt".to_owned())),
        )?;
        let mut reply: rasn_kerberos::AsRep = der::decode(&synthetic_as_rep_with_reply_key(
            &request,
            request.nonce,
            &request.service,
            &key,
        )?)?;
        reply.0.padata = Some(vec![rasn_kerberos::PaData {
            r#type: 3,
            value: b"alternate-salt".to_vec().into(),
        }]);
        let response = der::encode(&reply)?;
        let mut transport = MockTransport {
            expected_realm: client.realm.clone(),
            expected_request: request.der.to_vec(),
            response,
            called: false,
        };
        let session = login_tgt_with_password(
            &mut transport,
            client,
            TESTUSER_PASSWORD,
            AsReq::new(timestamp(1_893_553_447)?, 42).with_fast_negotiation(false),
        )?;
        assert_eq!(session.service, request.service);
        Ok(())
    }

    /// Pins that a keytab login rejects an assumed-preauth AS-REP keyed outside the requested etypes.
    #[test]
    fn keytab_initial_as_rep_outside_requested_enctypes_is_rejected() -> Result<(), TestError> {
        let client = Principal::user("TEST.GOKRB5", "testuser1");
        let options = AsReq::new(timestamp(1_893_553_447)?, 0x1122_3344)
            .with_etypes(vec![18_i32])
            .with_assume_preauthentication(true);
        let mut keytab = keytab_with_reply_key(4)?;
        let aes128_key_info = PreauthKeyInfo::new(17).with_salt(None).with_s2kparams(None);
        let aes128_reply_key =
            derive_password_reply_key(&client, TESTUSER_PASSWORD, &aes128_key_info)?;
        keytab.entries_mut().push(KeytabEntry::new(
            KeytabPrincipal::new("TEST.GOKRB5", 1, vec!["testuser1".to_owned()]),
            1_893_553_440,
            4,
            aes128_reply_key.clone(),
            4,
        ));
        let mut transport = AssumedPreauthTransport::new(aes128_reply_key, Some(4));

        let Err(error) = login_tgt_with_keytab(&mut transport, client, &keytab, options) else {
            return Err("an out-of-list keytab reply must be rejected".into());
        };
        assert!(matches!(error, Error::EnctypeNotRequested(17_i32)));
        assert_eq!(transport.calls, 1);
        Ok(())
    }
}
