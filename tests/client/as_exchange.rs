use rskrb5_ng::error::Config as ConfigError;

use super::*;

/// AS exchange tests: AS-REQ building, pre-authentication, AS-REP processing,
/// permitted enctypes, PA-DATA constants and nonces.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::iter;

    use rasn::{der, types::Integer};
    use rskrb5_ng::{
        client::{PA_AS_FRESHNESS, PA_FX_COOKIE, random_nonce},
        config::LibDefaults,
        messages::PaForUser,
    };

    use super::*;

    /// Pins the fields of a TGT AS-REQ: client, TGS service, till time, nonce and enctypes, with no padata.
    #[test]
    fn builds_tgt_as_req_with_expected_fields() -> Result<(), TestError> {
        let client = Principal::user("TEST.GOKRB5", "testuser1");
        let options = AsReq::new(timestamp(1_893_553_447)?, 0x1122_3344)
            .with_ticket_lifetime(Duration::from_hours(8))
            .with_etypes(vec![18_i32, 17_i32]);

        let request = build_tgt_as_req(client.clone(), options).context("AS-REQ builds")?;
        let decoded: rasn_kerberos::AsReq = der::decode(&request.der).context("AS-REQ decodes")?;

        assert_eq!(request.message, decoded);
        assert_eq!(decoded.0.pvno, Integer::from(5_i32));
        assert_eq!(decoded.0.msg_type, Integer::from(10_i32));
        assert!(decoded.0.padata.is_none());

        let body = &decoded.0.req_body;
        assert_eq!(
            principal_from_parts(&body.realm, body.cname.as_ref().context("cname")?)?,
            client
        );
        assert_eq!(
            principal_from_parts(&body.realm, body.sname.as_ref().context("sname")?)?,
            Principal::tgt_service("TEST.GOKRB5")
        );
        assert_eq!(
            system_time_from_kerberos_time(&body.till)?,
            timestamp(1_893_582_247)?
        );
        assert!(body.rtime.is_none());
        assert_eq!(body.nonce, 0x1122_3344);
        assert_eq!(body.etype, vec![18_i32, 17_i32]);
        assert!(body.addresses.is_none());
        assert!(body.enc_authorization_data.is_none());
        assert!(body.additional_tickets.is_none());
        Ok(())
    }

    /// Pins that a renew lifetime sets the RENEWABLE KDC option and the rtime of the AS-REQ.
    #[test]
    fn builds_tgt_as_req_with_renew_lifetime_sets_renewable_flag() -> Result<(), TestError> {
        let client = Principal::user("TEST.GOKRB5", "testuser1");
        let options = AsReq::new(timestamp(1_893_553_447)?, 0x1122_3344)
            .with_ticket_lifetime(Duration::from_hours(8))
            .with_renew_lifetime(Some(Duration::from_hours(10)));

        let request = build_tgt_as_req(client, options).context("AS-REQ builds")?;
        let decoded: rasn_kerberos::AsReq = der::decode(&request.der).context("AS-REQ decodes")?;
        let body = &decoded.0.req_body;

        assert_eq!(
            body.kdc_options.0.as_raw_slice(),
            KDC_OPTION_RENEWABLE.to_be_bytes().as_slice()
        );
        assert_eq!(
            system_time_from_kerberos_time(body.rtime.as_ref().context("renew time")?)?,
            timestamp(1_893_589_447)?
        );
        Ok(())
    }

    /// Unarmored AS requests preserve other options but suppress canonicalization.
    #[test]
    fn as_req_options_from_libdefaults_suppresses_canonicalize_flag() -> Result<(), TestError> {
        let defaults = LibDefaults::default()
            .with_canonicalize(true.into())
            .with_kdc_default_options(0x0000_0010);
        let client = Principal::user("TEST.GOKRB5", "testuser1");
        let options = AsReq::from_libdefaults(timestamp(1_893_553_447)?, 0x1122_3344, &defaults);

        let request = build_tgt_as_req(client, options).context("AS-REQ builds")?;
        let decoded: rasn_kerberos::AsReq = der::decode(&request.der).context("AS-REQ decodes")?;
        let body = &decoded.0.req_body;

        assert_eq!(
            body.kdc_options.0.as_raw_slice(),
            0x0000_0010_u32.to_be_bytes().as_slice()
        );
        Ok(())
    }

    /// Pins that a pre-authenticated AS-REQ names an explicit service and carries PA-ENC-TIMESTAMP.
    #[test]
    fn builds_preauthenticated_as_req_for_explicit_service() -> Result<(), TestError> {
        let client = Principal::user("TEST.GOKRB5", "testuser1");
        let service = change_password_principal();
        let request = build_preauthenticated_as_req(
            client.clone(),
            service.clone(),
            AsReq::new(timestamp(1_893_553_447)?, 0x1122_3344).with_etypes(vec![18_i32]),
            &reply_key()?,
            Some(7),
        )
        .context("AS-REQ builds")?;
        let decoded: rasn_kerberos::AsReq = der::decode(&request.der).context("AS-REQ decodes")?;

        assert_eq!(request.client, client);
        assert_eq!(request.service, service);
        let body = &decoded.0.req_body;
        assert_eq!(
            principal_from_parts(&body.realm, body.sname.as_ref().context("sname")?)?,
            change_password_principal()
        );
        let padata = decoded.0.padata.as_ref().context("preauth padata")?;
        assert!(padata.iter().any(|entry| entry.r#type == PA_ENC_TIMESTAMP));
        Ok(())
    }

    /// Pins the PA-ENC-TIMESTAMP encryption under the reply key with a fixed confounder.
    #[test]
    fn builds_and_encrypts_pa_enc_timestamp() -> Result<(), TestError> {
        let key = reply_key()?;
        let padata = pa_enc_timestamp_with_confounder(
            &key,
            timestamp(1_893_553_447)?,
            123_456,
            &decode_hex(PREAUTH_CONFOUNDER)?,
            Some(7),
        )
        .context("PA-ENC-TIMESTAMP builds")?;

        assert_eq!(padata.r#type, PA_ENC_TIMESTAMP);
        let encrypted: rasn_kerberos::EncryptedData =
            der::decode(padata.value.as_ref()).context("encrypted timestamp decodes")?;
        assert_eq!(encrypted.etype, 18_i32);
        assert_eq!(encrypted.kvno, Some(7));

        let plaintext = AesSha1Etype::Aes256
            .decrypt_message(
                &key.value,
                encrypted.cipher.as_ref(),
                AS_REQ_PA_ENC_TIMESTAMP_USAGE,
            )
            .context("encrypted timestamp decrypts")?;
        let timestamp_part: rasn_kerberos::PaEncTsEnc =
            der::decode(&plaintext).context("PA-ENC-TS-ENC decodes")?;

        assert_eq!(
            system_time_from_kerberos_time(&timestamp_part.patimestamp)?,
            timestamp(1_893_553_447)?
        );
        assert_eq!(
            timestamp_part
                .pausec
                .context("microseconds")?
                .to_string()
                .parse::<u32>()
                .context("microseconds parse")?,
            123_456
        );
        Ok(())
    }

    /// Pins the PA-FOR-USER padata of `S4U2Self`, including its HMAC-MD5 S4U checksum.
    #[test]
    fn builds_pa_for_user_padata_with_s4u_checksum() -> Result<(), TestError> {
        let user = Principal::new("ATHENA.MIT.EDU", 1, ["hftsai", "extra"]);
        let tgt_session_key = EncryptionKey::new(18, decode_hex(SESSION_KEY)?);

        let padata = pa_for_user_padata(&user, &tgt_session_key).context("PA-FOR-USER builds")?;

        assert_eq!(padata.r#type, PA_FOR_USER);
        let decoded = PaForUser::decode_der(padata.value.as_ref()).context("value decodes")?;
        assert_eq!(
            principal_from_parts(&decoded.user_realm, &decoded.user_name)?,
            user
        );
        assert_eq!(decoded.auth_package.as_bytes(), b"Kerberos");
        assert_eq!(decoded.cksum.r#type, -138_i32);
        let s4u_bytes = s4u_byte_array(&user, "Kerberos");
        assert_eq!(
            hex_encode(&s4u_bytes)?,
            "010000006866747361696578747261415448454e412e4d49542e4544554b65726265726f73"
        );
        assert_eq!(
            decoded.cksum.checksum.as_ref(),
            kerb_checksum_hmac_md5(
                &tgt_session_key.value,
                &s4u_bytes,
                PA_FOR_USER_CHECKSUM_USAGE
            )
        );
        Ok(())
    }

    /// Pins that a valid AS-REP yields the TGT session and exports it as a ccache credential.
    #[test]
    fn processes_as_rep_and_exports_ccache_credential() -> Result<(), TestError> {
        let request = sample_request()?;
        let reply_key = reply_key()?;
        let response = synthetic_as_rep(&request, request.nonce)?;

        let session =
            process_as_rep(&request, &response, &reply_key).context("AS-REP validates")?;

        assert_eq!(session.client, Principal::user("TEST.GOKRB5", "testuser1"));
        assert_eq!(session.service, Principal::tgt_service("TEST.GOKRB5"));
        assert_eq!(session.session_key.etype, 18_i32);
        assert_eq!(hex_encode(&session.session_key.value)?, SESSION_KEY);
        assert_eq!(session.ticket_flags, *TICKET_FLAGS);
        assert_eq!(session.auth_time, timestamp(1_893_553_445)?);
        assert_eq!(session.start_time, timestamp(1_893_553_445)?);
        assert_eq!(session.end_time, timestamp(1_893_639_845)?);
        assert_eq!(session.renew_till, Some(timestamp(1_894_071_845)?));

        let ticket: rasn_kerberos::Ticket =
            der::decode(&session.ticket).context("ticket decodes")?;
        assert_eq!(ticket.tkt_vno, Integer::from(5_i32));

        let credential = session
            .to_ccache_credential()
            .context("ccache credential converts")?;
        assert_eq!(credential.client.realm, "TEST.GOKRB5");
        assert_eq!(credential.client.components, vec!["testuser1"]);
        assert_eq!(credential.server.components, vec!["krbtgt", "TEST.GOKRB5"]);
        assert_eq!(credential.key.value, decode_hex(SESSION_KEY)?);
        assert_eq!(credential.times.auth_time, 1_893_553_445);
        assert_eq!(credential.times.end_time, 1_893_639_845);
        assert_eq!(credential.times.renew_till, 1_894_071_845);
        assert_eq!(credential.ticket, *session.ticket);
        assert!(
            credential.second_ticket.is_empty(),
            "the credential has no second ticket"
        );
        Ok(())
    }

    /// Pins that an AS-REP whose PA-REQ-ENC-PA-REP checksum matches the request is accepted.
    #[test]
    fn process_as_rep_validates_pa_req_enc_pa_rep_checksum() -> Result<(), TestError> {
        let request = sample_request_with_pa_req_enc_pa_rep()?;
        let reply_key = reply_key()?;
        assert_eq!(
            u32::from_be_bytes(*TICKET_FLAGS) & TICKET_FLAG_ENC_PA_REP,
            TICKET_FLAG_ENC_PA_REP
        );
        let response =
            synthetic_as_rep_with_reply_key(&request, request.nonce, &request.service, &reply_key)?;

        let session = process_as_rep(&request, &response, &reply_key)
            .context("AS-REP encrypted padata checksum validates")?;

        assert_eq!(session.client, Principal::user("TEST.GOKRB5", "testuser1"));
        assert_eq!(session.service, Principal::tgt_service("TEST.GOKRB5"));
        Ok(())
    }

    /// Pins that a corrupted PA-REQ-ENC-PA-REP checksum fails FAST negotiation.
    #[test]
    fn process_as_rep_rejects_invalid_pa_req_enc_pa_rep_checksum() -> Result<(), TestError> {
        let request = sample_request_with_pa_req_enc_pa_rep()?;
        let reply_key = reply_key()?;
        let response = synthetic_as_rep_with_reply_key_and_encrypted_padata(
            &request,
            request.nonce,
            &request.service,
            &reply_key,
            Some(fast_negotiation_encrypted_padata(
                &request, &reply_key, true,
            )?),
        )?;

        let error = process_as_rep(&request, &response, &reply_key)
            .err()
            .context("invalid AS-REP encrypted padata checksum fails")?;

        assert!(matches!(error, Error::FastNegotiationChecksumMismatch));
        Ok(())
    }

    /// Request integrity does not require the optional FAST advertisement.
    #[test]
    fn process_as_rep_accepts_checksum_without_fast_marker() -> Result<(), TestError> {
        let request = sample_request_with_pa_req_enc_pa_rep()?;
        let reply_key = reply_key()?;
        let response = synthetic_as_rep_with_reply_key_and_encrypted_padata(
            &request,
            request.nonce,
            &request.service,
            &reply_key,
            Some(vec![pa_req_enc_pa_rep_padata(&request, &reply_key, false)?]),
        )?;

        let session = process_as_rep(&request, &response, &reply_key)?;
        assert_eq!(session.client, request.client);
        Ok(())
    }

    /// Pins that a KRB-ERROR in place of an AS-REP surfaces as a KDC error.
    #[test]
    fn process_as_rep_surfaces_kdc_error_response() -> Result<(), TestError> {
        let request = sample_request()?;
        let error = process_as_rep(
            &request,
            &synthetic_preauth_required_error()?,
            &reply_key()?,
        )
        .err()
        .context("KRB-ERROR response is surfaced")?;

        assert!(matches!(
            error,
            Error::Kdc(kdc_error) if kdc_error.error_code == KDC_ERR_PREAUTH_REQUIRED
        ));
        Ok(())
    }

    /// Pins that an AS-REP with a nonce other than the request's is rejected.
    #[test]
    fn rejects_as_rep_nonce_mismatch() -> Result<(), TestError> {
        let request = sample_request()?;
        let response = synthetic_as_rep(&request, request.nonce + 1)?;

        let error = process_as_rep(&request, &response, &reply_key()?)
            .err()
            .context("nonce mismatch fails")?;

        assert!(matches!(
            error,
            Error::NonceMismatch {
                expected: 0x1122_3344,
                actual: 0x1122_3345,
            }
        ));
        Ok(())
    }

    /// Pins that an AS-REP whose ticket names another service is rejected.
    #[test]
    fn rejects_as_rep_ticket_service_mismatch() -> Result<(), TestError> {
        let request = sample_request()?;
        let response = synthetic_as_rep_with_ticket_service(
            &request,
            request.nonce,
            &Principal::tgt_service("BAD.REALM"),
        )?;

        let error = process_as_rep(&request, &response, &reply_key()?)
            .err()
            .context("service mismatch fails")?;

        assert!(matches!(
            error,
            Error::ServicePrincipalMismatch {
                expected,
                actual,
            } if expected == "krbtgt/TEST.GOKRB5" && actual == "krbtgt/BAD.REALM"
        ));
        Ok(())
    }

    /// Pins that the AS exchange sends the request through the `KdcTransport` to the client realm.
    #[test]
    fn exchange_as_req_uses_transport_boundary() -> Result<(), TestError> {
        let request = sample_request()?;
        let response = synthetic_as_rep(&request, request.nonce)?;
        let mut transport = MockTransport {
            expected_realm: "TEST.GOKRB5".to_owned(),
            expected_request: request.der.to_vec(),
            response,
            called: false,
        };

        let session = exchange_as_req(&mut transport, &request, &reply_key()?)
            .context("transport exchange works")?;

        assert!(transport.called);
        assert_eq!(session.service, Principal::tgt_service("TEST.GOKRB5"));
        Ok(())
    }

    /// Pins rejection of a mixed disabled AS-REQ enctype list without narrowing.
    #[test]
    fn as_req_rejects_mixed_disabled_enctype_list() -> Result<(), TestError> {
        let defaults = LibDefaults::default()
            .with_default_tkt_enctypes(vec![
                "aes256-cts".into(),
                "aes128-cts".into(),
                "rc4-hmac".into(),
            ])
            .with_permitted_enctypes(vec!["aes256-cts".into()])
            .with_permitted_enctypes_explicit(true.into());
        let options = AsReq::from_libdefaults(timestamp(1_893_553_447)?, 0x1122_3344, &defaults);
        let error = build_tgt_as_req(Principal::user("TEST.GOKRB5", "testuser1"), options)
            .err()
            .context("disabled mixed list is rejected")?;
        assert!(matches!(error, Error::EmptyEtypes));
        Ok(())
    }

    /// Pins that a request list disjoint from the permitted set fails closed.
    #[test]
    fn as_req_with_disjoint_permitted_enctypes_fails_closed() -> Result<(), TestError> {
        let defaults = LibDefaults::default()
            .with_default_tkt_enctypes(vec!["aes256-cts".into()])
            .with_permitted_enctypes(vec!["aes128-cts".into()])
            .with_permitted_enctypes_explicit(true.into());
        let options = AsReq::from_libdefaults(timestamp(1_893_553_447)?, 0x1122_3344, &defaults);
        assert!(
            options.etypes.is_empty(),
            "no requested etype is permitted: {:?}",
            options.etypes
        );

        let Err(error) = build_tgt_as_req(Principal::user("TEST.GOKRB5", "testuser1"), options)
        else {
            return Err("an empty request list must fail closed".into());
        };
        assert!(matches!(error, Error::EmptyEtypes));
        Ok(())
    }

    /// Pins that SHA2 request etypes survive when `permitted_enctypes` is implicit.
    #[test]
    fn sha2_request_list_survives_the_implicit_permitted_set() -> Result<(), TestError> {
        let defaults = LibDefaults::default()
            .with_default_tkt_enctypes(vec!["aes128-sha2".into(), "aes256-sha2".into()])
            .with_permitted_enctypes(vec![
                "aes256-cts".into(),
                "aes128-cts".into(),
                "rc4-hmac".into(),
            ]);
        let options = AsReq::from_libdefaults(timestamp(1_893_553_447)?, 0x1122_3344, &defaults);

        assert_eq!(options.etypes, vec![19_i32, 20_i32]);
        Ok(())
    }

    /// Pins that a parsed config with only SHA2 `default_tkt_enctypes` keeps that list.
    #[test]
    fn config_with_sha2_tkt_enctypes_and_no_permitted_line_keeps_the_request_list()
    -> Result<(), TestError> {
        let config = Config::parse(
            "
[libdefaults]
 default_tkt_enctypes = aes128-cts-hmac-sha256-128
",
        )?;
        assert!(!config.libdefaults.permitted_enctypes_explicit.is_enabled());

        let options =
            AsReq::from_libdefaults(timestamp(1_893_553_447)?, 0x1122_3344, &config.libdefaults);
        assert_eq!(options.etypes, vec![19_i32]);
        Ok(())
    }

    /// Pins that an explicit SHA2 request list outside an explicit allowlist is rejected.
    #[test]
    fn explicit_permitted_enctypes_reject_an_explicit_sha2_request_list() -> Result<(), TestError> {
        let Err(error) = Config::parse(
            "
[libdefaults]
 default_tkt_enctypes = aes128-cts-hmac-sha256-128
 permitted_enctypes = aes256-cts-hmac-sha1-96
",
        ) else {
            return Err(
                "an explicit SHA2 request list outside the allowlist must be rejected".into(),
            );
        };

        assert!(
            matches!(
                &error,
                ConfigError::EnctypeNotPermitted { key: "default_tkt_enctypes", enctype }
                    if enctype == "aes128-cts-hmac-sha256-128"
            ),
            "unexpected error: {error:?}"
        );
        Ok(())
    }

    /// Pins that an AS-REP session key outside the requested etypes is rejected.
    #[test]
    fn process_as_rep_rejects_session_key_outside_requested_enctypes() -> Result<(), TestError> {
        let request = build_tgt_as_req(
            Principal::user("TEST.GOKRB5", "testuser1"),
            AsReq::new(timestamp(1_893_553_447)?, 0x1122_3344).with_etypes(vec![17_i32]),
        )?;
        let reply_key = reply_key()?;
        let response =
            synthetic_as_rep_with_reply_key(&request, request.nonce, &request.service, &reply_key)?;

        let Err(error) = process_as_rep(&request, &response, &reply_key) else {
            return Err("a session key outside the requested list must be rejected".into());
        };
        assert!(matches!(error, Error::EnctypeNotRequested(18_i32)));
        Ok(())
    }

    /// Pins the IANA registrations of the exported `PA-FX-COOKIE` and `PA-AS-FRESHNESS`.
    #[test]
    fn exported_padata_constants_match_their_registrations() {
        assert_eq!(PA_FX_COOKIE, 133_i32);
        assert_eq!(PA_AS_FRESHNESS, 150_i32);
    }

    /// Pins that nonces keep the top bit clear and are not constant.
    #[test]
    fn random_nonce_keeps_the_top_bit_clear_and_varies() -> Result<(), TestError> {
        let draws = iter::repeat_with(random_nonce)
            .take(8)
            .collect::<Result<Vec<u32>, _>>()?;
        assert!(draws.iter().all(|nonce| nonce & 0x8000_0000 == 0));
        assert!(
            draws
                .windows(2)
                .any(|pair| matches!(pair, [first, second] if first != second))
        );
        Ok(())
    }

    /// Pins that an MIT-spelled `des3-cbc-sha1` request entry is requested as enctype 16.
    #[test]
    fn explicit_mit_des3_request_entry_is_requested() -> Result<(), TestError> {
        let config = Config::parse(
            "
[libdefaults]
 default_tkt_enctypes = aes256-cts-hmac-sha1-96 des3-cbc-sha1
 allow_des3 = true
 permitted_enctypes = DEFAULT des3
",
        )?;

        let options =
            AsReq::from_libdefaults(timestamp(1_893_553_447)?, 0x1122_3344, &config.libdefaults);
        let request = build_tgt_as_req(Principal::user("TEST.GOKRB5", "testuser1"), options)?;
        let decoded: rasn_kerberos::AsReq = der::decode(&request.der)?;
        assert_eq!(decoded.0.req_body.etype, vec![18_i32, 16_i32]);
        Ok(())
    }

    /// Pins that an MIT-spelled DES3 request entry outside an explicit allowlist fails parsing.
    #[test]
    fn explicit_mit_des3_request_entry_outside_permitted_fails_parsing() -> Result<(), TestError> {
        let Err(error) = Config::parse(
            "
[libdefaults]
 default_tkt_enctypes = aes256-cts-hmac-sha1-96 des3-cbc-sha1
 allow_des3 = true
 permitted_enctypes = aes256-cts-hmac-sha1-96
",
        ) else {
            return Err("a DES3 request entry outside the allowlist must be rejected".into());
        };

        assert!(
            matches!(
                &error,
                ConfigError::EnctypeNotPermitted { key: "default_tkt_enctypes", enctype }
                    if enctype == "des3-cbc-sha1"
            ),
            "unexpected error: {error:?}"
        );
        Ok(())
    }
}
