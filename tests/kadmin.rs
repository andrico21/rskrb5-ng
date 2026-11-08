//! kpasswd (`ChangePasswdData`, KRB-PRIV, request and reply frame) tests.
#![cfg(feature = "messages")]

/// kpasswd (`ChangePasswdData`, KRB-PRIV, request and reply frame) tests.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::{error, fmt::Display};

    use chrono::{DateTime, FixedOffset, Utc};
    use pretty_assertions::assert_eq;
    use rasn::{der, types::Integer};
    use rasn_kerberos::{KerberosString, KerberosTime, KrbError, PrincipalName};
    use rskrb5_ng::{
        ap_req,
        client::Password,
        crypto::KerberosEtype,
        error::Kadmin as KadminError,
        kadmin::{
            ChangePasswdData, ChangePasswdMessageOptions, ChangePasswordResult, KPASSWD_AUTHERROR,
            KPASSWD_SUCCESS, Reply, Request, build_change_password_message,
            build_change_password_message_with_confounders, build_change_password_request,
            build_change_password_request_with_confounder, build_krb_priv,
            build_krb_priv_with_confounder, decode_enc_krb_priv_part, decode_krb_priv,
            decrypt_krb_priv_enc_part, encode_krb_priv,
        },
        keytab::EncryptionKey,
        krb_priv::{
            EncKrbPrivPartOptions, KRB_PRIV_MSG_TYPE, KRB_PRIV_PVNO, ipv4_host_address,
            ipv6_host_address,
        },
    };

    /// Error type of the `Result`-returning tests.
    type TestError = Box<dyn error::Error>;

    /// Public encryption preserves the concrete cause of an invalid key.
    #[test]
    fn public_encrypt_retains_crypto_source() -> Result<(), TestError> {
        use core::error::Error as _;

        use rskrb5_ng::error::Crypto;
        let failure = build_krb_priv_with_confounder(
            b"payload",
            EncKrbPrivPartOptions::new(ipv4_host_address([127, 0, 0, 1])),
            &EncryptionKey::new(18, vec![0; 1]),
            &[0; 16],
        )
        .err()
        .context("invalid key")?;
        assert!(failure.source().context("crypto cause")?.is::<Crypto>());
        Ok(())
    }

    /// Full-message AP encryption preserves the concrete crypto source.
    #[test]
    fn full_message_retains_ap_crypto_source() -> Result<(), TestError> {
        use core::error::Error as _;

        use rskrb5_ng::{error::Crypto, kadmin::PasswordEncryption};

        let fixture = Request::parse(&decode_hex(MARSHALLED_KPASSWD_REQ)?)?;
        let failure = build_change_password_message_with_confounders(
            rasn_principal_name(1, ["testuser1"])?,
            "TEST.GOKRB5",
            &ChangePasswdData::new(Password::copy_from_str("new-password")),
            fixture.ap_req.ticket,
            &EncryptionKey::new(18, vec![0; 1]),
            ChangePasswdMessageOptions::new(
                kerberos_time(1_893_553_454)?,
                123,
                42,
                ipv4_host_address([127, 0, 0, 1]),
            ),
            PasswordEncryption::new(EncryptionKey::new(18, vec![0x44; 32]), &[0; 16], &[0; 16]),
        )
        .err()
        .context("invalid AP key")?;
        assert!(
            matches!(failure, KadminError::Crypto(_)),
            "AP crypto classified as decoding"
        );
        assert!(failure.source().context("AP crypto source")?.is::<Crypto>());
        Ok(())
    }

    /// Password byte equality rejects other values while diagnostics remain explicitly redacted.
    #[test]
    fn password_bytes_compare_and_identify_redaction() -> Result<(), TestError> {
        let value = ChangePasswdData::decode_der(
            &ChangePasswdData::new(Password::copy_from_str("canary")).encode_der()?,
        )?;
        assert_eq!(value.new_passwd, b"canary".to_vec());
        assert!(!(value.new_passwd == b"other".to_vec()));
        assert_eq!(format!("{:?}", value.new_passwd), "[REDACTED]");
        Ok(())
    }

    /// Error replies reject either independently present protected-message payload.
    #[test]
    fn error_reply_rejects_each_protected_payload() -> Result<(), TestError> {
        let protected = Reply::parse(&decode_hex(MARSHALLED_KPASSWD_REP)?)?;
        for include_ap in [false, true] {
            let mut error = Reply::parse(&decode_hex(KRB_ERROR_WITH_EDATA)?)?;
            if include_ap {
                error.ap_rep = protected.ap_rep.clone();
            } else {
                error.krb_priv = protected.krb_priv.clone();
            }
            assert!(matches!(
                error.encode(),
                Err(KadminError::InvalidErrorReplyPayload)
            ));
        }
        Ok(())
    }

    /// Attaches a description to a failure, as `expect` would, but as an error
    /// that `?` propagates.
    trait Context<T> {
        /// Returns the value, or an error that names `what`.
        fn context(self, what: &str) -> Result<T, TestError>;
    }

    impl<T, E: Display> Context<T> for Result<T, E> {
        fn context(self, what: &str) -> Result<T, TestError> {
            self.map_err(|cause| format!("{what}: {cause}").into())
        }
    }

    impl<T> Context<T> for Option<T> {
        fn context(self, what: &str) -> Result<T, TestError> {
            self.ok_or_else(|| what.into())
        }
    }

    /// The fixed AP-REQ authenticator confounder.
    const CHG_PASSWD_MSG_AP_REQ_CONFOUNDER: &str = "00112233445566778899aabbccddeeff";
    /// The fixed KRB-PRIV confounder.
    const CHG_PASSWD_MSG_KRB_PRIV_CONFOUNDER: &str = "0a0b0c0d0e0f10111213141516171819";

    /// The gokrb5 targeted `ChangePasswdData` fixture.
    const MARSHALLED_CHANGE_PASSWD_DATA: &str = "3036a00d040b6e657770617373776f7264a1163014a003020101a10d300b1b09746573747573657231a20d1b0b544553542e474f4b524235";
    /// The gokrb5 kpasswd request fixture.
    const MARSHALLED_KPASSWD_REQ: &str = include_str!("fixtures/kpasswd-request.hex");
    /// The gokrb5 kpasswd success reply fixture.
    const MARSHALLED_KPASSWD_REP: &str = "00ec0001008c6f8189308186a003020105a10302010fa27a3078a003020112a271046f57cb442fd321312aff0b2dcda70fe436812f9805611adf3403ab6cd7708604e86e77f765a8486864f0dbf8d5d065a63790370bc110ed1e3c7eae9890e02407e8a8b349703fed1e7f165e1261a822c5b3e6823c282884f59afeb9f84f2a9845994135dd307eb2f544874393c1c455d475583056a003020105a103020115a34a3048a003020112a241043fdd3edaf0b6cbcab5b663189bafc0a19e6cc03b3c59d989c403735748ebc36088bad852add0f62581eed515fc1f297324df4fa12cb94b7ad5db257165369db5";
    /// A KRB-ERROR whose e-data is the result `kr` / `b5data`.
    const KRB_ERROR_WITH_EDATA: &str = "7E81BA3081B7A003020105A10302011EA211180F31393934303631303036303331375AA305020301E240A411180F31393934303631303036303331375AA505020301E240A60302013CA7101B0E415448454E412E4D49542E454455A81A3018A003020101A111300F1B066866747361691B056578747261A9101B0E415448454E412E4D49542E454455AA1A3018A003020101A111300F1B066866747361691B056578747261AB0A1B086B72623564617461AC0A04086B72623564617461";
    /// The gokrb5 KRB-PRIV fixture.
    const MARSHALLED_KRB_PRIV: &str = concat!(
        "75333031A003020105A103020115A3253023A003020100A103020105A217",
        "04156B726241534E2E312074657374206D657373616765",
    );
    /// The gokrb5 `EncKrbPrivPart` fixture.
    const MARSHALLED_ENC_KRB_PRIV_PART: &str = concat!(
        "7C4F304DA00A04086B72623564617461A111180F31393934303631303036",
        "303331375AA205020301E240A303020111A40F300DA003020102A10604",
        "0412D00023A50F300DA003020102A106040412D00023",
    );
    /// The gokrb5 `EncKrbPrivPart` fixture without optional fields.
    const MARSHALLED_ENC_KRB_PRIV_PART_OPTIONALS_NULL: &str = concat!(
        "7C1F301DA00A04086B72623564617461A40F300DA003020102A10604",
        "0412D00023",
    );
    /// The gokrb5 fixture time, 1994-06-10 06:03:17 UTC, in Unix seconds.
    const TEST_TIME_SECONDS: i64 = 771_228_197;

    /// Pins that a targeted `ChangePasswdData` encodes to and decodes from the gokrb5 fixture.
    #[test]
    fn change_passwd_data_matches_gokrb5_fixture() -> Result<(), TestError> {
        let value = ChangePasswdData::for_target(
            Password::copy_from_str("newpassword"),
            1,
            ["testuser1"],
            "TEST.GOKRB5",
        )
        .context("targeted ChangePasswdData builds")?;
        let expected = decode_hex(MARSHALLED_CHANGE_PASSWD_DATA)?;

        let encoded = value.encode_der().context("ChangePasswdData encodes")?;
        assert_eq!(encoded, expected);

        let decoded =
            ChangePasswdData::decode_der(&expected).context("ChangePasswdData decodes")?;
        assert_eq!(decoded, value);
        assert_eq!(
            decoded
                .encode_der()
                .context("ChangePasswdData re-encodes")?,
            expected
        );
        Ok(())
    }

    /// Pins that a password-only `ChangePasswdData` round-trips without a target.
    #[test]
    fn change_passwd_data_builds_password_only_payload() -> Result<(), TestError> {
        let value = ChangePasswdData::new(Password::copy_from_str("newpassword"));
        let encoded = value.encode_der().context("ChangePasswdData encodes")?;
        let decoded = ChangePasswdData::decode_der(&encoded).context("ChangePasswdData decodes")?;

        assert_eq!(decoded, value);
        assert_eq!(decoded.new_passwd.as_ref(), b"newpassword");
        assert!(decoded.targ_name.is_none());
        assert!(decoded.targ_realm.is_none());
        Ok(())
    }

    /// Pins that the targeted gokrb5 fixture decodes to the built value and re-encodes unchanged.
    #[test]
    fn change_passwd_data_decodes_and_encodes_target_payload() -> Result<(), TestError> {
        let value = ChangePasswdData::decode_der(&decode_hex(MARSHALLED_CHANGE_PASSWD_DATA)?)
            .context("targeted ChangePasswdData decodes")?;
        let expected = ChangePasswdData::for_target(
            Password::copy_from_str("newpassword"),
            1,
            ["testuser1"],
            "TEST.GOKRB5",
        )
        .context("targeted ChangePasswdData builds")?;

        assert_eq!(value, expected);
        assert_eq!(
            value.encode_der().context("ChangePasswdData encodes")?,
            decode_hex(MARSHALLED_CHANGE_PASSWD_DATA)?
        );
        Ok(())
    }

    /// Pins the fields of the gokrb5 KRB-PRIV fixture and its byte-exact re-encoding.
    #[test]
    fn krb_priv_decodes_and_roundtrips_gokrb5_fixture() -> Result<(), TestError> {
        let bytes = decode_hex(MARSHALLED_KRB_PRIV)?;

        let krb_priv = decode_krb_priv(&bytes).context("KRB-PRIV decodes")?;

        assert_eq!(krb_priv.pvno, Integer::from(KRB_PRIV_PVNO));
        assert_eq!(krb_priv.msg_type, Integer::from(KRB_PRIV_MSG_TYPE));
        assert_eq!(krb_priv.enc_part.etype, 0_i32);
        assert_eq!(krb_priv.enc_part.kvno, Some(5));
        assert_eq!(krb_priv.enc_part.cipher.as_ref(), b"krbASN.1 test message");
        assert_eq!(
            encode_krb_priv(&krb_priv).context("KRB-PRIV encodes")?,
            bytes
        );
        Ok(())
    }

    /// Pins the fields of the gokrb5 `EncKrbPrivPart` fixture.
    #[test]
    fn enc_krb_priv_part_decodes_gokrb5_fixture() -> Result<(), TestError> {
        let enc_part = decode_enc_krb_priv_part(&decode_hex(MARSHALLED_ENC_KRB_PRIV_PART)?)
            .context("EncKrbPrivPart decodes")?;

        assert_eq!(enc_part.user_data.as_ref(), b"krb5data");
        assert_eq!(
            enc_part
                .timestamp
                .as_ref()
                .context("timestamp")?
                .0
                .timestamp(),
            TEST_TIME_SECONDS
        );
        assert_eq!(enc_part.usec, Some(Integer::from(123_456_i32)));
        assert_eq!(enc_part.seq_number, Some(17));
        assert_eq!(enc_part.sender_address.addr_type, 2_i32);
        assert_eq!(
            enc_part.sender_address.address.as_ref(),
            decode_hex("12d00023")?
        );
        assert_eq!(
            enc_part
                .recipient_address
                .as_ref()
                .context("recipient address")?
                .address
                .as_ref(),
            decode_hex("12d00023")?
        );
        Ok(())
    }

    /// Pins the gokrb5 `EncKrbPrivPart` fixture without its optional fields.
    #[test]
    fn enc_krb_priv_part_decodes_gokrb5_optionals_null_fixture() -> Result<(), TestError> {
        let enc_part =
            decode_enc_krb_priv_part(&decode_hex(MARSHALLED_ENC_KRB_PRIV_PART_OPTIONALS_NULL)?)
                .context("EncKrbPrivPart decodes")?;

        assert_eq!(enc_part.user_data.as_ref(), b"krb5data");
        assert!(enc_part.timestamp.is_none());
        assert!(enc_part.usec.is_none());
        assert!(enc_part.seq_number.is_none());
        assert_eq!(enc_part.sender_address.addr_type, 2_i32);
        assert_eq!(
            enc_part.sender_address.address.as_ref(),
            decode_hex("12d00023")?
        );
        assert!(enc_part.recipient_address.is_none());
        Ok(())
    }

    /// Pins that a KRB-PRIV built with a fixed confounder decrypts to its payload, addresses and sequence number.
    #[test]
    fn krb_priv_builder_encrypts_change_password_payload() -> Result<(), TestError> {
        let data = ChangePasswdData::new(Password::copy_from_str("newpassword"))
            .encode_der()
            .context("ChangePasswdData encodes")?;
        let key = EncryptionKey::new(18, vec![0x11; 32]);
        let sender_address = ipv4_host_address([127, 0, 0, 1]);
        let recipient_address = ipv6_host_address([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let options = EncKrbPrivPartOptions::new(sender_address.clone())
            .with_sequence_number(7)
            .with_recipient_address(recipient_address.clone());
        let etype = KerberosEtype::from_etype_id(key.etype).context("AES256 etype")?;
        let confounder = vec![0x22; etype.confounder_len()];

        let krb_priv = build_krb_priv_with_confounder(&data, options, &key, &confounder)
            .context("KRB-PRIV builds")?;

        assert_eq!(krb_priv.pvno, Integer::from(KRB_PRIV_PVNO));
        assert_eq!(krb_priv.msg_type, Integer::from(KRB_PRIV_MSG_TYPE));
        assert_eq!(krb_priv.enc_part.etype, key.etype);
        assert!(krb_priv.enc_part.kvno.is_none());

        let enc_part =
            decrypt_krb_priv_enc_part(&krb_priv, &key).context("KRB-PRIV decrypts and decodes")?;
        let decoded_data =
            ChangePasswdData::decode_der(enc_part.user_data.as_ref()).context("payload decodes")?;

        assert_eq!(
            decoded_data,
            ChangePasswdData::new(Password::copy_from_str("newpassword"))
        );
        assert_eq!(enc_part.sender_address, sender_address);
        assert_eq!(enc_part.recipient_address, Some(recipient_address));
        assert_eq!(enc_part.seq_number, Some(7));
        Ok(())
    }

    /// Pins that a KRB-PRIV built with a random confounder decrypts to its payload.
    #[test]
    fn krb_priv_builder_generates_confounder_for_change_password_payload() -> Result<(), TestError>
    {
        let data = ChangePasswdData::new(Password::copy_from_str("newpassword"))
            .encode_der()
            .context("ChangePasswdData encodes")?;
        let key = EncryptionKey::new(18, vec![0x11; 32]);
        let sender_address = ipv4_host_address([127, 0, 0, 1]);
        let options = EncKrbPrivPartOptions::new(sender_address.clone()).with_sequence_number(8);

        let krb_priv = build_krb_priv(&data, options, &key).context("KRB-PRIV builds")?;

        assert_eq!(krb_priv.enc_part.etype, key.etype);

        let enc_part =
            decrypt_krb_priv_enc_part(&krb_priv, &key).context("KRB-PRIV decrypts and decodes")?;
        let decoded_data =
            ChangePasswdData::decode_der(enc_part.user_data.as_ref()).context("payload decodes")?;

        assert_eq!(
            decoded_data,
            ChangePasswdData::new(Password::copy_from_str("newpassword"))
        );
        assert_eq!(enc_part.sender_address, sender_address);
        assert_eq!(enc_part.seq_number, Some(8));
        Ok(())
    }

    /// Pins the frame header and messages of the gokrb5 kpasswd request and its re-encoding.
    #[test]
    fn kpasswd_request_roundtrips_gokrb5_fixture() -> Result<(), TestError> {
        let bytes = decode_hex(MARSHALLED_KPASSWD_REQ)?;
        let request = Request::parse(&bytes).context("kpasswd request parses")?;

        assert_eq!(usize::from(read_u16(&bytes, 0)?), bytes.len());
        assert_eq!(read_u16(&bytes, 2)?, 0xff80);
        assert_eq!(read_u16(&bytes, 4)?, 705);
        assert_eq!(request.ap_req.pvno, Integer::from(5_i32));
        assert_eq!(request.ap_req.msg_type, Integer::from(14_i32));
        assert_eq!(request.ap_req.authenticator.etype, 18_i32);
        assert_eq!(request.krb_priv.pvno, Integer::from(5_i32));
        assert_eq!(request.krb_priv.msg_type, Integer::from(21_i32));
        assert_eq!(request.krb_priv.enc_part.etype, 18_i32);
        assert_eq!(request.encode().context("request encodes")?, bytes);
        Ok(())
    }

    /// Pins that the gokrb5 kpasswd request re-encodes byte for byte.
    #[test]
    fn kpasswd_request_parse_and_encode_roundtrip() -> Result<(), TestError> {
        let bytes = decode_hex(MARSHALLED_KPASSWD_REQ)?;
        let request = Request::parse(&bytes).context("request parses")?;

        assert_eq!(request.encode().context("request encodes")?, bytes);
        Ok(())
    }

    /// Pins that a request built with a fixed confounder keeps the AP-REQ and decrypts to its payload.
    #[test]
    fn kpasswd_request_builder_encrypts_payload_and_frames_request() -> Result<(), TestError> {
        let fixture_request = Request::parse(&decode_hex(MARSHALLED_KPASSWD_REQ)?)
            .context("fixture request parses")?;
        let change_data = ChangePasswdData::for_target(
            Password::copy_from_str("replacement-password"),
            1,
            ["target-user"],
            "TEST.GOKRB5",
        )
        .context("targeted ChangePasswdData builds")?;
        let reply_key = EncryptionKey::new(18, vec![0x44; 32]);
        let sender_address = ipv4_host_address([127, 0, 0, 1]);
        let recipient_address = ipv6_host_address([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let options = EncKrbPrivPartOptions::new(sender_address.clone())
            .with_sequence_number(99)
            .with_recipient_address(recipient_address.clone());
        let etype = KerberosEtype::from_etype_id(reply_key.etype).context("AES256 etype")?;
        let confounder = vec![0x55; etype.confounder_len()];

        let built = build_change_password_request_with_confounder(
            fixture_request.ap_req.clone(),
            &change_data,
            reply_key.clone(),
            options,
            &confounder,
        )
        .context("kpasswd request builds")?;

        assert_eq!(built.reply_key, reply_key);
        assert_eq!(built.request.ap_req, fixture_request.ap_req);

        let parsed = Request::parse(&built.der).context("built request parses")?;
        assert_eq!(parsed.ap_req, fixture_request.ap_req);

        let enc_part =
            decrypt_krb_priv_enc_part(&parsed.krb_priv, &reply_key).context("payload decrypts")?;
        let decoded_data =
            ChangePasswdData::decode_der(enc_part.user_data.as_ref()).context("payload decodes")?;

        assert_eq!(decoded_data, change_data);
        assert_eq!(enc_part.sender_address, sender_address);
        assert_eq!(enc_part.recipient_address, Some(recipient_address));
        assert_eq!(enc_part.seq_number, Some(99));
        Ok(())
    }

    /// Pins that a request built with a random confounder keeps the AP-REQ and decrypts to its payload.
    #[test]
    fn kpasswd_request_builder_generates_krb_priv_confounder() -> Result<(), TestError> {
        let fixture_request = Request::parse(&decode_hex(MARSHALLED_KPASSWD_REQ)?)
            .context("fixture request parses")?;
        let change_data = ChangePasswdData::new(Password::copy_from_str("replacement-password"));
        let reply_key = EncryptionKey::new(18, vec![0x66; 32]);
        let sender_address = ipv4_host_address([127, 0, 0, 1]);
        let options = EncKrbPrivPartOptions::new(sender_address.clone()).with_sequence_number(101);

        let built = build_change_password_request(
            fixture_request.ap_req.clone(),
            &change_data,
            reply_key.clone(),
            options,
        )
        .context("kpasswd request builds")?;

        assert_eq!(built.reply_key, reply_key);

        let parsed = Request::parse(&built.der).context("built request parses")?;
        assert_eq!(parsed.ap_req, fixture_request.ap_req);

        let enc_part =
            decrypt_krb_priv_enc_part(&parsed.krb_priv, &reply_key).context("payload decrypts")?;
        let decoded_data =
            ChangePasswdData::decode_der(enc_part.user_data.as_ref()).context("payload decodes")?;

        assert_eq!(decoded_data, change_data);
        assert_eq!(enc_part.sender_address, sender_address);
        assert_eq!(enc_part.seq_number, Some(101));
        Ok(())
    }

    /// Pins the authenticator and KRB-PRIV of a full change-password message built with explicit confounders.
    #[test]
    fn kpasswd_request_builds_full_message_with_explicit_context() -> Result<(), TestError> {
        let fixture_request = Request::parse(&decode_hex(MARSHALLED_KPASSWD_REQ)?)
            .context("kpasswd request parses")?;
        let service_ticket = fixture_request.ap_req.ticket.clone();
        let service_session_key =
            EncryptionKey::new(fixture_request.ap_req.authenticator.etype, vec![0x11; 32]);
        let reply_key =
            EncryptionKey::new(fixture_request.ap_req.authenticator.etype, vec![0x55; 32]);
        let options = ChangePasswdMessageOptions::new(
            kerberos_time(1_893_553_452)?,
            456_789,
            42,
            ipv4_host_address([127, 0, 0, 1]),
        )
        .with_recipient_address(ipv4_host_address([127, 0, 0, 2]));
        let change_data = ChangePasswdData::new(Password::copy_from_str("newpassword"));

        let built = build_change_password_message_with_confounders(
            rasn_principal_name(1, ["testuser1"])?,
            "TEST.GOKRB5",
            &change_data,
            service_ticket,
            &service_session_key,
            options,
            rskrb5_ng::kadmin::PasswordEncryption::new(
                reply_key.clone(),
                &decode_hex(CHG_PASSWD_MSG_AP_REQ_CONFOUNDER)?,
                &decode_hex(CHG_PASSWD_MSG_KRB_PRIV_CONFOUNDER)?,
            ),
        )
        .context("kpasswd message builds")?;

        let parsed = Request::parse(&built.der).context("built message parses")?;
        let authenticator_usage = ap_req::authenticator_usage_for_ticket(&parsed.ap_req.ticket);
        let authenticator = ap_req::decrypt_ap_req_authenticator(
            &parsed.ap_req,
            &service_session_key,
            authenticator_usage,
        )
        .context("AP-REQ authenticator decrypts")?;

        assert_eq!(authenticator.cname, rasn_principal_name(1, ["testuser1"])?);
        assert_eq!(authenticator.crealm, kerberos_string("TEST.GOKRB5")?);
        assert_eq!(authenticator.cusec, Integer::from(456_789_i32));
        assert_eq!(authenticator.seq_number, Some(42));
        assert_eq!(authenticator.subkey, Some(rasn_encryption_key(&reply_key)));

        let enc_part =
            decrypt_krb_priv_enc_part(&parsed.krb_priv, &reply_key).context("KRB-PRIV decrypts")?;
        let decoded_data =
            ChangePasswdData::decode_der(enc_part.user_data.as_ref()).context("payload decodes")?;
        assert_eq!(decoded_data, change_data);
        assert_eq!(enc_part.seq_number, Some(42));
        assert_eq!(enc_part.sender_address, ipv4_host_address([127, 0, 0, 1]));
        assert_eq!(
            enc_part
                .recipient_address
                .as_ref()
                .context("recipient address")?,
            &ipv4_host_address([127, 0, 0, 2])
        );
        assert_eq!(enc_part.timestamp, Some(kerberos_time(1_893_553_452)?));
        assert_eq!(enc_part.usec, Some(Integer::from(456_789_i32)));
        assert_eq!(built.request, parsed);
        Ok(())
    }

    /// Rejects invalid explicit time scalars before constructing a mutation frame.
    #[test]
    fn password_request_builders_validate_scalars() -> Result<(), TestError> {
        use rskrb5_ng::kadmin::{
            build_change_password_request, build_change_password_request_with_confounder,
        };
        for random in [false, true] {
            for (micros, fractional) in [
                (-1_i32, false),
                (1_000_000_i32, false),
                (0_i32, true),
                (0_i32, false),
                (999_999_i32, false),
            ] {
                let fixture = Request::parse(&decode_hex(MARSHALLED_KPASSWD_REQ)?)?;
                let mut time = kerberos_time(1_893_553_452)?;
                if fractional {
                    time.0 += chrono::Duration::nanoseconds(1);
                }
                let mut options = EncKrbPrivPartOptions::new(ipv4_host_address([127, 0, 0, 1]));
                options.timestamp = Some(time);
                options.usec = Some(micros.into());
                let data = ChangePasswdData::new(Password::copy_from_str("scalar-fixture"));
                let key = EncryptionKey::new(18, vec![0x11; 32]);
                let result = if random {
                    build_change_password_request(fixture.ap_req, &data, key, options)
                } else {
                    build_change_password_request_with_confounder(
                        fixture.ap_req,
                        &data,
                        key,
                        options,
                        &[0; 16],
                    )
                };
                assert_eq!(
                    result.is_ok(),
                    !fractional && (0_i32..=999_999_i32).contains(&micros)
                );
            }
        }
        Ok(())
    }

    /// Rejects invalid explicit time scalars before constructing a mutation frame.
    #[test]
    fn protocol_time_kpasswd_builder_rejects_invalid_scalars() -> Result<(), TestError> {
        // Given a service ticket and explicit invalid request metadata.
        for fractional in [false, true] {
            let request = Request::parse(&decode_hex(MARSHALLED_KPASSWD_REQ)?)?;
            let key = EncryptionKey::new(18, vec![0x11; 32]);
            let mut time = kerberos_time(1_893_553_452)?;
            if fractional {
                time.0 += chrono::Duration::nanoseconds(1);
            }
            let options = ChangePasswdMessageOptions::new(
                time,
                if fractional { 0 } else { 1_000_000 },
                42,
                ipv4_host_address([127, 0, 0, 1]),
            );
            // When construction runs, then no invalid wire request is produced.
            let _error = build_change_password_message(
                rasn_principal_name(1, ["testuser1"])?,
                "TEST.GOKRB5",
                &ChangePasswdData::new(Password::copy_from_str("dummy-password")),
                request.ap_req.ticket,
                &key,
                options,
            )
            .err()
            .context("invalid request time rejected")?;
        }
        Ok(())
    }

    /// Redacts password-specific ownership rather than exposing bytes to loggers.
    #[test]
    fn password_plaintext_debug_is_redacted() -> Result<(), TestError> {
        // Given a recognizable password, when rendered, then only its marker survives.
        let data = ChangePasswdData::for_target(
            Password::copy_from_str("password-secret-canary"),
            1,
            ["dummy"],
            "TEST.GOKRB5",
        )?;
        let rendered = format!("{data:?}");
        assert!(!rendered.contains("password-secret-canary"));
        assert!(!rendered.contains("112, 97, 115, 115"));
        assert!(rendered.contains("[REDACTED]"));
        Ok(())
    }

    /// Pins that a built change-password message decrypts to its targeted payload.
    #[test]
    fn kpasswd_request_build_change_password_message_builds_and_decrypts_payload()
    -> Result<(), TestError> {
        let fixture_request = Request::parse(&decode_hex(MARSHALLED_KPASSWD_REQ)?)
            .context("kpasswd request parses")?;
        let service_ticket = fixture_request.ap_req.ticket;
        let service_session_key =
            EncryptionKey::new(fixture_request.ap_req.authenticator.etype, vec![0x22; 32]);
        let options = ChangePasswdMessageOptions::new(
            kerberos_time(1_893_553_453)?,
            654_321,
            7,
            ipv4_host_address([127, 0, 0, 1]),
        );
        let change_data = ChangePasswdData::for_target(
            Password::copy_from_str("updated-password"),
            1,
            ["target-user"],
            "TEST.GOKRB5",
        )
        .context("targeted ChangePasswdData builds")?;

        let built = build_change_password_message(
            rasn_principal_name(1, ["testuser1"])?,
            "TEST.GOKRB5",
            &change_data,
            service_ticket,
            &service_session_key,
            options,
        )
        .context("change-password message builds")?;

        let parsed = Request::parse(&built.der).context("change-password message parses")?;
        let enc_part = decrypt_krb_priv_enc_part(&parsed.krb_priv, &built.reply_key)
            .context("KRB-PRIV decrypts")?;
        let decoded_data =
            ChangePasswdData::decode_der(enc_part.user_data.as_ref()).context("payload decodes")?;

        assert_eq!(decoded_data, change_data);
        Ok(())
    }

    /// Pins that a change-password message for the client itself decrypts to its payload.
    #[test]
    fn kpasswd_request_build_change_password_message_supports_self_target_payload()
    -> Result<(), TestError> {
        let fixture_request = Request::parse(&decode_hex(MARSHALLED_KPASSWD_REQ)?)
            .context("kpasswd request parses")?;
        let service_ticket = fixture_request.ap_req.ticket;
        let service_session_key =
            EncryptionKey::new(fixture_request.ap_req.authenticator.etype, vec![0x44; 32]);
        let change_data = ChangePasswdData::for_target(
            Password::copy_from_str("default-style-password"),
            1,
            ["testuser1"],
            "TEST.GOKRB5",
        )
        .context("targeted ChangePasswdData builds")?;
        let options = ChangePasswdMessageOptions::new(
            kerberos_time(1_893_553_456)?,
            123_987,
            23,
            ipv4_host_address([127, 0, 0, 1]),
        );

        let built = build_change_password_message(
            rasn_principal_name(1, ["testuser1"])?,
            "TEST.GOKRB5",
            &change_data,
            service_ticket,
            &service_session_key,
            options,
        )
        .context("change-password message builds")?;

        let parsed = Request::parse(&built.der).context("change-password message parses")?;
        let enc_part = decrypt_krb_priv_enc_part(&parsed.krb_priv, &built.reply_key)
            .context("KRB-PRIV decrypts")?;
        let decoded_data =
            ChangePasswdData::decode_der(enc_part.user_data.as_ref()).context("payload decodes")?;

        assert_eq!(decoded_data, change_data);
        assert_eq!(enc_part.sender_address, ipv4_host_address([127, 0, 0, 1]));
        assert_eq!(parsed, built.request);
        Ok(())
    }

    /// Pins that a message built with explicit confounders decrypts under the given reply key.
    #[test]
    fn kpasswd_request_build_change_password_message_with_confounders_decrypts_payload()
    -> Result<(), TestError> {
        let fixture_request = Request::parse(&decode_hex(MARSHALLED_KPASSWD_REQ)?)
            .context("kpasswd request parses")?;
        let service_ticket = fixture_request.ap_req.ticket;
        let service_session_key =
            EncryptionKey::new(fixture_request.ap_req.authenticator.etype, vec![0x33; 32]);
        let reply_key =
            EncryptionKey::new(fixture_request.ap_req.authenticator.etype, vec![0x44; 32]);
        let options = ChangePasswdMessageOptions::new(
            kerberos_time(1_893_553_454)?,
            321_654,
            9,
            ipv4_host_address([127, 0, 0, 1]),
        )
        .with_recipient_address(ipv4_host_address([127, 0, 0, 2]));
        let change_data = ChangePasswdData::for_target(
            Password::copy_from_str("alias-with-confounders"),
            1,
            ["target-user"],
            "TEST.GOKRB5",
        )
        .context("targeted ChangePasswdData builds")?;
        let ap_req_confounder = vec![0x9a; 16];
        let krb_priv_confounder = vec![0x9b; 16];

        let built = build_change_password_message_with_confounders(
            rasn_principal_name(1, ["testuser1"])?,
            "TEST.GOKRB5",
            &change_data,
            service_ticket,
            &service_session_key,
            options,
            rskrb5_ng::kadmin::PasswordEncryption::new(
                reply_key.clone(),
                &ap_req_confounder,
                &krb_priv_confounder,
            ),
        )
        .context("change-password message with confounders builds")?;

        let parsed = Request::parse(&built.der).context("change-password message parses")?;
        let enc_part =
            decrypt_krb_priv_enc_part(&parsed.krb_priv, &reply_key).context("KRB-PRIV decrypts")?;
        let decoded_data =
            ChangePasswdData::decode_der(enc_part.user_data.as_ref()).context("payload decodes")?;

        assert_eq!(decoded_data, change_data);
        Ok(())
    }

    /// Pins that a message built with a generated reply key decrypts under the returned key.
    #[test]
    fn kpasswd_request_build_change_password_message_generates_keys_and_keeps_context()
    -> Result<(), TestError> {
        let fixture_request = Request::parse(&decode_hex(MARSHALLED_KPASSWD_REQ)?)
            .context("kpasswd request parses")?;
        let service_ticket = fixture_request.ap_req.ticket;
        let service_session_key =
            EncryptionKey::new(fixture_request.ap_req.authenticator.etype, vec![0x77; 32]);
        let options = ChangePasswdMessageOptions::new(
            kerberos_time(1_893_553_455)?,
            147_258,
            13,
            ipv4_host_address([127, 0, 0, 1]),
        );
        let change_data = ChangePasswdData::new(Password::copy_from_str("randomized-reply-key"));

        let built = build_change_password_message(
            rasn_principal_name(1, ["testuser1"])?,
            "TEST.GOKRB5",
            &change_data,
            service_ticket,
            &service_session_key,
            options,
        )
        .context("gokrb5-compatible message builder")?;

        let parsed = Request::parse(&built.der).context("message parses")?;
        let encoded = ChangePasswdData::decode_der(
            decrypt_krb_priv_enc_part(&parsed.krb_priv, &built.reply_key)
                .context("KRB-PRIV decrypts")?
                .user_data
                .as_ref(),
        )
        .context("payload decodes")?;

        assert_eq!(encoded, change_data);
        Ok(())
    }

    /// Pins the errors for a wrong request version and inconsistent AP-REQ lengths.
    #[test]
    fn kpasswd_request_rejects_malformed_frames() {
        assert!(matches!(
            Request::parse(&[0, 6, 0, 1, 0, 0]),
            Err(KadminError::InvalidRequestVersion(1))
        ));

        assert!(matches!(
            Request::parse(&[0, 7, 0xff, 0x80, 0, 0, 0]),
            Err(KadminError::InvalidApReqLength {
                ap_req_length: 0,
                body_length: 1
            })
        ));

        assert!(matches!(
            Request::parse(&[0, 7, 0xff, 0x80, 0, 1, 0]),
            Err(KadminError::InvalidApReqLength {
                ap_req_length: 1,
                body_length: 1
            })
        ));
    }

    /// Pins the frame header, AP-REP and KRB-PRIV of the gokrb5 kpasswd reply.
    #[test]
    fn kpasswd_reply_matches_gokrb5_fixture() -> Result<(), TestError> {
        let bytes = decode_hex(MARSHALLED_KPASSWD_REP)?;
        let reply = Reply::parse(&bytes).context("kpasswd reply parses")?;

        assert_eq!(reply.message_length, 236);
        assert_eq!(reply.version, 1);
        assert_eq!(reply.ap_rep_length, 140);
        assert!(!reply.is_krb_error());
        assert!(reply.krb_error.is_none());
        assert!(reply.result.is_none());

        let ap_rep = reply.ap_rep.context("AP-REP parsed")?;
        assert_eq!(ap_rep.pvno, Integer::from(5_i32));
        assert_eq!(ap_rep.msg_type, Integer::from(15_i32));
        assert_eq!(ap_rep.enc_part.etype, 18_i32);

        let krb_priv = reply.krb_priv.context("KRB-PRIV parsed")?;
        assert_eq!(krb_priv.pvno, Integer::from(5_i32));
        assert_eq!(krb_priv.msg_type, Integer::from(21_i32));
        assert_eq!(krb_priv.enc_part.etype, 18_i32);
        Ok(())
    }

    /// Pins that the gokrb5 success reply re-encodes byte for byte.
    #[test]
    fn kpasswd_reply_roundtrips_success_reply() -> Result<(), TestError> {
        let bytes = decode_hex(MARSHALLED_KPASSWD_REP)?;
        let reply = Reply::parse(&bytes).context("kpasswd reply parses")?;

        assert_eq!(reply.encode().context("reply encodes")?, bytes);
        Ok(())
    }

    /// Pins that `decrypt_result` returns the result parsed from a KRB-ERROR e-data.
    #[test]
    fn kpasswd_reply_decrypt_result_returns_parsed_error_result() -> Result<(), TestError> {
        let bytes = kpasswd_reply_frame(0, &decode_hex(KRB_ERROR_WITH_EDATA)?)?;
        let reply = Reply::parse(&bytes).map_err(|cause| format!("reply parses: {cause}"))?;
        let key = EncryptionKey::new(18, vec![0; 32]);
        let expected = ChangePasswordResult::parse(b"krb5data")?;

        assert!(reply.result.is_some());
        assert_eq!(
            reply
                .decrypt_result(&key)
                .map_err(|cause| format!("result decrypts: {cause}"))?,
            expected
        );
        Ok(())
    }

    /// Pins that a KRB-ERROR reply re-encodes byte for byte.
    #[test]
    fn kpasswd_reply_roundtrips_error_reply() -> Result<(), TestError> {
        let bytes = kpasswd_reply_frame(0, &decode_hex(KRB_ERROR_WITH_EDATA)?)?;
        let reply = Reply::parse(&bytes).context("KRB-ERROR reply parses")?;

        assert_eq!(reply.encode().context("reply encodes")?, bytes);
        Ok(())
    }

    /// Accepts the RFC 3244 unencapsulated error and preserves its wire profile.
    #[test]
    fn kpasswd_bare_error_roundtrips() -> Result<(), TestError> {
        // Given a standalone application-30 error, not a kpasswd frame.
        let bytes = decode_hex(KRB_ERROR_WITH_EDATA)?;
        // When the response parser dispatches it.
        let reply = Reply::parse(&bytes)?;
        // Then it retains the error result and bare encoding.
        assert!(reply.is_krb_error());
        assert_eq!(
            reply.decrypt_result(&EncryptionKey::new(18, vec![0; 32]))?,
            ChangePasswordResult::parse(b"krb5data")?
        );
        assert_eq!(reply.encode()?, bytes);
        Ok(())
    }

    /// Rejects unauthenticated success in both bare and legacy wrapped errors.
    #[test]
    fn kpasswd_bare_error_cannot_assert_success() -> Result<(), TestError> {
        // Given an error carrying a forged success result.
        let mut error: KrbError = der::decode(&decode_hex(KRB_ERROR_WITH_EDATA)?)?;
        error.e_data = Some(vec![0, 0].into());
        let bare = der::encode(&error)?;
        for bytes in [bare.clone(), kpasswd_reply_frame(0, &bare)?] {
            // When the result is consumed, then unauthenticated success is rejected.
            let reply = Reply::parse(&bytes)?;
            assert!(matches!(
                reply.decrypt_result(&EncryptionKey::new(18, vec![0; 32])),
                Err(KadminError::UnauthenticatedSuccess)
            ));
        }
        Ok(())
    }

    /// Rejects extra bytes beyond a complete framed request or reply.
    #[test]
    fn kpasswd_rejects_complete_frame_suffix() -> Result<(), TestError> {
        // Given complete frames followed by a second, unchecked value.
        let mut request = decode_hex(MARSHALLED_KPASSWD_REQ)?;
        let mut reply = decode_hex(MARSHALLED_KPASSWD_REP)?;
        request.extend_from_slice(&[0x05, 0]);
        reply.extend_from_slice(&[0x05, 0]);
        // When each whole-frame boundary parses, then both reject the suffix.
        let _request_error = Request::parse(&request)
            .err()
            .context("request suffix rejected")?;
        let _reply_error = Reply::parse(&reply)
            .err()
            .context("reply suffix rejected")?;
        Ok(())
    }

    /// Pins that a KRB-ERROR reply with an AP-REP and KRB-PRIV cannot be encoded.
    #[test]
    fn kpasswd_reply_rejects_mixed_error_payloads() -> Result<(), TestError> {
        let mut reply = Reply::parse(&kpasswd_reply_frame(0, &decode_hex(KRB_ERROR_WITH_EDATA)?)?)
            .context("KRB-ERROR reply parses")?;
        let success =
            Reply::parse(&decode_hex(MARSHALLED_KPASSWD_REP)?).context("KRB-REP reply parses")?;
        reply.ap_rep = success.ap_rep;
        reply.krb_priv = success.krb_priv;

        assert!(matches!(
            reply.encode(),
            Err(KadminError::InvalidErrorReplyPayload)
        ));
        Ok(())
    }

    /// Pins that a success reply without a KRB-PRIV cannot be encoded.
    #[test]
    fn kpasswd_reply_rejects_success_payloads_without_krb_priv() -> Result<(), TestError> {
        let mut reply =
            Reply::parse(&decode_hex(MARSHALLED_KPASSWD_REP)?).context("KRB-REP reply parses")?;
        reply.krb_priv = None;

        assert!(matches!(reply.encode(), Err(KadminError::MissingKrbPriv)));
        Ok(())
    }

    /// Pins that a success reply without an AP-REP cannot be encoded.
    #[test]
    fn kpasswd_reply_rejects_success_payloads_without_ap_rep() -> Result<(), TestError> {
        let mut reply =
            Reply::parse(&decode_hex(MARSHALLED_KPASSWD_REP)?).context("KRB-REP reply parses")?;
        reply.ap_rep = None;

        assert!(matches!(reply.encode(), Err(KadminError::MissingApRep)));
        Ok(())
    }

    /// Pins the frame fields and the result parsed from a KRB-ERROR kpasswd reply.
    #[test]
    fn kpasswd_reply_parses_krb_error_response_data() -> Result<(), TestError> {
        let error = decode_hex(KRB_ERROR_WITH_EDATA)?;
        let frame = kpasswd_reply_frame(0, &error)?;
        let reply =
            Reply::parse(&frame).map_err(|cause| format!("KRB-ERROR reply parses: {cause}"))?;

        assert_eq!(usize::from(reply.message_length), frame.len());
        assert_eq!(reply.version, 1);
        assert_eq!(reply.ap_rep_length, 0);
        assert!(reply.is_krb_error());
        assert!(reply.ap_rep.is_none());
        assert!(reply.krb_priv.is_none());
        assert!(reply.krb_error.is_some());
        assert_eq!(
            reply.result,
            Some(ChangePasswordResult::parse(b"krb5data")?)
        );
        Ok(())
    }

    /// Pins that a KRB-ERROR result needs no decryption key.
    #[test]
    fn kpasswd_reply_decrypt_result_returns_krb_error_result() -> Result<(), TestError> {
        let reply = Reply::parse(&kpasswd_reply_frame(0, &decode_hex(KRB_ERROR_WITH_EDATA)?)?)
            .map_err(|cause| format!("KRB-ERROR reply parses: {cause}"))?;
        let key = EncryptionKey::new(18, vec![0; 32]);

        assert_eq!(
            reply
                .decrypt_result(&key)
                .map_err(|cause| format!("KRB-ERROR result needs no decrypt: {cause}"))?,
            ChangePasswordResult::parse(b"krb5data")?
        );
        Ok(())
    }

    /// Pins that result code 0 is a success.
    #[test]
    fn kpasswd_result_success_helper_accepts_zero_code() -> Result<(), TestError> {
        let result = ChangePasswordResult::parse(&[0, 0]).context("success result parses")?;

        assert_eq!(result.code, KPASSWD_SUCCESS);
        assert!(result.is_success());
        assert_eq!(result.ensure_success(), Ok(()));
        Ok(())
    }

    /// Pins that `ensure_success` reports a failure code with its text.
    #[test]
    fn kpasswd_result_success_helper_reports_failure_code() -> Result<(), TestError> {
        let result = ChangePasswordResult::parse(b"\x00\x03authentication failed")?;

        assert!(!result.is_success());
        assert!(matches!(
            result.ensure_success(),
            Err(KadminError::PasswordChangeFailed { code, text, text_raw: _ })
                if code == KPASSWD_AUTHERROR && text == "authentication failed"
        ));
        Ok(())
    }

    /// Pins that a key whose etype differs from the KRB-PRIV's is rejected.
    #[test]
    fn kpasswd_reply_decrypt_result_rejects_wrong_key_etype() -> Result<(), TestError> {
        let reply =
            Reply::parse(&decode_hex(MARSHALLED_KPASSWD_REP)?).context("kpasswd reply parses")?;
        let key = EncryptionKey::new(17, vec![0; 16]);

        assert!(matches!(
            reply.decrypt_result(&key),
            Err(KadminError::KeyEtypeMismatch {
                key_etype: 17_i32,
                encrypted_data_etype: 18_i32,
            })
        ));
        Ok(())
    }

    /// Pins the errors for short, truncated, misversioned and inconsistent reply frames.
    #[test]
    fn kpasswd_reply_rejects_malformed_frames() {
        assert!(matches!(
            Reply::parse(&[0, 1]),
            Err(KadminError::FrameTooShort { actual: 2 })
        ));

        assert!(matches!(
            Reply::parse(&[0, 7, 0, 1, 0, 0]),
            Err(KadminError::TruncatedFrame {
                expected: 7,
                actual: 6
            })
        ));

        assert!(matches!(
            Reply::parse(&[0, 6, 0, 2, 0, 0]),
            Err(KadminError::InvalidReplyVersion(2))
        ));

        assert!(matches!(
            Reply::parse(&[0, 7, 0, 1, 0, 1, 0]),
            Err(KadminError::InvalidApRepLength {
                ap_rep_length: 1,
                body_length: 1
            })
        ));
    }

    /// Decodes a hex fixture, ignoring surrounding whitespace.
    fn decode_hex(input: &str) -> Result<Vec<u8>, TestError> {
        Ok(hex::decode(input.trim())?)
    }

    /// Frames `body` as a kpasswd reply with the given AP-REP length.
    fn kpasswd_reply_frame(ap_rep_length: u16, body: &[u8]) -> Result<Vec<u8>, TestError> {
        let message_length = HEADER_LEN
            .checked_add(body.len())
            .context("the frame length fits usize")?;
        let length_field = u16::try_from(message_length).context("the frame length fits u16")?;

        let mut frame = Vec::with_capacity(message_length);
        frame.extend_from_slice(&length_field.to_be_bytes());
        frame.extend_from_slice(&1_u16.to_be_bytes());
        frame.extend_from_slice(&ap_rep_length.to_be_bytes());
        frame.extend_from_slice(body);
        Ok(frame)
    }

    /// Reads the big-endian `u16` at `offset`.
    fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, TestError> {
        let end = offset.checked_add(2).context("the field end fits usize")?;
        let field: [u8; 2] = bytes
            .get(offset..end)
            .context("the field is in bounds")?
            .try_into()?;
        Ok(u16::from_be_bytes(field))
    }

    /// Length of the kpasswd reply frame header.
    const HEADER_LEN: usize = 6;

    /// The UTC Kerberos time `seconds` after the Unix epoch.
    fn kerberos_time(seconds: i64) -> Result<KerberosTime, TestError> {
        let utc = DateTime::<Utc>::from_timestamp(seconds, 0).context("valid time")?;
        let offset = FixedOffset::east_opt(0).context("UTC offset exists")?;
        Ok(KerberosTime(utc.with_timezone(&offset)))
    }

    /// A principal name of `name_type` with `components`.
    fn rasn_principal_name<I, S>(name_type: i32, components: I) -> Result<PrincipalName, TestError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        Ok(PrincipalName {
            r#type: name_type,
            string: components
                .into_iter()
                .map(|component| kerberos_string(component.as_ref()))
                .collect::<Result<_, _>>()?,
        })
    }

    /// `value` as a `KerberosString`.
    fn kerberos_string(value: &str) -> Result<KerberosString, TestError> {
        KerberosString::try_from(value).context("valid KerberosString")
    }

    /// `key` as a `rasn_kerberos` encryption key.
    fn rasn_encryption_key(key: &EncryptionKey) -> rasn_kerberos::EncryptionKey {
        rasn_kerberos::EncryptionKey {
            r#type: key.etype,
            value: key.value.to_vec().into(),
        }
    }

    /// Pins that a KRB-ERROR reply carrying a success result code is rejected as unauthenticated.
    #[test]
    fn kpasswd_reply_rejects_unsigned_krb_error_success_result() -> Result<(), TestError> {
        let mut result = Vec::new();
        result.extend_from_slice(&KPASSWD_SUCCESS.to_be_bytes());
        result.extend_from_slice(b"password changed");
        let error = KrbError {
            pvno: Integer::from(5_i32),
            msg_type: Integer::from(30_i32),
            ctime: None,
            cusec: None,
            stime: kerberos_time(1_893_553_440)?,
            susec: Integer::from(0_i32),
            error_code: 52,
            crealm: Some(kerberos_string("TEST.GOKRB5")?),
            cname: Some(rasn_principal_name(1, ["testuser1"])?),
            realm: kerberos_string("TEST.GOKRB5")?,
            sname: rasn_principal_name(1, ["kadmin", "changepw"])?,
            e_text: None,
            e_data: Some(result.into()),
        };
        let encoded = der::encode(&error).map_err(|cause| format!("KRB-ERROR encodes: {cause}"))?;
        let reply = Reply::parse(&kpasswd_reply_frame(0, &encoded)?)
            .map_err(|cause| format!("KRB-ERROR reply parses: {cause}"))?;
        let key = EncryptionKey::new(18, vec![0; 32]);

        assert!(matches!(
            reply
                .decrypt_result(&key)
                .err()
                .ok_or("unsigned success result rejected")?,
            KadminError::UnauthenticatedSuccess
        ));
        Ok(())
    }

    /// Pins that a non-UTF-8 result text is kept verbatim on the parse and failure paths.
    #[test]
    fn non_utf8_result_text_is_kept_verbatim_on_both_reply_paths() -> Result<(), TestError> {
        // Result code 4 (soft error) followed by a Latin-1 body, which is not UTF-8.
        let reply = b"\x00\x04Passwort zu \xe4hnlich";
        let raw = &reply[2..];

        let result = ChangePasswordResult::parse(reply)
            .map_err(|cause| format!("result parses: {cause}"))?;
        assert_eq!(result.text_raw, raw);
        assert!(
            result.text.contains('\u{fffd}'),
            "the display text stays lossy"
        );

        match result.ensure_success() {
            Err(KadminError::PasswordChangeFailed {
                code,
                text: _,
                text_raw,
            }) => {
                assert_eq!(code, 4);
                assert_eq!(text_raw, raw);
            }
            other => return Err(format!("result code 4 is a failure: {other:?}").into()),
        }
        Ok(())
    }
}
