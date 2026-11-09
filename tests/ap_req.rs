//! AP-REQ tests: gokrb5 fixture decoding, authenticator building, encryption and key usages.
#![cfg(feature = "messages")]

/// AP-REQ tests.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::error;

    use pretty_assertions::assert_eq;
    use rasn::types::{GeneralString, Integer};
    use rasn_kerberos::{KerberosString, PrincipalName};
    use rskrb5_ng::{
        ap_req::{
            AP_REQ_AUTHENTICATOR_USAGE, KRB_AP_REQ_MSG_TYPE, TGS_REQ_AP_REQ_AUTHENTICATOR_USAGE,
            ap_options_from_bits, ap_options_to_bits, authenticator_usage_for_ticket,
            build as build_ap_req, build_ap_req_with_confounder, decode as decode_ap_req,
            decode_authenticator, decrypt_ap_req_authenticator, encode as encode_ap_req,
            encode_build_ap_req_with_confounder,
        },
        crypto::KerberosEtype,
        error::ApReq as Error,
        keytab::EncryptionKey,
    };

    /// Error type of the `Result`-returning tests.
    type TestError = Box<dyn error::Error>;

    /// gokrb5 AP-REQ fixture.
    const MARSHALLED_AP_REQ: &str = concat!(
        "6E819D30819AA003020105A10302010EA207030500FEDCBA98A35E615C",
        "305AA003020105A1101B0E415448454E412E4D49542E454455A21A3018",
        "A003020101A111300F1B066866747361691B056578747261A3253023A0",
        "03020100A103020105A21704156B726241534E2E312074657374206D65",
        "7373616765A4253023A003020100A103020105A21704156B726241534E",
        "2E312074657374206D657373616765",
    );
    /// gokrb5 Authenticator fixture.
    const MARSHALLED_AUTHENTICATOR: &str = concat!(
        "6281A130819EA003020105A1101B0E415448454E412E4D49542E454455",
        "A21A3018A003020101A111300F1B066866747361691B056578747261A3",
        "0F300DA003020101A106040431323334A405020301E240A511180F3139",
        "3934303631303036303331375AA6133011A003020101A10A0408313233",
        "3435363738A703020111A8243022300FA003020101A1080406666F6F62",
        "6172300FA003020101A1080406666F6F626172",
    );
    /// Timestamp of the gokrb5 fixtures, in seconds since the Unix epoch.
    const TEST_TIME_SECONDS: i64 = 771_228_197;
    /// AES256 key used to encrypt the authenticators.
    const REPLY_KEY: &str = "9cad00bbc72d703258e911dc18e6d5487cf737bf67fd111f0c2463ad6033bf51";

    /// Rejects authenticated nonzero suffixes while retaining intentional zero padding.
    #[test]
    fn authenticator_rejects_nonzero_authenticated_suffix() -> Result<(), TestError> {
        // Given authenticator plaintext with an authenticated nonzero suffix.
        let mut request = decode_ap_req(&hex::decode(MARSHALLED_AP_REQ)?)?;
        let mut plaintext = hex::decode(MARSHALLED_AUTHENTICATOR)?;
        plaintext.push(1);
        let key = reply_key()?;
        let etype = KerberosEtype::from_etype_id(key.etype()).ok_or("etype")?;
        request.authenticator.etype = key.etype();
        request.authenticator.cipher = etype
            .encrypt_message_with_confounder(
                key.value(),
                &plaintext,
                AP_REQ_AUTHENTICATOR_USAGE,
                &[0; 16],
            )?
            .into();
        // When the decrypted complete value is decoded, then the suffix is rejected.
        let _error = decrypt_ap_req_authenticator(&request, &key, AP_REQ_AUTHENTICATOR_USAGE)
            .err()
            .ok_or("authenticated suffix accepted")?;
        Ok(())
    }

    /// Pins that the gokrb5 AP-REQ fixture decodes to the expected fields and re-encodes byte for byte.
    #[test]
    fn decodes_gokrb5_ap_req_fixture() -> Result<(), TestError> {
        let bytes = hex::decode(MARSHALLED_AP_REQ)?;

        let ap_req = decode_ap_req(&bytes)?;

        assert_eq!(ap_req.pvno, Integer::from(5_i32));
        assert_eq!(ap_req.msg_type, Integer::from(KRB_AP_REQ_MSG_TYPE));
        assert_eq!(ap_options_to_bits(&ap_req.ap_options), 0xfedc_ba98);
        assert_eq!(ap_req.ticket.tkt_vno, Integer::from(5_i32));
        assert_eq!(
            kerberos_string_bytes(&ap_req.ticket.realm),
            b"ATHENA.MIT.EDU"
        );
        assert_eq!(ap_req.ticket.sname.r#type, 1_i32);
        assert_eq!(
            principal_components(&ap_req.ticket.sname),
            vec![b"hftsai".as_slice(), b"extra".as_slice()],
        );
        assert_eq!(ap_req.ticket.enc_part.etype, 0_i32);
        assert_eq!(ap_req.ticket.enc_part.kvno, Some(5));
        assert_eq!(
            ap_req.ticket.enc_part.cipher.as_ref(),
            b"krbASN.1 test message",
        );
        assert_eq!(ap_req.authenticator.etype, 0_i32);
        assert_eq!(ap_req.authenticator.kvno, Some(5));
        assert_eq!(
            ap_req.authenticator.cipher.as_ref(),
            b"krbASN.1 test message"
        );
        assert_eq!(encode_ap_req(&ap_req)?, bytes);
        Ok(())
    }

    /// Pins that the gokrb5 Authenticator fixture decodes to the expected fields.
    #[test]
    fn decodes_gokrb5_authenticator_fixture() -> Result<(), TestError> {
        let authenticator = decode_authenticator(&hex::decode(MARSHALLED_AUTHENTICATOR)?)?;

        assert_eq!(authenticator.authenticator_vno, Integer::from(5_i32));
        assert_eq!(
            kerberos_string_bytes(&authenticator.crealm),
            b"ATHENA.MIT.EDU"
        );
        assert_eq!(authenticator.cname.r#type, 1_i32);
        assert_eq!(
            principal_components(&authenticator.cname),
            vec![b"hftsai".as_slice(), b"extra".as_slice()],
        );
        let checksum = authenticator.cksum.as_ref().ok_or("checksum")?;
        assert_eq!(checksum.r#type, 1_i32);
        assert_eq!(checksum.checksum.as_ref(), b"1234");
        assert_eq!(authenticator.cusec, Integer::from(123_456_i32));
        assert_eq!(authenticator.ctime.0.timestamp(), TEST_TIME_SECONDS);
        let subkey = authenticator.subkey.as_ref().ok_or("subkey")?;
        assert_eq!(subkey.r#type, 1_i32);
        assert_eq!(subkey.value.as_ref(), b"12345678");
        assert_eq!(authenticator.seq_number, Some(17));
        assert_eq!(
            authenticator
                .authorization_data
                .as_ref()
                .ok_or("authorization data")?
                .len(),
            2,
        );
        Ok(())
    }

    /// Pins that an AP-REQ built with an explicit confounder carries its options and decrypts back.
    #[test]
    fn builds_and_decrypts_ap_req_with_explicit_confounder() -> Result<(), TestError> {
        let fixture = decode_ap_req(&hex::decode(MARSHALLED_AP_REQ)?)?;
        let authenticator = decode_authenticator(&hex::decode(MARSHALLED_AUTHENTICATOR)?)?;
        let key = reply_key()?;
        let etype = KerberosEtype::from_etype_id(key.etype()).ok_or("AES256 etype")?;
        let confounder = vec![0x44; etype.confounder_len()];

        let ap_req = build_ap_req_with_confounder(
            fixture.ticket,
            ap_options_from_bits(0x0102_0304),
            &authenticator,
            &key,
            AP_REQ_AUTHENTICATOR_USAGE,
            Some(9),
            &confounder,
        )?;

        assert_eq!(ap_req.pvno, Integer::from(5_i32));
        assert_eq!(ap_req.msg_type, Integer::from(KRB_AP_REQ_MSG_TYPE));
        assert_eq!(ap_options_to_bits(&ap_req.ap_options), 0x0102_0304);
        assert_eq!(ap_req.authenticator.etype, key.etype());
        assert_eq!(ap_req.authenticator.kvno, Some(9));
        let decrypted = decrypt_ap_req_authenticator(&ap_req, &key, AP_REQ_AUTHENTICATOR_USAGE)?;
        assert_eq!(decrypted, authenticator);
        Ok(())
    }

    /// Pins that an encoded AP-REQ built with an explicit confounder decodes and decrypts.
    #[test]
    fn encodes_built_ap_req_with_explicit_confounder() -> Result<(), TestError> {
        let fixture = decode_ap_req(&hex::decode(MARSHALLED_AP_REQ)?)?;
        let authenticator = decode_authenticator(&hex::decode(MARSHALLED_AUTHENTICATOR)?)?;
        let key = reply_key()?;
        let etype = KerberosEtype::from_etype_id(key.etype()).ok_or("AES256 etype")?;
        let confounder = vec![0x22; etype.confounder_len()];

        let encoded = encode_build_ap_req_with_confounder(
            fixture.ticket,
            ap_options_from_bits(0),
            &authenticator,
            &key,
            AP_REQ_AUTHENTICATOR_USAGE,
            None,
            &confounder,
        )?;
        let decoded = decode_ap_req(&encoded)?;

        assert_eq!(decoded.authenticator.etype, key.etype());
        assert!(decoded.authenticator.kvno.is_none(), "kvno is absent");
        let decrypted = decrypt_ap_req_authenticator(&decoded, &key, AP_REQ_AUTHENTICATOR_USAGE)?;
        assert_eq!(decrypted, authenticator);
        Ok(())
    }

    /// Pins that an AP-REQ built with a random confounder decrypts back to its authenticator.
    #[test]
    fn builds_and_decrypts_ap_req_with_random_confounder() -> Result<(), TestError> {
        let fixture = decode_ap_req(&hex::decode(MARSHALLED_AP_REQ)?)?;
        let authenticator = decode_authenticator(&hex::decode(MARSHALLED_AUTHENTICATOR)?)?;
        let key = reply_key()?;

        let ap_req = build_ap_req(
            fixture.ticket,
            ap_options_from_bits(0),
            &authenticator,
            &key,
            AP_REQ_AUTHENTICATOR_USAGE,
            None,
        )?;

        let decrypted = decrypt_ap_req_authenticator(&ap_req, &key, AP_REQ_AUTHENTICATOR_USAGE)?;
        assert_eq!(decrypted, authenticator);
        Ok(())
    }

    /// Pins that a krbtgt ticket selects the TGS-REQ authenticator key usage.
    #[test]
    fn selects_tgs_authenticator_usage_for_krbtgt_tickets() -> Result<(), TestError> {
        let mut ap_req = decode_ap_req(&hex::decode(MARSHALLED_AP_REQ)?)?;

        assert_eq!(
            authenticator_usage_for_ticket(&ap_req.ticket),
            AP_REQ_AUTHENTICATOR_USAGE,
        );

        ap_req.ticket.sname.r#type = 2_i32;
        ap_req.ticket.sname.string = vec![
            KerberosString::from_bytes(b"krbtgt")?,
            KerberosString::from_bytes(b"ATHENA.MIT.EDU")?,
        ];

        assert_eq!(
            authenticator_usage_for_ticket(&ap_req.ticket),
            TGS_REQ_AP_REQ_AUTHENTICATOR_USAGE,
        );
        Ok(())
    }

    /// Pins that decrypting the authenticator with a key of another etype is rejected.
    #[test]
    fn rejects_ap_req_authenticator_key_etype_mismatch() -> Result<(), TestError> {
        let fixture = decode_ap_req(&hex::decode(MARSHALLED_AP_REQ)?)?;
        let authenticator = decode_authenticator(&hex::decode(MARSHALLED_AUTHENTICATOR)?)?;
        let key = reply_key()?;
        let etype = KerberosEtype::from_etype_id(key.etype()).ok_or("AES256 etype")?;
        let confounder = vec![0x44; etype.confounder_len()];
        let ap_req = build_ap_req_with_confounder(
            fixture.ticket,
            ap_options_from_bits(0),
            &authenticator,
            &key,
            AP_REQ_AUTHENTICATOR_USAGE,
            None,
            &confounder,
        )?;
        let wrong_key = EncryptionKey::new(17, vec![0; 16]);

        let error = decrypt_ap_req_authenticator(&ap_req, &wrong_key, AP_REQ_AUTHENTICATOR_USAGE)
            .err()
            .ok_or("wrong etype key is rejected")?;

        assert!(
            matches!(
                error,
                Error::KeyEtypeMismatch {
                    key_etype: 17_i32,
                    encrypted_data_etype: 18_i32,
                }
            ),
            "{error:?}"
        );
        Ok(())
    }

    /// Pins the AP-REQ authenticator key usage numbers.
    #[test]
    fn exposes_ap_req_key_usage_constants() {
        assert_eq!(AP_REQ_AUTHENTICATOR_USAGE, 11);
        assert_eq!(TGS_REQ_AP_REQ_AUTHENTICATOR_USAGE, 7);
    }

    /// Returns the AES256 key used to encrypt the authenticators.
    fn reply_key() -> Result<EncryptionKey, TestError> {
        Ok(EncryptionKey::new(18, hex::decode(REPLY_KEY)?))
    }

    /// Returns the bytes of a Kerberos string.
    fn kerberos_string_bytes(input: &KerberosString) -> &[u8] {
        input.as_bytes()
    }

    /// Returns the name components of a principal name as byte slices.
    fn principal_components(name: &PrincipalName) -> Vec<&[u8]> {
        name.string.iter().map(GeneralString::as_bytes).collect()
    }
}
