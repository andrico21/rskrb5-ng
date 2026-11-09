//! AP-REP tests: gokrb5 fixture round-trips and encrypted-part building and decryption.
#![cfg(feature = "messages")]

/// AP-REP tests.
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
    use rasn::types::Integer;
    use rskrb5_ng::{
        ap_rep::{
            AP_REP_ENCPART_USAGE, KRB_AP_REP_MSG_TYPE, build as build_ap_rep,
            build_ap_rep_with_confounder, decode as decode_ap_rep, decode_enc_ap_rep_part,
            decrypt_ap_rep_enc_part, encode as encode_ap_rep, encode_build_ap_rep_with_confounder,
        },
        crypto::KerberosEtype,
        error::ApRep as Error,
        keytab::EncryptionKey,
    };

    /// Error type of the `Result`-returning tests.
    type TestError = Box<dyn error::Error>;

    /// gokrb5 AP-REP fixture.
    const MARSHALLED_AP_REP: &str = concat!(
        "6F333031A003020105A10302010FA2253023A003020100A103020105A217",
        "04156B726241534E2E312074657374206D657373616765",
    );
    /// gokrb5 `EncAPRepPart` fixture with every optional field set.
    const MARSHALLED_ENC_AP_REP_PART: &str = concat!(
        "7B363034A011180F31393934303631303036303331375AA105020301E240",
        "A2133011A003020101A10A04083132333435363738A303020111",
    );
    /// gokrb5 `EncAPRepPart` fixture without optional fields.
    const MARSHALLED_ENC_AP_REP_PART_OPTIONALS_NULL: &str =
        "7B1C301AA011180F31393934303631303036303331375AA105020301E240";
    /// Timestamp of the gokrb5 fixtures, in seconds since the Unix epoch.
    const TEST_TIME_SECONDS: i64 = 771_228_197;
    /// AES256 reply key used to encrypt the AP-REP parts.
    const REPLY_KEY: &str = "9cad00bbc72d703258e911dc18e6d5487cf737bf67fd111f0c2463ad6033bf51";

    /// Pins that the gokrb5 AP-REP fixture decodes to the expected fields and re-encodes byte for byte.
    #[test]
    fn decodes_gokrb5_ap_rep_fixture() -> Result<(), TestError> {
        let bytes = hex::decode(MARSHALLED_AP_REP)?;

        let ap_rep = decode_ap_rep(&bytes)?;

        assert_eq!(ap_rep.pvno, Integer::from(5_i32));
        assert_eq!(ap_rep.msg_type, Integer::from(KRB_AP_REP_MSG_TYPE));
        assert_eq!(ap_rep.enc_part.etype, 0_i32);
        assert_eq!(ap_rep.enc_part.kvno, Some(5));
        assert_eq!(ap_rep.enc_part.cipher.as_ref(), b"krbASN.1 test message");
        assert_eq!(encode_ap_rep(&ap_rep)?, bytes);
        Ok(())
    }

    /// Pins that the gokrb5 `EncAPRepPart` fixture decodes to the expected fields.
    #[test]
    fn decodes_gokrb5_enc_ap_rep_part_fixture() -> Result<(), TestError> {
        let enc_part = decode_enc_ap_rep_part(&hex::decode(MARSHALLED_ENC_AP_REP_PART)?)?;

        assert_eq!(enc_part.ctime.0.timestamp(), TEST_TIME_SECONDS);
        assert_eq!(enc_part.cusec, Integer::from(123_456_i32));
        let subkey = enc_part.subkey.as_ref().ok_or("subkey")?;
        assert_eq!(subkey.r#type, 1_i32);
        assert_eq!(subkey.value.as_ref(), b"12345678");
        assert_eq!(enc_part.seq_number, Some(17));
        Ok(())
    }

    /// Pins that the gokrb5 `EncAPRepPart` fixture without optional fields decodes.
    #[test]
    fn decodes_gokrb5_enc_ap_rep_part_optionals_null_fixture() -> Result<(), TestError> {
        let enc_part =
            decode_enc_ap_rep_part(&hex::decode(MARSHALLED_ENC_AP_REP_PART_OPTIONALS_NULL)?)?;

        assert_eq!(enc_part.ctime.0.timestamp(), TEST_TIME_SECONDS);
        assert_eq!(enc_part.cusec, Integer::from(123_456_i32));
        assert!(enc_part.subkey.is_none(), "subkey is absent");
        assert!(enc_part.seq_number.is_none(), "sequence number is absent");
        Ok(())
    }

    /// Pins that an AP-REP built with an explicit confounder decrypts back to its encrypted part.
    #[test]
    fn builds_and_decrypts_ap_rep_with_explicit_confounder() -> Result<(), TestError> {
        let enc_part = decode_enc_ap_rep_part(&hex::decode(MARSHALLED_ENC_AP_REP_PART)?)?;
        let key = reply_key()?;
        let etype = KerberosEtype::from_etype_id(key.etype()).ok_or("AES256 etype")?;
        let confounder = vec![0x55; etype.confounder_len()];

        let ap_rep = build_ap_rep_with_confounder(&enc_part, &key, Some(7), &confounder)?;

        assert_eq!(ap_rep.pvno, Integer::from(5_i32));
        assert_eq!(ap_rep.msg_type, Integer::from(KRB_AP_REP_MSG_TYPE));
        assert_eq!(ap_rep.enc_part.etype, key.etype());
        assert_eq!(ap_rep.enc_part.kvno, Some(7));
        let decrypted = decrypt_ap_rep_enc_part(&ap_rep, &key)?;
        assert_eq!(decrypted, enc_part);
        Ok(())
    }

    /// Pins that an encoded AP-REP built with an explicit confounder decodes and decrypts.
    #[test]
    fn encodes_built_ap_rep_with_explicit_confounder() -> Result<(), TestError> {
        let enc_part =
            decode_enc_ap_rep_part(&hex::decode(MARSHALLED_ENC_AP_REP_PART_OPTIONALS_NULL)?)?;
        let key = reply_key()?;
        let etype = KerberosEtype::from_etype_id(key.etype()).ok_or("AES256 etype")?;
        let confounder = vec![0x33; etype.confounder_len()];

        let encoded = encode_build_ap_rep_with_confounder(&enc_part, &key, None, &confounder)?;
        let decoded = decode_ap_rep(&encoded)?;

        assert_eq!(decoded.enc_part.etype, key.etype());
        assert!(decoded.enc_part.kvno.is_none(), "kvno is absent");
        let decrypted = decrypt_ap_rep_enc_part(&decoded, &key)?;
        assert_eq!(decrypted, enc_part);
        Ok(())
    }

    /// Pins that an AP-REP built with a random confounder decrypts back to its encrypted part.
    #[test]
    fn builds_and_decrypts_ap_rep_with_random_confounder() -> Result<(), TestError> {
        let enc_part = decode_enc_ap_rep_part(&hex::decode(MARSHALLED_ENC_AP_REP_PART)?)?;
        let key = reply_key()?;

        let ap_rep = build_ap_rep(&enc_part, &key, None)?;

        assert_eq!(ap_rep.enc_part.etype, key.etype());
        let decrypted = decrypt_ap_rep_enc_part(&ap_rep, &key)?;
        assert_eq!(decrypted, enc_part);
        Ok(())
    }

    /// Pins that decrypting with a key of another etype is rejected.
    #[test]
    fn rejects_ap_rep_key_etype_mismatch() -> Result<(), TestError> {
        let enc_part = decode_enc_ap_rep_part(&hex::decode(MARSHALLED_ENC_AP_REP_PART)?)?;
        let key = reply_key()?;
        let etype = KerberosEtype::from_etype_id(key.etype()).ok_or("AES256 etype")?;
        let confounder = vec![0x55; etype.confounder_len()];
        let ap_rep = build_ap_rep_with_confounder(&enc_part, &key, None, &confounder)?;
        let wrong_key = EncryptionKey::new(17, vec![0; 16]);

        let error = decrypt_ap_rep_enc_part(&ap_rep, &wrong_key)
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

    /// Pins the AP-REP encrypted-part key usage number.
    #[test]
    fn exposes_ap_rep_key_usage_constant() {
        assert_eq!(AP_REP_ENCPART_USAGE, 12);
    }

    /// Returns the AES256 reply key.
    fn reply_key() -> Result<EncryptionKey, TestError> {
        Ok(EncryptionKey::new(18, hex::decode(REPLY_KEY)?))
    }
}
