//! KDC-REP tests: gokrb5 AS-REP, TGS-REP and `EncKDCRepPart` fixtures and encrypted-part handling.
#![cfg(feature = "messages")]

/// KDC-REP tests.
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
    use rasn_kerberos::{EncKdcRepPart, KdcRep, PrincipalName, TicketFlags};
    use rskrb5_ng::{
        crypto::KerberosEtype,
        error::KdcRep as Error,
        kdc_rep::{
            AS_REP_ENCPART_USAGE, KRB_AS_REP_MSG_TYPE, KRB_TGS_REP_MSG_TYPE,
            TGS_REP_ENCPART_SESSION_KEY_USAGE, decode_as_rep, decode_enc_kdc_rep_part,
            decode_tgs_rep, decrypt_as_rep_enc_part, decrypt_tgs_rep_enc_part, encode_as_rep,
            encode_enc_as_rep_part, encode_enc_tgs_rep_part, encode_tgs_rep,
            encrypt_as_rep_enc_part, encrypt_as_rep_enc_part_with_confounder,
            encrypt_tgs_rep_enc_part, encrypt_tgs_rep_enc_part_with_confounder,
        },
        keytab::EncryptionKey,
    };

    /// Error type of the `Result`-returning tests.
    type TestError = Box<dyn error::Error>;

    /// gokrb5 AS-REP fixture with every optional field set.
    const MARSHALLED_AS_REP: &str = concat!(
        "6B81EA3081E7A003020105A10302010BA22630243010A10302010DA209",
        "040770612D646174613010A10302010DA209040770612D64617461A310",
        "1B0E415448454E412E4D49542E454455A41A3018A003020101A11130",
        "0F1B066866747361691B056578747261A55E615C305AA003020105A110",
        "1B0E415448454E412E4D49542E454455A21A3018A003020101A11130",
        "0F1B066866747361691B056578747261A3253023A003020100A10302",
        "0105A21704156B726241534E2E312074657374206D657373616765A625",
        "3023A003020100A103020105A21704156B726241534E2E312074657374",
        "206D657373616765",
    );
    /// gokrb5 AS-REP fixture without optional fields.
    const MARSHALLED_AS_REP_OPTIONALS_NULL: &str = concat!(
        "6B81C23081BFA003020105A10302010BA3101B0E415448454E412E4D49",
        "542E454455A41A3018A003020101A111300F1B066866747361691B05",
        "6578747261A55E615C305AA003020105A1101B0E415448454E412E4D",
        "49542E454455A21A3018A003020101A111300F1B066866747361691B",
        "056578747261A3253023A003020100A103020105A21704156B726241",
        "534E2E312074657374206D657373616765A6253023A003020100A103",
        "020105A21704156B726241534E2E312074657374206D657373616765",
    );
    /// gokrb5 TGS-REP fixture with every optional field set.
    const MARSHALLED_TGS_REP: &str = concat!(
        "6D81EA3081E7A003020105A10302010DA22630243010A10302010DA209",
        "040770612D646174613010A10302010DA209040770612D64617461A310",
        "1B0E415448454E412E4D49542E454455A41A3018A003020101A11130",
        "0F1B066866747361691B056578747261A55E615C305AA003020105A110",
        "1B0E415448454E412E4D49542E454455A21A3018A003020101A11130",
        "0F1B066866747361691B056578747261A3253023A003020100A10302",
        "0105A21704156B726241534E2E312074657374206D657373616765A625",
        "3023A003020100A103020105A21704156B726241534E2E312074657374",
        "206D657373616765",
    );
    /// gokrb5 TGS-REP fixture without optional fields.
    const MARSHALLED_TGS_REP_OPTIONALS_NULL: &str = concat!(
        "6D81C23081BFA003020105A10302010DA3101B0E415448454E412E4D49",
        "542E454455A41A3018A003020101A111300F1B066866747361691B05",
        "6578747261A55E615C305AA003020105A1101B0E415448454E412E4D",
        "49542E454455A21A3018A003020101A111300F1B066866747361691B",
        "056578747261A3253023A003020100A103020105A21704156B726241",
        "534E2E312074657374206D657373616765A6253023A003020100A103",
        "020105A21704156B726241534E2E312074657374206D657373616765",
    );
    /// gokrb5 `EncKDCRepPart` fixture with every optional field set.
    const MARSHALLED_ENC_KDC_REP_PART: &str = concat!(
        "7A82010E3082010AA0133011A003020101A10A04083132333435363738",
        "A13630343018A0030201FBA111180F3139393430363130303630333137",
        "5A3018A0030201FBA111180F31393934303631303036303331375AA203",
        "02012AA311180F31393934303631303036303331375AA407030500FEDC",
        "BA98A511180F31393934303631303036303331375AA611180F31393934",
        "303631303036303331375AA711180F3139393430363130303630333137",
        "5AA811180F31393934303631303036303331375AA9101B0E415448454E",
        "412E4D49542E454455AA1A3018A003020101A111300F1B0668667473",
        "61691B056578747261AB20301E300DA003020102A106040412D00023",
        "300DA003020102A106040412D00023",
    );
    /// gokrb5 `EncKDCRepPart` fixture without optional fields.
    const MARSHALLED_ENC_KDC_REP_PART_OPTIONALS_NULL: &str = concat!(
        "7A81B23081AFA0133011A003020101A10A04083132333435363738A136",
        "30343018A0030201FBA111180F31393934303631303036303331375A30",
        "18A0030201FBA111180F31393934303631303036303331375AA2030201",
        "2AA407030500FE5CBA98A511180F31393934303631303036303331375A",
        "A711180F31393934303631303036303331375AA9101B0E415448454E41",
        "2E4D49542E454455AA1A3018A003020101A111300F1B066866747361",
        "691B056578747261",
    );
    /// Timestamp of the gokrb5 fixtures, in seconds since the Unix epoch.
    const TEST_TIME_SECONDS: i64 = 771_228_197;
    /// AES256 reply key used to encrypt the KDC-REP parts.
    const REPLY_KEY: &str = "9cad00bbc72d703258e911dc18e6d5487cf737bf67fd111f0c2463ad6033bf51";

    /// Pins that the gokrb5 AS-REP fixture decodes to the expected fields and re-encodes byte for byte.
    #[test]
    fn decodes_gokrb5_as_rep_fixture() -> Result<(), TestError> {
        let bytes = hex::decode(MARSHALLED_AS_REP)?;

        let as_rep = decode_as_rep(&bytes)?;

        assert_kdc_rep_fields(&as_rep.0, KRB_AS_REP_MSG_TYPE, 2);
        assert_eq!(encode_as_rep(&as_rep)?, bytes);
        Ok(())
    }

    /// Pins that the gokrb5 AS-REP fixture without optional fields decodes and re-encodes byte for byte.
    #[test]
    fn decodes_gokrb5_as_rep_optionals_null_fixture() -> Result<(), TestError> {
        let bytes = hex::decode(MARSHALLED_AS_REP_OPTIONALS_NULL)?;

        let as_rep = decode_as_rep(&bytes)?;

        assert_kdc_rep_fields(&as_rep.0, KRB_AS_REP_MSG_TYPE, 0);
        assert_eq!(encode_as_rep(&as_rep)?, bytes);
        Ok(())
    }

    /// Pins that the gokrb5 TGS-REP fixture decodes to the expected fields and re-encodes byte for byte.
    #[test]
    fn decodes_gokrb5_tgs_rep_fixture() -> Result<(), TestError> {
        let bytes = hex::decode(MARSHALLED_TGS_REP)?;

        let tgs_rep = decode_tgs_rep(&bytes)?;

        assert_kdc_rep_fields(&tgs_rep.0, KRB_TGS_REP_MSG_TYPE, 2);
        assert_eq!(encode_tgs_rep(&tgs_rep)?, bytes);
        Ok(())
    }

    /// Pins that the gokrb5 TGS-REP fixture without optional fields decodes and re-encodes byte for byte.
    #[test]
    fn decodes_gokrb5_tgs_rep_optionals_null_fixture() -> Result<(), TestError> {
        let bytes = hex::decode(MARSHALLED_TGS_REP_OPTIONALS_NULL)?;

        let tgs_rep = decode_tgs_rep(&bytes)?;

        assert_kdc_rep_fields(&tgs_rep.0, KRB_TGS_REP_MSG_TYPE, 0);
        assert_eq!(encode_tgs_rep(&tgs_rep)?, bytes);
        Ok(())
    }

    /// Pins that the gokrb5 `EncKDCRepPart` fixture decodes to the expected fields and re-encodes byte for byte.
    #[test]
    fn decodes_gokrb5_enc_kdc_rep_part_fixture() -> Result<(), TestError> {
        let bytes = hex::decode(MARSHALLED_ENC_KDC_REP_PART)?;

        let enc_part = decode_enc_kdc_rep_part(&bytes)?;

        assert_enc_kdc_rep_part_fields(&enc_part, 0xfedc_ba98);
        assert!(enc_part.key_expiration.is_some(), "key expiration is set");
        assert!(enc_part.start_time.is_some(), "start time is set");
        assert!(enc_part.renew_till.is_some(), "renew till is set");
        assert!(enc_part.caddr.is_some(), "addresses are set");
        assert_eq!(encode_enc_tgs_rep_part(&enc_part)?, bytes);
        Ok(())
    }

    /// Pins that the gokrb5 `EncKDCRepPart` fixture without optional fields decodes and re-encodes byte for byte.
    #[test]
    fn decodes_gokrb5_enc_kdc_rep_part_optionals_null_fixture() -> Result<(), TestError> {
        let bytes = hex::decode(MARSHALLED_ENC_KDC_REP_PART_OPTIONALS_NULL)?;

        let enc_part = decode_enc_kdc_rep_part(&bytes)?;

        assert_enc_kdc_rep_part_fields(&enc_part, 0xfe5c_ba98);
        assert!(
            enc_part.key_expiration.is_none(),
            "key expiration is absent"
        );
        assert!(enc_part.start_time.is_none(), "start time is absent");
        assert!(enc_part.renew_till.is_none(), "renew till is absent");
        assert!(enc_part.caddr.is_none(), "addresses are absent");
        assert_eq!(encode_enc_tgs_rep_part(&enc_part)?, bytes);
        Ok(())
    }

    /// Pins that the generic `EncKDCRepPart` decoder also accepts the `EncASRepPart` application tag.
    #[test]
    fn generic_enc_kdc_rep_decode_accepts_as_rep_application_tag() -> Result<(), TestError> {
        let enc_part = decode_enc_kdc_rep_part(&hex::decode(MARSHALLED_ENC_KDC_REP_PART)?)?;
        let encoded_as = encode_enc_as_rep_part(&enc_part)?;

        let decoded = decode_enc_kdc_rep_part(&encoded_as)?;

        assert_eq!(decoded, enc_part);
        Ok(())
    }

    /// Pins that an AS-REP encrypted part built with an explicit confounder decrypts back.
    #[test]
    fn builds_and_decrypts_as_rep_enc_part_with_explicit_confounder() -> Result<(), TestError> {
        let enc_part = decode_enc_kdc_rep_part(&hex::decode(MARSHALLED_ENC_KDC_REP_PART)?)?;
        let key = reply_key()?;
        let etype = KerberosEtype::from_etype_id(key.etype()).ok_or("AES256 etype")?;
        let confounder = vec![0x22; etype.confounder_len()];
        let mut as_rep = decode_as_rep(&hex::decode(MARSHALLED_AS_REP)?)?;

        as_rep.0.enc_part =
            encrypt_as_rep_enc_part_with_confounder(&enc_part, &key, Some(6), &confounder)?;

        assert_eq!(as_rep.0.enc_part.etype, key.etype());
        assert_eq!(as_rep.0.enc_part.kvno, Some(6));
        let decrypted = decrypt_as_rep_enc_part(&as_rep, &key)?;
        assert_eq!(decrypted, enc_part);
        Ok(())
    }

    /// Pins that a TGS-REP encrypted part built with an explicit confounder decrypts back.
    #[test]
    fn builds_and_decrypts_tgs_rep_enc_part_with_explicit_confounder() -> Result<(), TestError> {
        let enc_part = decode_enc_kdc_rep_part(&hex::decode(MARSHALLED_ENC_KDC_REP_PART)?)?;
        let key = reply_key()?;
        let etype = KerberosEtype::from_etype_id(key.etype()).ok_or("AES256 etype")?;
        let confounder = vec![0x44; etype.confounder_len()];
        let mut tgs_rep = decode_tgs_rep(&hex::decode(MARSHALLED_TGS_REP)?)?;

        tgs_rep.0.enc_part =
            encrypt_tgs_rep_enc_part_with_confounder(&enc_part, &key, None, &confounder)?;

        assert_eq!(tgs_rep.0.enc_part.etype, key.etype());
        assert!(tgs_rep.0.enc_part.kvno.is_none(), "kvno is absent");
        let decrypted = decrypt_tgs_rep_enc_part(&tgs_rep, &key)?;
        assert_eq!(decrypted, enc_part);
        Ok(())
    }

    /// Pins that AS-REP and TGS-REP encrypted parts built with random confounders decrypt back.
    #[test]
    fn builds_and_decrypts_kdc_rep_enc_parts_with_random_confounders() -> Result<(), TestError> {
        let enc_part = decode_enc_kdc_rep_part(&hex::decode(MARSHALLED_ENC_KDC_REP_PART)?)?;
        let key = reply_key()?;
        let mut as_rep = decode_as_rep(&hex::decode(MARSHALLED_AS_REP)?)?;
        let mut tgs_rep = decode_tgs_rep(&hex::decode(MARSHALLED_TGS_REP)?)?;

        as_rep.0.enc_part = encrypt_as_rep_enc_part(&enc_part, &key, None)?;
        tgs_rep.0.enc_part = encrypt_tgs_rep_enc_part(&enc_part, &key, None)?;

        assert_eq!(decrypt_as_rep_enc_part(&as_rep, &key)?, enc_part);
        assert_eq!(decrypt_tgs_rep_enc_part(&tgs_rep, &key)?, enc_part);
        Ok(())
    }

    /// Pins that decrypting with a key of another etype is rejected.
    #[test]
    fn rejects_kdc_rep_enc_part_key_etype_mismatch() -> Result<(), TestError> {
        let enc_part = decode_enc_kdc_rep_part(&hex::decode(MARSHALLED_ENC_KDC_REP_PART)?)?;
        let key = reply_key()?;
        let mut as_rep = decode_as_rep(&hex::decode(MARSHALLED_AS_REP)?)?;
        as_rep.0.enc_part = encrypt_as_rep_enc_part(&enc_part, &key, None)?;
        let wrong_key = EncryptionKey::new(17, vec![0; 16]);

        let error = decrypt_as_rep_enc_part(&as_rep, &wrong_key)
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

    /// Pins the KDC-REP encrypted-part key usage numbers.
    #[test]
    fn exposes_kdc_rep_key_usage_constants() {
        assert_eq!(AS_REP_ENCPART_USAGE, 3);
        assert_eq!(TGS_REP_ENCPART_SESSION_KEY_USAGE, 8);
    }

    /// Asserts the KDC-REP fields shared by the gokrb5 AS-REP and TGS-REP fixtures.
    fn assert_kdc_rep_fields(rep: &KdcRep, expected_msg_type: i32, expected_padata_count: usize) {
        assert_eq!(rep.pvno, Integer::from(5_i32));
        assert_eq!(rep.msg_type, Integer::from(expected_msg_type));
        assert_eq!(
            rep.padata.as_ref().map(Vec::len).unwrap_or_default(),
            expected_padata_count,
        );
        if let Some(padata) = &rep.padata {
            for entry in padata {
                assert_eq!(entry.r#type, 13_i32);
                assert_eq!(entry.value.as_ref(), b"pa-data");
            }
        }
        assert_eq!(rep.crealm.as_bytes(), b"ATHENA.MIT.EDU");
        assert_eq!(rep.cname.r#type, 1_i32);
        assert_eq!(
            principal_components(&rep.cname),
            vec![b"hftsai".as_slice(), b"extra".as_slice()],
        );
        assert_eq!(rep.ticket.tkt_vno, Integer::from(5_i32));
        assert_eq!(rep.ticket.realm.as_bytes(), b"ATHENA.MIT.EDU");
        assert_eq!(rep.ticket.sname.r#type, 1_i32);
        assert_eq!(
            principal_components(&rep.ticket.sname),
            vec![b"hftsai".as_slice(), b"extra".as_slice()],
        );
        assert_eq!(rep.ticket.enc_part.etype, 0_i32);
        assert_eq!(rep.ticket.enc_part.kvno, Some(5));
        assert_eq!(
            rep.ticket.enc_part.cipher.as_ref(),
            b"krbASN.1 test message"
        );
        assert_eq!(rep.enc_part.etype, 0_i32);
        assert_eq!(rep.enc_part.kvno, Some(5));
        assert_eq!(rep.enc_part.cipher.as_ref(), b"krbASN.1 test message");
    }

    /// Asserts the `EncKDCRepPart` fields of the gokrb5 fixtures.
    fn assert_enc_kdc_rep_part_fields(enc_part: &EncKdcRepPart, expected_flags: u32) {
        assert_eq!(enc_part.key.r#type, 1_i32);
        assert_eq!(enc_part.key.value.as_ref(), b"12345678");
        assert_eq!(enc_part.last_req.len(), 2);
        for last_req in &enc_part.last_req {
            assert_eq!(last_req.r#type, -5_i32);
            assert_eq!(last_req.value.0.timestamp(), TEST_TIME_SECONDS);
        }
        assert_eq!(enc_part.nonce, 42);
        assert_eq!(ticket_flags_to_bits(&enc_part.flags), expected_flags);
        assert_eq!(enc_part.auth_time.0.timestamp(), TEST_TIME_SECONDS);
        assert_eq!(enc_part.end_time.0.timestamp(), TEST_TIME_SECONDS);
        assert_eq!(enc_part.srealm.as_bytes(), b"ATHENA.MIT.EDU");
        assert_eq!(enc_part.sname.r#type, 1_i32);
        assert_eq!(
            principal_components(&enc_part.sname),
            vec![b"hftsai".as_slice(), b"extra".as_slice()],
        );
    }

    /// Returns the AES256 reply key.
    fn reply_key() -> Result<EncryptionKey, TestError> {
        Ok(EncryptionKey::new(18, hex::decode(REPLY_KEY)?))
    }

    /// Returns the name components of a principal name as byte slices.
    fn principal_components(name: &PrincipalName) -> Vec<&[u8]> {
        name.string.iter().map(GeneralString::as_bytes).collect()
    }

    /// Returns the first 32 ticket flag bits as a big-endian integer; missing bytes read as zero.
    fn ticket_flags_to_bits(flags: &TicketFlags) -> u32 {
        let raw = flags.0.as_raw_slice();
        u32::from_be_bytes([
            raw.first().copied().unwrap_or_default(),
            raw.get(1).copied().unwrap_or_default(),
            raw.get(2).copied().unwrap_or_default(),
            raw.get(3).copied().unwrap_or_default(),
        ])
    }
}
