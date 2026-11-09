//! Message-layer tests: gokrb5 fixtures for `EncryptedData`, KRB-ERROR and pre-authentication data.
#![cfg(feature = "messages")]

/// Message-layer tests.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::{error, time::Duration};
    use std::time::{SystemTime, UNIX_EPOCH};

    use rasn::der;
    use rasn_kerberos::{Checksum, KrbError};
    use rskrb5_ng::{
        error::Messages as Error,
        krb_error,
        messages::{
            EncryptedData, KrbErrorInfo, PaForUser, PaPacOptions, PaReqEncPaRep, decode_der,
            encode_der,
        },
    };

    /// Error type of the `Result`-returning tests.
    type TestError = Box<dyn error::Error>;

    /// gokrb5 `EncryptedData` fixture with kvno 5.
    const ENCRYPTED_DATA: &str =
        "3023A003020100A103020105A21704156B726241534E2E312074657374206D657373616765";
    /// gokrb5 `EncryptedData` fixture whose kvno has its most significant bit set.
    const ENCRYPTED_DATA_MSB_SET_KVNO: &str =
        "3026A003020100A1060204FF000000A21704156B726241534E2E312074657374206D657373616765";
    /// gokrb5 `EncryptedData` fixture with kvno -1.
    const ENCRYPTED_DATA_KVNO_NEGATIVE_ONE: &str =
        "3023A003020100A1030201FFA21704156B726241534E2E312074657374206D657373616765";
    /// gokrb5 KRB-ERROR fixture with every optional field set.
    const KRB_ERROR: &str = concat!(
        "7E81BA3081B7A003020105A10302011EA211180F31393934303631303036303331375AA305",
        "020301E240A411180F31393934303631303036303331375AA505020301E240A60302013C",
        "A7101B0E415448454E412E4D49542E454455A81A3018A003020101A111300F1B066866",
        "747361691B056578747261A9101B0E415448454E412E4D49542E454455AA1A3018A003",
        "020101A111300F1B066866747361691B056578747261AB0A1B086B72623564617461AC0A",
        "04086B72623564617461",
    );
    /// gokrb5 KRB-ERROR fixture without optional fields.
    const KRB_ERROR_OPTIONALS_NULL: &str = concat!(
        "7E60305EA003020105A10302011EA305020301E240A411180F3139393430363130303630",
        "3331375AA505020301E240A60302013CA9101B0E415448454E412E4D49542E454455AA1A",
        "3018A003020101A111300F1B066866747361691B056578747261",
    );
    /// gokrb5 PA-FOR-USER fixture.
    const PA_FOR_USER: &str = concat!(
        "304BA01A3018A003020101A111300F1B066866747361691B056578747261A1101B0E",
        "415448454E412E4D49542E454455A20F300DA003020101A106040431323334A30A1B",
        "086B72623564617461",
    );
    /// PA-PAC-OPTIONS with the claims and resource-based constrained delegation flags.
    const PA_PAC_OPTIONS_CLAIMS_AND_RBCD: &str = "3009A00703050090000000";
    /// PA-REQ-ENC-PA-REP in the gokrb5 shape.
    const PA_REQ_ENC_PA_REP: &str = "300DA00302010FA106040431323334";
    /// Cipher text carried by the gokrb5 `EncryptedData` fixtures.
    const TEST_CIPHER: &[u8] = b"krbASN.1 test message";
    /// Timestamp of the gokrb5 fixtures, in seconds since the Unix epoch.
    const TEST_TIME_SECONDS: u64 = 771_228_197;

    /// Enforces the RFC Microseconds domain at semantic diagnostic conversion.
    #[test]
    fn protocol_time_rejects_out_of_domain_microseconds() -> Result<(), TestError> {
        // Given valid KRB-ERRORs with invalid microsecond fields.
        for value in [-1_i64, 1_000_000, 0xffff_ffff] {
            let mut error: KrbError = der::decode(&hex::decode(KRB_ERROR)?)?;
            error.susec = value.into();
            // When semantic validation runs, then invalid values are rejected.
            let _error = KrbErrorInfo::from_rasn(&error)
                .err()
                .ok_or("invalid susec accepted")?;
        }
        Ok(())
    }

    /// Rejects fractional `KerberosTime` rather than normalizing it.
    #[test]
    fn protocol_time_rejects_fractional_kerberos_time() -> Result<(), TestError> {
        // Given an otherwise valid error with fractional server time.
        let mut error: KrbError = der::decode(&hex::decode(KRB_ERROR)?)?;
        error.stime.0 += chrono::Duration::nanoseconds(1);
        // When semantic conversion runs, then the fraction is rejected.
        let _error = KrbErrorInfo::from_rasn(&error)
            .err()
            .ok_or("fraction accepted")?;
        Ok(())
    }

    /// Accepts both inclusive Microseconds boundaries without modifying them.
    #[test]
    fn protocol_time_accepts_microsecond_boundaries() -> Result<(), TestError> {
        for value in [0_u32, 999_999] {
            let mut error: KrbError = der::decode(&hex::decode(KRB_ERROR)?)?;
            error.susec = value.into();
            assert_eq!(KrbErrorInfo::from_rasn(&error)?.susec(), value);
        }
        Ok(())
    }

    /// Rejects unchecked suffixes at complete KRB-ERROR decoding boundaries.
    #[test]
    fn whole_message_rejects_trailing_value() -> Result<(), TestError> {
        // Given a valid error followed by a second DER value.
        let mut bytes = hex::decode(KRB_ERROR)?;
        bytes.extend_from_slice(&[0x05, 0]);
        // When the validated codec is used, then the suffix is rejected.
        let _error = krb_error::decode(&bytes).err().ok_or("suffix accepted")?;
        Ok(())
    }

    /// Named semantic decoders reject a second DER value.
    #[test]
    fn named_decoders_reject_trailing_value() -> Result<(), TestError> {
        // Given complete typed values followed by a DER NULL.
        let suffix = |fixture| -> Result<Vec<u8>, TestError> {
            let mut bytes = hex::decode(fixture)?;
            bytes.extend_from_slice(&[0x05, 0]);
            Ok(bytes)
        };
        // When each named decoding boundary receives the concatenation.
        let rejected = [
            KrbErrorInfo::decode_der(&suffix(KRB_ERROR)?).is_err(),
            PaForUser::decode_der(&suffix(PA_FOR_USER)?).is_err(),
            PaPacOptions::decode_der(&suffix(PA_PAC_OPTIONS_CLAIMS_AND_RBCD)?).is_err(),
            PaReqEncPaRep::decode_der(&suffix(PA_REQ_ENC_PA_REP)?).is_err(),
        ];
        // Then every boundary rejects the unaudited remainder.
        assert_eq!(rejected, [true; 4]);
        Ok(())
    }

    /// Preserves the explicitly raw generic prefix decoder's existing contract.
    #[test]
    fn raw_codec_retains_prefix_contract() -> Result<(), TestError> {
        // Given concatenated DER values at the raw convenience boundary.
        let mut bytes = hex::decode(KRB_ERROR)?;
        bytes.extend_from_slice(&[0x05, 0]);
        // When prefix decoding is explicitly requested, then the first value survives.
        let error: KrbError = decode_der("raw KRB-ERROR", &bytes)?;
        assert_eq!(error.error_code, 60_i32);
        Ok(())
    }

    /// Pins that the gokrb5 `EncryptedData` fixtures decode with their kvno and re-encode byte for byte.
    #[test]
    fn encrypted_data_roundtrips_gokrb5_fixtures_exactly() -> Result<(), TestError> {
        for (fixture, expected_kvno) in [
            (ENCRYPTED_DATA, 5_i32),
            (ENCRYPTED_DATA_MSB_SET_KVNO, -0x0100_0000_i32),
            (ENCRYPTED_DATA_KVNO_NEGATIVE_ONE, -1_i32),
        ] {
            let bytes = hex::decode(fixture)?;
            let decoded: EncryptedData = der::decode(&bytes)?;

            assert_eq!(decoded.etype(), 0_i32);
            assert_eq!(decoded.kvno_i32()?, Some(expected_kvno));
            assert_eq!(decoded.cipher(), TEST_CIPHER);
            assert_eq!(der::encode(&decoded)?, bytes);
        }
        Ok(())
    }

    /// Pins that `EncryptedData` with a normal kvno converts to the rasn type and back.
    #[test]
    fn encrypted_data_converts_to_rasn_for_normal_kvno() -> Result<(), TestError> {
        let decoded = decode_encrypted_data(ENCRYPTED_DATA)?;
        let rasn = decoded.try_to_rasn()?;

        assert_eq!(rasn.etype, 0_i32);
        assert_eq!(rasn.kvno, Some(5_u32));
        assert_eq!(rasn.cipher.as_ref(), TEST_CIPHER);
        assert_eq!(EncryptedData::from_rasn(rasn), decoded);
        Ok(())
    }

    /// Pins that a negative kvno is rejected when converting to the unsigned rasn type.
    #[test]
    fn encrypted_data_rejects_signed_kvno_for_rasn_conversion() -> Result<(), TestError> {
        for fixture in [
            ENCRYPTED_DATA_MSB_SET_KVNO,
            ENCRYPTED_DATA_KVNO_NEGATIVE_ONE,
        ] {
            let decoded = decode_encrypted_data(fixture)?;
            let error = decoded
                .try_to_rasn()
                .err()
                .ok_or("negative kvno cannot convert to u32")?;

            assert!(
                matches!(
                    error,
                    Error::KvnoOutOfRange {
                        target: "u32",
                        kvno: _
                    }
                ),
                "{error:?}"
            );
        }
        Ok(())
    }

    /// Pins that the gokrb5 KRB-ERROR fixture decodes into its info view and re-encodes byte for byte.
    #[test]
    fn krb_error_decodes_and_roundtrips_gokrb5_fixture() -> Result<(), TestError> {
        let bytes = hex::decode(KRB_ERROR)?;
        let decoded: KrbError = decode_der("KRB-ERROR", &bytes)?;
        let info = KrbErrorInfo::from_rasn(&decoded)?;

        assert_eq!(info.ctime(), Some(timestamp(TEST_TIME_SECONDS)?));
        assert_eq!(info.cusec(), Some(123_456));
        assert_eq!(info.stime(), timestamp(TEST_TIME_SECONDS)?);
        assert_eq!(info.susec(), 123_456);
        assert_eq!(info.error_code(), 60_i32);
        let client = info.client().ok_or("client principal exists")?;
        assert_eq!(client.realm, "ATHENA.MIT.EDU");
        assert_eq!(client.name_type, 1_i32);
        assert_eq!(client.components, ["hftsai", "extra"]);
        assert_eq!(client.name(), "hftsai/extra");
        assert_eq!(info.service().realm, "ATHENA.MIT.EDU");
        assert_eq!(info.service().name_type, 1_i32);
        assert_eq!(info.service().components, ["hftsai", "extra"]);
        assert_eq!(info.e_text(), Some("krb5data"));
        assert_eq!(info.e_data(), Some(b"krb5data".as_slice()));
        assert_eq!(encode_der("KRB-ERROR", &decoded)?, bytes);
        Ok(())
    }

    /// Pins that the gokrb5 KRB-ERROR fixture without optional fields decodes and re-encodes byte for byte.
    #[test]
    fn krb_error_optional_nulls_decode_and_roundtrip() -> Result<(), TestError> {
        let bytes = hex::decode(KRB_ERROR_OPTIONALS_NULL)?;
        let decoded: KrbError = decode_der("KRB-ERROR", &bytes)?;
        let info = KrbErrorInfo::decode_der(&bytes)?;

        assert_eq!(info.ctime(), None);
        assert_eq!(info.cusec(), Some(123_456));
        assert_eq!(info.stime(), timestamp(TEST_TIME_SECONDS)?);
        assert_eq!(info.susec(), 123_456);
        assert_eq!(info.error_code(), 60_i32);
        assert_eq!(info.client(), None);
        assert_eq!(info.service().realm, "ATHENA.MIT.EDU");
        assert_eq!(info.service().name(), "hftsai/extra");
        assert_eq!(info.e_text(), None);
        assert_eq!(info.e_data(), None);
        assert_eq!(encode_der("KRB-ERROR", &decoded)?, bytes);
        Ok(())
    }

    /// Pins that the gokrb5 PA-FOR-USER fixture decodes to the expected fields and re-encodes byte for byte.
    #[test]
    fn pa_for_user_decodes_and_roundtrips_gokrb5_fixture() -> Result<(), TestError> {
        let bytes = hex::decode(PA_FOR_USER)?;
        let decoded = PaForUser::decode_der(&bytes)?;

        assert_eq!(decoded.user_name().r#type, 1_i32);
        assert_eq!(decoded.user_name().string.len(), 2);
        assert_eq!(
            decoded
                .user_name()
                .string
                .first()
                .ok_or("first name component")?
                .as_bytes(),
            b"hftsai"
        );
        assert_eq!(
            decoded
                .user_name()
                .string
                .get(1)
                .ok_or("second name component")?
                .as_bytes(),
            b"extra"
        );
        assert_eq!(decoded.user_realm().as_bytes(), b"ATHENA.MIT.EDU");
        assert_eq!(decoded.cksum().r#type, 1_i32);
        assert_eq!(decoded.cksum().checksum.as_ref(), b"1234");
        assert_eq!(decoded.auth_package().as_bytes(), b"krb5data");
        assert_eq!(decoded.encode_der()?, bytes);
        Ok(())
    }

    /// Pins that PA-PAC-OPTIONS flags decode to their bits and re-encode byte for byte.
    #[test]
    fn pa_pac_options_decodes_and_roundtrips_flags() -> Result<(), TestError> {
        let bytes = hex::decode(PA_PAC_OPTIONS_CLAIMS_AND_RBCD)?;
        let decoded = PaPacOptions::decode_der(&bytes)?;

        assert_eq!(decoded.bits(), 0x9000_0000);
        assert_eq!(decoded.encode_der()?, bytes);
        assert_eq!(PaPacOptions::from_bits(0x9000_0000), decoded);
        Ok(())
    }

    /// Pins that PA-REQ-ENC-PA-REP decodes, converts to and from a checksum and re-encodes byte for byte.
    #[test]
    fn pa_req_enc_pa_rep_decodes_and_roundtrips_gokrb5_shape() -> Result<(), TestError> {
        let bytes = hex::decode(PA_REQ_ENC_PA_REP)?;
        let decoded = PaReqEncPaRep::decode_der(&bytes)?;

        assert_eq!(decoded.checksum_type(), 15_i32);
        assert_eq!(decoded.checksum(), b"1234");
        assert_eq!(
            decoded.to_checksum(),
            Checksum {
                r#type: 15,
                checksum: b"1234".as_slice().into(),
            }
        );
        assert_eq!(PaReqEncPaRep::from_checksum(decoded.to_checksum()), decoded);
        assert_eq!(decoded.encode_der()?, bytes);
        Ok(())
    }

    /// Decodes a hex `EncryptedData` fixture.
    fn decode_encrypted_data(fixture: &str) -> Result<EncryptedData, TestError> {
        Ok(der::decode(&hex::decode(fixture)?)?)
    }

    /// Returns the system time `seconds` after the Unix epoch.
    fn timestamp(seconds: u64) -> Result<SystemTime, TestError> {
        Ok(UNIX_EPOCH
            .checked_add(Duration::from_secs(seconds))
            .ok_or("fixture timestamp is representable")?)
    }
}
