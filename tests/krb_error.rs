//! KRB-ERROR tests: gokrb5 fixture round-trips, validation and METHOD-DATA extraction.
#![cfg(feature = "messages")]

/// KRB-ERROR tests.
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

    use pretty_assertions::assert_eq;
    use rasn::types::Integer;
    use rasn_kerberos::{MethodData, PaData};
    use rskrb5_ng::{
        error::KrbErrorCodec as Error,
        krb_error::{
            KRB_ERROR_MSG_TYPE, KRB5_PVNO, decode as decode_krb_error, decode_krb_error_info,
            decode_method_data, encode as encode_krb_error, encode_method_data,
            preauth_method_data, validate as validate_krb_error,
        },
    };

    /// Error type of the `Result`-returning tests.
    type TestError = Box<dyn error::Error>;

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
    /// Timestamp of the gokrb5 fixtures, in seconds since the Unix epoch.
    const TEST_TIME_SECONDS: u64 = 771_228_197;
    /// `KDC_ERR_PREAUTH_REQUIRED` error code.
    const KDC_ERR_PREAUTH_REQUIRED: i32 = 25;
    /// `PA-ETYPE-INFO2` pre-authentication data type.
    const PA_ETYPE_INFO2: i32 = 19;

    /// Pins that the gokrb5 KRB-ERROR fixture decodes to the expected fields and re-encodes byte for byte.
    #[test]
    fn decodes_and_roundtrips_gokrb5_krb_error_fixture() -> Result<(), TestError> {
        let bytes = hex::decode(KRB_ERROR)?;

        let krb_error = decode_krb_error(&bytes)?;
        let info = decode_krb_error_info(&bytes)?;

        assert_eq!(krb_error.pvno, Integer::from(KRB5_PVNO));
        assert_eq!(krb_error.msg_type, Integer::from(KRB_ERROR_MSG_TYPE));
        assert_eq!(info.ctime(), Some(timestamp(TEST_TIME_SECONDS)?));
        assert_eq!(info.cusec(), Some(123_456));
        assert_eq!(info.stime(), timestamp(TEST_TIME_SECONDS)?);
        assert_eq!(info.susec(), 123_456);
        assert_eq!(info.error_code(), 60_i32);
        assert_eq!(
            info.client().ok_or("client principal exists")?.realm,
            "ATHENA.MIT.EDU"
        );
        assert_eq!(
            info.client().ok_or("client principal exists")?.name(),
            "hftsai/extra"
        );
        assert_eq!(info.service().realm, "ATHENA.MIT.EDU");
        assert_eq!(info.service().name(), "hftsai/extra");
        assert_eq!(info.e_text(), Some("krb5data"));
        assert_eq!(info.e_data(), Some(b"krb5data".as_slice()));
        assert_eq!(encode_krb_error(&krb_error)?, bytes);
        Ok(())
    }

    /// Pins that the gokrb5 KRB-ERROR fixture without optional fields decodes and re-encodes byte for byte.
    #[test]
    fn decodes_and_roundtrips_gokrb5_krb_error_optionals_null_fixture() -> Result<(), TestError> {
        let bytes = hex::decode(KRB_ERROR_OPTIONALS_NULL)?;

        let krb_error = decode_krb_error(&bytes)?;
        let info = decode_krb_error_info(&bytes)?;

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
        assert_eq!(encode_krb_error(&krb_error)?, bytes);
        Ok(())
    }

    /// Pins that a KRB-ERROR with another message type is rejected with the observed type.
    #[test]
    fn rejects_non_krb_error_message_type() -> Result<(), TestError> {
        let mut krb_error = decode_krb_error(&hex::decode(KRB_ERROR)?)?;
        krb_error.msg_type = Integer::from(11_i32);

        let error = validate_krb_error(&krb_error)
            .err()
            .ok_or("wrong msg-type is rejected")?;

        assert_eq!(
            error,
            Error::InvalidMessage {
                field: "msg-type",
                expected: KRB_ERROR_MSG_TYPE,
                actual: "11".to_owned(),
            }
        );
        Ok(())
    }

    /// Pins that the METHOD-DATA of a pre-authentication-required error decodes.
    #[test]
    fn decodes_method_data_from_preauth_required_error() -> Result<(), TestError> {
        let mut krb_error = decode_krb_error(&hex::decode(KRB_ERROR)?)?;
        let method_data = MethodData::from([PaData {
            r#type: PA_ETYPE_INFO2,
            value: vec![1, 2, 3].into(),
        }]);
        krb_error.error_code = KDC_ERR_PREAUTH_REQUIRED;
        krb_error.e_data = Some(encode_method_data(&method_data)?.into());

        let decoded = preauth_method_data(&krb_error, KDC_ERR_PREAUTH_REQUIRED)?;

        assert_eq!(decoded, method_data);
        assert_eq!(
            decode_method_data(krb_error.e_data.as_ref().ok_or("e-data exists")?.as_ref())?,
            method_data
        );
        Ok(())
    }

    /// Pins that METHOD-DATA is ignored when the error code is not the requested one.
    #[test]
    fn ignores_method_data_when_error_code_does_not_match() -> Result<(), TestError> {
        let krb_error = decode_krb_error(&hex::decode(KRB_ERROR)?)?;

        let method_data = preauth_method_data(&krb_error, KDC_ERR_PREAUTH_REQUIRED)?;

        assert!(method_data.is_empty(), "no METHOD-DATA is returned");
        Ok(())
    }

    /// Returns the system time `seconds` after the Unix epoch.
    fn timestamp(seconds: u64) -> Result<SystemTime, TestError> {
        Ok(UNIX_EPOCH
            .checked_add(Duration::from_secs(seconds))
            .ok_or("fixture timestamp is representable")?)
    }
}
