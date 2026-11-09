//! Preauthentication error hints at the public client decoding boundary.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use rasn::der;
    use rskrb5_ng::client::{PA_FX_COOKIE, process_kdc_error};

    use super::super::{Context as _, Error, TestError, synthetic_preauth_required_error};

    /// Builds an otherwise valid KRB-ERROR with the selected code and raw data.
    fn error_with_data(code: i32, data: Option<Vec<u8>>) -> Result<Vec<u8>, TestError> {
        let mut reply: rasn_kerberos::KrbError = der::decode(&synthetic_preauth_required_error()?)?;
        reply.error_code = code;
        reply.e_data = data.map(Into::into);
        Ok(der::encode(&reply)?)
    }

    /// Error 24 preserves both the key hint and the exact binary cookie.
    #[test]
    fn failed_preauth_preserves_info2_and_cookie() -> Result<(), TestError> {
        // Given a challenge with a known INFO2 hint and a binary cookie.
        let original = synthetic_preauth_required_error()?;
        let expected = process_kdc_error(&original)?;
        let mut data = expected.method_data().to_vec();
        data.push(rasn_kerberos::PaData {
            r#type: PA_FX_COOKIE,
            value: vec![0, 0xff, 42].into(),
        });
        let bytes = error_with_data(24, Some(der::encode(&data)?))?;

        // When the public client decodes PREAUTH_FAILED instead of REQUIRED.
        let parsed = process_kdc_error(&bytes)?;

        // Then neither the INFO2 parameters nor the cookie is discarded.
        assert_eq!(parsed.error_code(), 24_i32);
        assert_eq!(parsed.preauth_key_info(), expected.preauth_key_info());
        assert_eq!(parsed.method_data().to_vec(), data);
        Ok(())
    }

    /// Malformed error-24 hints are not silently treated as missing hints.
    #[test]
    fn failed_preauth_rejects_malformed_method_data() -> Result<(), TestError> {
        // Given a valid KRB-ERROR envelope with malformed METHOD-DATA.
        let bytes = error_with_data(24, Some(vec![0xff]))?;
        // When parsing the client error.
        let Err(error) = process_kdc_error(&bytes) else {
            return Err("malformed hints must fail".into());
        };
        // Then the exact decoding failure survives the client boundary.
        assert!(matches!(
            error,
            Error::Decode {
                target: "METHOD-DATA",
                message: _
            }
        ));
        Ok(())
    }

    /// An error without e-data still decodes as a hint-free error.
    #[test]
    fn failed_preauth_accepts_absent_method_data() -> Result<(), TestError> {
        // Given PREAUTH_FAILED without optional e-data.
        let bytes = error_with_data(24, None)?;
        // When parsing it.
        let parsed = process_kdc_error(&bytes)?;
        // Then absent hints remain distinct from malformed input.
        assert_eq!(parsed.e_data(), None);
        assert!(
            parsed.method_data().is_empty(),
            "absent data supplies no hints"
        );
        Ok(())
    }

    /// Unrelated errors keep opaque e-data without interpreting it as hints.
    #[test]
    fn unrelated_error_preserves_opaque_data() -> Result<(), TestError> {
        // Given a non-preauth error whose data is deliberately not DER.
        let opaque = vec![0xff, 0, 0x80];
        let bytes = error_with_data(6, Some(opaque.clone()))?;
        // When parsing it.
        let parsed = process_kdc_error(&bytes)?;
        // Then raw diagnostics survive and cannot supply retry hints.
        assert_eq!(
            parsed.e_data().context("opaque data retained")?.as_slice(),
            opaque.as_slice()
        );
        assert!(
            parsed.method_data().is_empty(),
            "unrelated data is not METHOD-DATA"
        );
        assert!(
            parsed.preauth_key_info().is_empty(),
            "unrelated data supplies no key"
        );
        Ok(())
    }
}
