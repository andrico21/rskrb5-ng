use super::*;

/// Unarmored AS canonicalization policy regressions.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use super::*;

    /// Unarmored AS requests must not advertise unsupported identity changes.
    #[test]
    fn as_request_does_not_advertise_unprotected_canonicalization() -> Result<(), TestError> {
        let request = build_tgt_as_req(
            Principal::user("TEST.GOKRB5", "alias"),
            AsReq::new(timestamp(1_893_553_447)?, 42).with_kdc_option_bits(KDC_OPTION_CANONICALIZE),
        )?;
        assert_eq!(
            request.message().0.req_body.kdc_options.0.as_raw_slice(),
            &[0, 0, 0, 0]
        );
        Ok(())
    }
}
