use super::*;

/// Explicit AP-REQ metadata must describe precisely the encoded authenticator.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use rasn::types::Integer;
    use rskrb5_ng::ap_req;
    #[cfg(feature = "spnego")]
    use rskrb5_ng::{
        ap_rep,
        spnego::{self, InitiatorContextOptions},
    };

    use super::*;

    /// Complete builders reject invalid split timestamp scalars before encryption.
    #[test]
    fn complete_authenticators_reject_invalid_scalars() -> Result<(), TestError> {
        let session = sample_tgt_session()?;
        let whole = timestamp(1_893_553_452)?;
        for (time, usec) in [
            (whole, 1_000_000),
            (whole, u32::MAX),
            (
                whole
                    .checked_add(Duration::from_millis(500))
                    .context("fraction")?,
                0,
            ),
        ] {
            assert!(matches!(
                pa_enc_timestamp_with_confounder(&session.session_key, time, usec, &[0; 16], None),
                Err(Error::Encode {
                    target: _,
                    message: _
                })
            ));
            assert!(matches!(
                build_tgs_req_with_confounder(
                    &session,
                    sample_service_principal(),
                    TgsReq::new(whole, 42),
                    time,
                    usec,
                    &[0; 16]
                ),
                Err(Error::Encode {
                    target: _,
                    message: _
                })
            ));
            assert!(matches!(
                build_ap_req_with_confounder(&session, ApReq::new(), time, usec, &[0; 16]),
                Err(Error::Encode {
                    target: _,
                    message: _
                })
            ));
        }
        Ok(())
    }

    /// Fractional explicit input must not produce truncated wire data and fractional metadata.
    #[test]
    fn fractional_ap_req_time_is_rejected() -> Result<(), TestError> {
        // Given positive and negative half-second explicit timestamps.
        let session = sample_tgt_session()?;
        for time in [
            SystemTime::UNIX_EPOCH.checked_sub(Duration::from_millis(500)),
            timestamp(1_893_553_452)?.checked_add(Duration::from_millis(500)),
        ] {
            // When building the authenticator, then the caller must supply whole seconds.
            let result = build_ap_req_with_confounder(
                &session,
                ApReq::new(),
                time.context("time")?,
                123_456,
                &[0; 16],
            );
            assert!(matches!(
                result,
                Err(Error::Encode {
                    target: "AP-REQ timestamp",
                    message: _
                })
            ));
        }
        Ok(())
    }

    /// Whole-second timestamps around the epoch round-trip with separate microseconds intact.
    #[test]
    fn whole_second_ap_req_metadata_matches_wire() -> Result<(), TestError> {
        // Given explicit whole seconds, including a pre-epoch value.
        let session = sample_tgt_session()?;
        for seconds in [-1_i64, 0, 1_893_553_452] {
            let time = if seconds < 0 {
                SystemTime::UNIX_EPOCH.checked_sub(Duration::from_secs(seconds.unsigned_abs()))
            } else {
                SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(u64::try_from(seconds)?))
            }
            .context("time")?;
            // When building and independently decrypting the authenticator.
            let built =
                build_ap_req_with_confounder(&session, ApReq::new(), time, 999_999, &[0; 16])?;
            let decoded = ap_req::decrypt_ap_req_authenticator(
                &built.message,
                &session.session_key,
                ap_req::authenticator_usage_for_ticket(&built.message.ticket),
            )?;
            // Then wire fields and retained AP-REP verification metadata agree exactly.
            assert_eq!(decoded.ctime.0.timestamp(), seconds);
            assert_eq!(decoded.cusec, Integer::from(999_999_u32));
            assert_eq!(built.authenticator_ctime, time);
            #[cfg(feature = "spnego")]
            {
                let context = spnego::init_sec_context_with_confounder(
                    &session,
                    InitiatorContextOptions::new().with_sequence_number(Some(42)),
                    time,
                    999_999,
                    &[0; 16],
                )?;
                let reply = ap_rep::build_ap_rep_with_confounder(
                    &rasn_kerberos::EncApRepPart {
                        ctime: decoded.ctime,
                        cusec: decoded.cusec,
                        subkey: None,
                        seq_number: Some(42),
                    },
                    &session.session_key,
                    None,
                    &[0; 16],
                )?;
                let verified = context.verify_ap_rep(&ap_rep::encode(&reply)?)?;
                assert_eq!(verified.ctime, time);
                assert_eq!(verified.authenticator_time, built.authenticator_time);
            }
            assert_eq!(
                built.authenticator_time,
                time.checked_add(Duration::from_micros(999_999))
                    .context("microseconds")?
            );
        }
        Ok(())
    }
}
