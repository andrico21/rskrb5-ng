//! Explicit checksum admission at the complete AP construction boundary.
use super::*;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use rskrb5_ng::{
        ap_req,
        error::{Crypto, Policy, RejectedFeature},
    };

    use super::*;

    /// Explicit unkeyed selections fail before even an invalid crypto input is used.
    #[test]
    fn ap_rejects_prohibited_checksums_before_crypto() -> Result<(), TestError> {
        let session = sample_tgt_session()?;
        for id in (1_i32..=10_i32).chain([14_i32]) {
            for confounder in [&[0_u8; 16][..], &[][..]] {
                let options = ApReq::new().with_checksum(Some(rasn_kerberos::Checksum {
                    r#type: id,
                    checksum: vec![0x5a; 16].into(),
                }));
                let result = build_ap_req_with_confounder(
                    &session,
                    options,
                    timestamp(1_893_553_452)?,
                    0,
                    confounder,
                );
                assert!(
                    matches!(result, Err(Error::Crypto(Crypto::Policy(Policy::RejectedFeature {
                    feature: RejectedFeature::UnauthenticatedChecksum { id: rejected },
                    reason: _,
                }))) if rejected == id)
                );
            }
        }
        Ok(())
    }

    /// Keyed and GSS checksums retain their type and payload in the authenticator.
    #[test]
    fn ap_preserves_keyed_and_gss_checksums() -> Result<(), TestError> {
        let session = sample_tgt_session()?;
        let accepted: [i32; 7] = [12, 15, 16, 19, 20, -138, 0x8003];
        for id in accepted {
            let checksum = rasn_kerberos::Checksum {
                r#type: id,
                checksum: vec![0x5a; 16].into(),
            };
            let built = build_ap_req_with_confounder(
                &session,
                ApReq::new().with_checksum(Some(checksum.clone())),
                timestamp(1_893_553_452)?,
                0,
                &[0; 16],
            )?;
            let decoded = ap_req::decrypt_ap_req_authenticator(
                built.message(),
                session.session_key(),
                ap_req::authenticator_usage_for_ticket(&built.message().ticket),
            )?;
            assert_eq!(decoded.cksum, Some(checksum));
        }
        Ok(())
    }
}
