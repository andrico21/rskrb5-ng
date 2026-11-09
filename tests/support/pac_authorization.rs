//! Resource-boundary probes for direct PAC authorization-data traversal.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use rasn::der;
    use rasn_kerberos::{AuthorizationData, AuthorizationDataValue};
    use rskrb5_ng::{
        error::Pac as PacError,
        pac::{self, AD_IF_RELEVANT, AD_WIN2K_PAC},
    };

    use crate::{
        context::{Context as _, TestError},
        pac_ad_win2k,
    };

    /// Pins rejection of a ninth wrapper without attempting stack exhaustion.
    #[test]
    fn rejects_authorization_data_depth_above_eight() -> Result<(), TestError> {
        // Given: nine independently valid DER wrappers.
        let data = nested(AuthorizationData::default(), 9)?;
        // When: the public helper traverses the chain.
        let error = pac::find_pac_in_authorization_data(&data)
            .err()
            .context("ninth wrapper must exceed the depth budget")?;
        // Then: traversal fails rather than treating the chain as PAC-free.
        assert!(matches!(error, PacError::AuthorizationDataDepthLimit));
        Ok(())
    }

    /// Pins successful PAC extraction at the inclusive depth boundary.
    #[test]
    fn extracts_pac_at_authorization_data_depth_eight() -> Result<(), TestError> {
        // Given: the existing PAC vector under eight wrappers.
        let bytes = hex::decode(pac_ad_win2k::PAC_AD_WIN2K).context("PAC vector decodes")?;
        let data = nested(
            AuthorizationData::from(vec![AuthorizationDataValue {
                r#type: AD_WIN2K_PAC,
                data: bytes.into(),
            }]),
            8,
        )?;
        // When: the public helper extracts the PAC.
        let pac = pac::find_pac_in_authorization_data(&data)
            .context("boundary depth is permitted")?
            .context("nested PAC is found")?;
        // Then: the ordinary PAC is still processed.
        assert_eq!(pac.c_buffers(), 5);
        Ok(())
    }

    /// Pins one aggregate byte budget across sibling decodes and their children.
    #[test]
    fn rejects_authorization_data_aggregate_bytes() -> Result<(), TestError> {
        // Given: individually small sibling wrappers whose total work exceeds 1 MiB.
        let child = AuthorizationData::from(vec![AuthorizationDataValue {
            r#type: 42,
            data: vec![0; 300_000].into(),
        }]);
        let encoded = der::encode(&child).context("child encodes")?;
        let data = AuthorizationData::from(vec![
            AuthorizationDataValue {
                r#type: AD_IF_RELEVANT,
                data: encoded.clone().into(),
            },
            AuthorizationDataValue {
                r#type: AD_IF_RELEVANT,
                data: encoded.into(),
            },
        ]);
        // When: traversal visits both branches.
        let error = pac::find_pac_in_authorization_data(&data)
            .err()
            .context("siblings must share the byte budget")?;
        // Then: aggregate work is rejected, not reset for each branch.
        assert!(matches!(error, PacError::AuthorizationDataByteLimit));
        Ok(())
    }

    /// Pins the inclusive byte boundary for visited payloads.
    #[test]
    fn accepts_authorization_data_at_byte_budget() -> Result<(), TestError> {
        // Given: one ignored payload of exactly 1 MiB.
        let data = AuthorizationData::from(vec![AuthorizationDataValue {
            r#type: 42,
            data: vec![0; 0x0010_0000].into(),
        }]);
        // When: traversal charges the payload against the budget.
        let result = pac::find_pac_in_authorization_data(&data)
            .context("exactly the byte budget is permitted")?;
        // Then: there is no PAC and no resource error.
        assert!(result.is_none());
        Ok(())
    }

    /// Pins byte admission before attempting to decode an oversized wrapper.
    #[test]
    fn rejects_authorization_data_bytes_before_decode() -> Result<(), TestError> {
        // Given: an oversized payload that is also malformed DER.
        let data = AuthorizationData::from(vec![AuthorizationDataValue {
            r#type: AD_IF_RELEVANT,
            data: vec![0; 0x0010_0001].into(),
        }]);
        // When: the public helper reaches the wrapper.
        let error = pac::find_pac_in_authorization_data(&data)
            .err()
            .context("oversized wrapper is rejected")?;
        // Then: resource admission wins over a DER error after allocation.
        assert!(matches!(error, PacError::AuthorizationDataByteLimit));
        Ok(())
    }

    /// Wraps opaque authorization data without recursively building the fixture.
    fn nested(mut data: AuthorizationData, depth: usize) -> Result<AuthorizationData, TestError> {
        for _ in 0..depth {
            data = AuthorizationData::from(vec![AuthorizationDataValue {
                r#type: AD_IF_RELEVANT,
                data: der::encode(&data).context("wrapper encodes")?.into(),
            }]);
        }
        Ok(data)
    }
}
