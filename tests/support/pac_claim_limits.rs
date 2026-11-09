//! Trusted output bounds for PAC claims decoding.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use compcol::{vec::compress_to_vec, xpress::Xpress};
    use rskrb5_ng::{
        error::Pac as PacError,
        pac::{
            CLAIMS_COMPRESSION_FORMAT_LZNT1, CLAIMS_COMPRESSION_FORMAT_NONE,
            CLAIMS_COMPRESSION_FORMAT_XPRESS, CLAIMS_COMPRESSION_FORMAT_XPRESS_HUFF,
            ClaimsSetMetadata,
        },
    };

    use crate::context::{Context as _, TestError};

    /// Pins admission before invoking any compressed format's decoder.
    #[test]
    fn claims_rejects_excessive_declared_output() -> Result<(), TestError> {
        // Given: valid metadata with a tiny payload and an excessive size hint.
        for format in [
            CLAIMS_COMPRESSION_FORMAT_LZNT1,
            CLAIMS_COMPRESSION_FORMAT_XPRESS,
            CLAIMS_COMPRESSION_FORMAT_XPRESS_HUFF,
        ] {
            let mut metadata = metadata()?;
            metadata.compression_format = format;
            metadata.uncompressed_claims_set_size = 0x0010_0001;
            // When: output decoding is requested.
            let error = metadata
                .decoded_claims_set_bytes()
                .err()
                .context("oversized declaration rejected")?;
            // Then: the policy ceiling, not malformed compression, rejects it.
            assert!(matches!(error, PacError::ClaimsOutputLimit));
        }
        Ok(())
    }

    /// Pins that uncompressed copies cannot bypass the output ceiling.
    #[test]
    fn claims_rejects_excessive_uncompressed_output() -> Result<(), TestError> {
        // Given: mutable public metadata with an oversized uncompressed payload.
        let mut metadata = metadata()?;
        metadata.compression_format = CLAIMS_COMPRESSION_FORMAT_NONE;
        metadata.claims_set_bytes = vec![0; 0x0010_0001];
        // When: output decoding is requested.
        let error = metadata
            .decoded_claims_set_bytes()
            .err()
            .context("oversized raw output rejected")?;
        // Then: copying is subject to the same trusted limit.
        assert!(matches!(error, PacError::ClaimsOutputLimit));
        Ok(())
    }

    /// Pins inclusive compressed output admission.
    #[test]
    fn claims_accepts_output_limit() -> Result<(), TestError> {
        // Given: a compressible payload exactly at the local output ceiling.
        let payload = vec![0x41; 0x0010_0000];
        let compressed = compress_to_vec::<Xpress>(&payload).context("XPRESS compresses")?;
        let mut metadata = metadata()?;
        metadata.compression_format = CLAIMS_COMPRESSION_FORMAT_XPRESS;
        metadata.uncompressed_claims_set_size = 0x0010_0000;
        metadata.claims_set_bytes = compressed.get(8..).context("XPRESS frame header")?.to_vec();
        // When: the exact-boundary stream is decoded.
        let decoded = metadata
            .decoded_claims_set_bytes()
            .context("boundary output permitted")?;
        // Then: the entire payload survives, without clamping.
        assert_eq!(decoded, payload);
        Ok(())
    }

    /// Uncompressed wire metadata must declare the exact decoded extent.
    #[test]
    fn uncompressed_claims_require_exact_declared_size() -> Result<(), TestError> {
        // Given: one actual byte and independent size declarations.
        for expected in [0_u32, 1, 2] {
            let mut wire = vec![1, 0x10, 8, 0, 0xcc, 0xcc, 0xcc, 0xcc];
            wire.extend_from_slice(&48_u32.to_le_bytes());
            wire.extend_from_slice(&0_u32.to_le_bytes());
            wire.extend_from_slice(&1_u32.to_le_bytes());
            wire.extend_from_slice(&1_u32.to_le_bytes());
            wire.extend_from_slice(&1_u32.to_le_bytes());
            wire.extend_from_slice(&0_u32.to_le_bytes());
            wire.extend_from_slice(&expected.to_le_bytes());
            wire.extend_from_slice(&[0; 12]);
            wire.extend_from_slice(&1_u32.to_le_bytes());
            wire.extend_from_slice(&[0x42, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
            let parsed = ClaimsSetMetadata::parse(&wire)?;
            // When: uncompressed output is requested.
            let result = parsed.decoded_claims_set_bytes();
            // Then: both mismatch directions return the exact consistency error.
            if expected == 1 {
                assert_eq!(result?, [0x42]);
            } else {
                assert!(
                    matches!(result, Err(PacError::ClaimsDecompressedSizeMismatch {
                    compression_format: CLAIMS_COMPRESSION_FORMAT_NONE,
                    expected: declared,
                    actual: 1,
                }) if declared == usize::try_from(expected)?)
                );
            }
        }
        assert!(
            metadata()?.decoded_claims_set_bytes()?.is_empty(),
            "matching empty output"
        );
        Ok(())
    }

    /// Builds an empty metadata object independently of claims decoding.
    fn metadata() -> Result<ClaimsSetMetadata, TestError> {
        let bytes = hex::decode("01100800cccccccc20000000000000000000020000000000000000000000000000000000000000000000000000000000").context("metadata hex decodes")?;
        ClaimsSetMetadata::parse(&bytes).context("empty metadata parses")
    }
}
