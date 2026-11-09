//! Supplemental credential count admission probes.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use rskrb5_ng::{error::Pac as PacError, pac::CredentialData};

    use crate::context::{Context as _, TestError};

    /// Pins count rejection before reading or reserving nonexistent descriptors.
    #[test]
    fn credentials_rejects_count_without_descriptor_extent() -> Result<(), TestError> {
        // Given: a bounded count without the corresponding fixed descriptors.
        let mut bytes = count_only(64);
        bytes.extend_from_slice(&64_u32.to_le_bytes());
        bytes.extend_from_slice(&[0; 4]);
        bytes
            .get_mut(8..12)
            .context("object length")?
            .copy_from_slice(&16_u32.to_le_bytes());
        // When: the public parser admits the count.
        let error = CredentialData::parse(&bytes)
            .err()
            .context("missing extent rejected")?;
        // Then: count admission fails before descriptor decoding begins.
        assert!(matches!(
            error,
            PacError::UnreasonableNdrCount {
                count: 64,
                target: _
            }
        ));
        Ok(())
    }

    /// The count ceiling rejects even a fully supplied fixed descriptor extent.
    #[test]
    fn credentials_rejects_count_above_ceiling_with_extent() -> Result<(), TestError> {
        // Given matching counts and sufficient zeroed descriptors above the ceiling.
        let count = 1_000_001_u32;
        let descriptor_bytes = usize::try_from(count)?.checked_mul(16).context("extent")?;
        let object_len = descriptor_bytes.checked_add(16).context("object extent")?;
        let mut bytes = count_only(count);
        bytes.extend_from_slice(&count.to_le_bytes());
        bytes.resize(object_len.checked_add(16).context("wrapper extent")?, 0);
        bytes
            .get_mut(8..12)
            .context("object length")?
            .copy_from_slice(&u32::try_from(object_len)?.to_le_bytes());
        // When the public parser admits the complete descriptor extent.
        let result = CredentialData::parse(&bytes);
        // Then the independent policy ceiling rejects before descriptor allocation.
        assert!(matches!(
            result,
            Err(PacError::UnreasonableNdrCount {
                count: 1_000_001,
                target: "SECPKGSupplementalCred"
            })
        ));
        Ok(())
    }

    /// Pins empty credential data as a valid zero-allocation boundary.
    #[test]
    fn credentials_accepts_empty_count() -> Result<(), TestError> {
        // Given: an empty credential object.
        let mut bytes = count_only(0);
        bytes.extend_from_slice(&[0; 8]);
        bytes
            .get_mut(8..12)
            .context("object length")?
            .copy_from_slice(&16_u32.to_le_bytes());
        // When: the public parser handles it.
        let data = CredentialData::parse(&bytes).context("empty credentials parse")?;
        // Then: no supplemental packages are returned.
        assert!(
            data.credentials().is_empty(),
            "zero count has no credentials"
        );
        Ok(())
    }

    /// Pins the NDR32 conformant count preceding the structure's own count.
    #[test]
    fn credentials_accepts_conformant_single_entry() -> Result<(), TestError> {
        // Given: conformance count, CredentialCount, then one empty package descriptor.
        let mut bytes = count_only(1);
        bytes.extend_from_slice(&1_u32.to_le_bytes());
        bytes.extend_from_slice(&[0; 16]);
        bytes.extend_from_slice(&[0; 4]);
        bytes
            .get_mut(8..12)
            .context("object length")?
            .copy_from_slice(&32_u32.to_le_bytes());
        // When: the conforming empty-package object is parsed.
        let data = CredentialData::parse(&bytes).context("conformant package parses")?;
        // Then: its single package is retained.
        assert_eq!(data.credentials().len(), 1);
        Ok(())
    }

    /// Nonempty RPC strings cannot reference null, even with matching capacity.
    #[test]
    fn credentials_rejects_nonempty_null_package_name() -> Result<(), TestError> {
        let mut bytes = count_only(1);
        bytes.extend_from_slice(&1_u32.to_le_bytes());
        bytes.extend_from_slice(&2_u16.to_le_bytes());
        bytes.extend_from_slice(&2_u16.to_le_bytes());
        bytes.extend_from_slice(&[0; 16]);
        bytes
            .get_mut(8..12)
            .context("length")?
            .copy_from_slice(&32_u32.to_le_bytes());
        assert!(matches!(
            CredentialData::parse(&bytes),
            Err(PacError::MissingNdrPointer(
                "SECPKGSupplementalCred.PackageName"
            ))
        ));
        Ok(())
    }

    /// Pins correlation before descriptor admission or allocation.
    #[test]
    fn credentials_rejects_mismatched_conformant_count() -> Result<(), TestError> {
        // Given: two count words that disagree.
        let mut bytes = count_only(1);
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        bytes.extend_from_slice(&[0; 4]);
        bytes
            .get_mut(8..12)
            .context("object length")?
            .copy_from_slice(&16_u32.to_le_bytes());
        // When: the count pair is parsed.
        let error = CredentialData::parse(&bytes)
            .err()
            .context("count mismatch rejected")?;
        // Then: the mismatch is identified independently of descriptor contents.
        assert!(matches!(
            error,
            PacError::CountMismatch {
                target: _,
                expected: 0,
                actual: 1
            }
        ));
        Ok(())
    }

    /// Builds the historical single-count wire shape for the rejection controls.
    fn count_only(count: u32) -> Vec<u8> {
        let mut bytes = vec![1, 0x10, 8, 0, 0xcc, 0xcc, 0xcc, 0xcc];
        bytes.extend_from_slice(&8_u32.to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        bytes.extend_from_slice(&0x0002_0000_u32.to_le_bytes());
        bytes.extend_from_slice(&count.to_le_bytes());
        bytes
    }
}
