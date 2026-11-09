//! MS-PAC NTLM supplemental credential wire regressions.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use rskrb5_ng::{error::Pac as PacError, pac::NtlmSupplementalCredential};

    use crate::context::{Context as _, TestError};

    /// Pins numeric low-bit validity masks and ignored reserved bits.
    #[test]
    fn ntlm_uses_low_bit_validity_masks() -> Result<(), TestError> {
        // Given: valid low-bit combinations, optionally with reserved high bits.
        for flags in [1_u32, 2, 3, 0x8000_0001, 0x8000_0002, 0xffff_ffff] {
            let bytes = wire(flags);
            // When: flags are decoded from their little-endian wire representation.
            let credential =
                NtlmSupplementalCredential::parse(&bytes).context("valid flags parse")?;
            // Then: only low bits determine validity, regardless of reserved bits.
            assert_eq!(credential.has_lm_password(), (flags & 1) != 0);
            assert_eq!(credential.has_nt_password(), (flags & 2) != 0);
        }
        Ok(())
    }

    /// Pins the requirement that at least one hash validity flag is present.
    #[test]
    fn ntlm_rejects_flags_without_valid_hash() -> Result<(), TestError> {
        // Given: no validity bit, including the formerly recognized high bits.
        for flags in [0_u32, 0x0300_0000, 0xffff_fffc] {
            let bytes = wire(flags);
            // When: the record is parsed.
            let error = NtlmSupplementalCredential::parse(&bytes)
                .err()
                .context("missing validity flags rejected")?;
            // Then: reserved bits cannot make an empty credential valid.
            assert!(matches!(error, PacError::MissingNtlmValidityFlag));
        }
        Ok(())
    }

    /// Pins NT-only validity to the second fixed hash slot.
    #[test]
    fn ntlm_reads_nt_from_its_fixed_slot() -> Result<(), TestError> {
        // Given: NT-only validity and different LM/NT wire slots.
        let bytes = wire(2);
        // When: the NT-only credential is parsed.
        let credential =
            NtlmSupplementalCredential::parse(&bytes).context("NT-only record parses")?;
        // Then: the invalid LM slot is consumed but never exposed as NT.
        assert_eq!(credential.nt_password(), Some(&[0x22; 16]));
        assert_eq!(credential.lm_password(), None);
        Ok(())
    }

    /// Pins both fixed slots as required even if one hash is not valid.
    #[test]
    fn ntlm_rejects_truncated_fixed_slots() -> Result<(), TestError> {
        // Given: every nonempty validity combination and truncations within both slots.
        for flags in [1_u32, 2, 3] {
            let bytes = wire(flags);
            for len in [8, 23, 24, 39] {
                let truncated = bytes.get(..len).context("truncated prefix")?;
                // When: a short fixed-width record is parsed.
                let error = NtlmSupplementalCredential::parse(truncated)
                    .err()
                    .context("both fixed slots required")?;
                // Then: invalid-member flags do not excuse missing wire bytes.
                assert!(matches!(
                    error,
                    PacError::Truncated {
                        offset: _,
                        needed: _,
                        remaining: _
                    }
                ));
            }
        }
        Ok(())
    }

    /// Pins redaction without treating Debug's full layout as a stable format.
    #[test]
    fn ntlm_debug_redacts_hash_material() -> Result<(), TestError> {
        // Given: hash slots carrying recognizable marker bytes.
        let credential = NtlmSupplementalCredential::parse(&wire(3)).context("NTLM parses")?;
        // When: callers render public diagnostics.
        let rendered = format!("{credential:?}");
        // Then: neither hash marker leaks and redaction is explicit.
        assert!(!rendered.contains("17, 17"));
        assert!(!rendered.contains("34, 34"));
        assert!(rendered.contains("REDACTED"));
        Ok(())
    }

    /// Encodes the fixed 40-byte structure with distinct LM and NT slot markers.
    fn wire(flags: u32) -> Vec<u8> {
        let mut bytes = 0_u32.to_le_bytes().to_vec();
        bytes.extend_from_slice(&flags.to_le_bytes());
        bytes.extend_from_slice(&[0x11; 16]);
        bytes.extend_from_slice(&[0x22; 16]);
        bytes
    }
}
