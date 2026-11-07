//! Audited MAC verification boundaries and tag-length controls.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::error::Error;
    use std::fs;

    use rskrb5_ng::crypto::KerberosEtype;

    /// The assurance boundary uses the HMAC crate rather than raw tag comparison.
    #[test]
    fn verification_requires_audited_hmac_api() -> Result<(), Box<dyn Error>> {
        // Given production source at the extracted verification boundary.
        let boundary = fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/crypto/verification.rs"
        ))?;
        let dispatch = fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/crypto.rs"))?;
        // When auditing the verification API and its callers.
        // Then raw equality cannot replace the audited MAC verifier.
        assert!(
            boundary.contains(".verify_slice("),
            "full HMAC verification missing"
        );
        assert!(
            boundary.contains(".verify_truncated_left("),
            "truncated verification missing"
        );
        assert!(
            !dispatch.contains("constant_time_eq"),
            "handwritten equality remains reachable"
        );
        let spnego = fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/spnego.rs"))?;
        assert!(
            !spnego.contains("constant_time_eq"),
            "SPNEGO still uses handwritten MAC equality"
        );
        Ok(())
    }

    /// All families reject partial, extended and independently corrupted tags.
    #[test]
    fn checksum_rejects_each_mismatch_and_wrong_length() -> Result<(), Box<dyn Error>> {
        // Given authentic checksums from every supported family.
        for id in [16_i32, 17_i32, 18_i32, 19_i32, 20_i32, 23_i32] {
            let etype = KerberosEtype::from_etype_id(id).ok_or("etype")?;
            let key = vec![0x42; etype.key_len()];
            let tag = etype.checksum(&key, b"message", 17)?;
            // When exact, shortened, extended and changed tags are verified.
            assert!(etype.verify_checksum(&key, b"message", &tag, 17));
            for position in [0, tag.len().div_euclid(2), tag.len().saturating_sub(1)] {
                let mut changed = tag.clone();
                *changed.get_mut(position).ok_or("tag byte")? ^= 1;
                assert!(
                    !etype.verify_checksum(&key, b"message", &changed, 17),
                    "changed tag accepted"
                );
            }
            let short = tag.get(..tag.len().saturating_sub(1)).ok_or("short tag")?;
            let mut long = tag.clone();
            long.push(0);
            // Then public tag length is checked independently of constant-time equality.
            assert!(!etype.verify_checksum(&key, b"message", short, 17));
            assert!(!etype.verify_checksum(&key, b"message", &long, 17));
            assert!(!etype.verify_checksum(&key, b"message", &[], 17));
        }
        Ok(())
    }
}
