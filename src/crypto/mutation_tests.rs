//! RFC HMAC boundary vectors.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
/// Private crypto contract tests.
mod tests {
    use core::error::Error;

    use hmac::{Hmac, KeyInit as _, Mac as _};
    use sha2::Sha256;

    /// Mutating scratch changes the owned buffer later borrowed and returned.
    #[test]
    fn scratch_mutation_updates_owned_buffer() -> Result<(), Box<dyn Error>> {
        let mut scratch = super::super::SecretScratch::new(hex::decode("42")?);
        scratch.push(0x24);
        assert_eq!(scratch.as_slice(), &[0x42, 0x24]);
        Ok(())
    }

    /// RFC4231 case six hashes keys exceeding the SHA256 block size.
    #[test]
    fn hmac_hashes_oversized_key() {
        assert_eq!(
            hex::encode(super::super::hmac_sha256(
                &[0xaa; 131],
                b"Test Using Larger Than Block-Size Key - Hash Key First"
            )),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    /// RFC2104 leaves a full-block key unhashed, unlike an oversized key.
    #[test]
    fn hmac_retains_full_block_key() -> Result<(), Box<dyn Error>> {
        let key = [0xaa; 64];
        let mut oracle = Hmac::<Sha256>::new_from_slice(&key)?;
        oracle.update(b"full block key");
        assert_eq!(
            super::super::hmac_sha256(&key, b"full block key"),
            oracle.finalize().into_bytes().as_slice()
        );
        Ok(())
    }
}
