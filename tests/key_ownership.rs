//! Public key storage must erase independently of its enclosing record.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    reason = "test code is not rendered API documentation"
)]
mod tests {
    use core::error::Error;

    use rskrb5_ng::{ccache, keytab};
    use zeroize::{Zeroize as _, ZeroizeOnDrop};

    /// Require independently erased storage at the public replacement boundary.
    fn owns_erasure<T>(_: &T)
    where
        T: ZeroizeOnDrop,
    {
    }

    /// Replacing either public byte field must retain value-attached erasure.
    #[test]
    fn replaceable_key_bytes_own_erasure() -> Result<(), Box<dyn Error>> {
        let cache = ccache::EncryptionKey::new(18, hex::decode("51".repeat(32))?);
        let keytab = keytab::EncryptionKey::new(18, hex::decode("62".repeat(32))?);
        owns_erasure(&cache.value);
        owns_erasure(&keytab.value);
        let mut erased = keytab.value.clone();
        erased.zeroize();
        assert!(erased.is_empty(), "zeroize leaves no key bytes");
        Ok(())
    }
}
