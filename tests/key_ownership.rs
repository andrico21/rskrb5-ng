//! Public key storage must erase independently of its enclosing record.

#[cfg(test)]
mod tests {
    use rskrb5_ng::{ccache, keytab};
    use zeroize::ZeroizeOnDrop;

    /// Require independently erased storage at the public replacement boundary.
    fn owns_erasure<T>(_: &T)
    where
        T: ZeroizeOnDrop,
    {
    }

    /// Replacing either public byte field must retain value-attached erasure.
    #[test]
    fn replaceable_key_bytes_own_erasure() {
        let cache = ccache::EncryptionKey::new(18, vec![0x51; 32]);
        let keytab = keytab::EncryptionKey::new(18, vec![0x62; 32]);
        owns_erasure(&cache.value);
        owns_erasure(&keytab.value);
    }
}
