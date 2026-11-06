//! Redacted diagnostics and value-attached erasure for decrypted credentials.

use core::fmt;

use zeroize::Zeroize as _;

use super::{NtlmSupplementalCredential, SecpkgSupplementalCredential};

impl fmt::Debug for SecpkgSupplementalCredential {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            package_name,
            credential_size,
            credentials: _,
        } = self;
        f.debug_struct("SecpkgSupplementalCredential")
            .field("package_name", package_name)
            .field("credential_size", credential_size)
            .field("credentials", &"[REDACTED]")
            .finish()
    }
}

impl fmt::Debug for NtlmSupplementalCredential {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            version,
            flags,
            lm_password: _,
            nt_password: _,
        } = self;
        f.debug_struct("NtlmSupplementalCredential")
            .field("version", version)
            .field("flags", flags)
            .field("lm_password", &"[REDACTED]")
            .field("nt_password", &"[REDACTED]")
            .finish()
    }
}

// Drop audit: optional fixed-size hash erasure is synchronous and performs no
// allocation, I/O or fallible work; abort still skips this destructor.
impl Drop for NtlmSupplementalCredential {
    /// Erases both owned optional hashes before releasing the credential value.
    #[inline]
    fn drop(&mut self) {
        let Self {
            version: _,
            flags: _,
            lm_password,
            nt_password,
        } = self;
        lm_password.zeroize();
        nt_password.zeroize();
        #[cfg(test)]
        super::mutation_tests::ERASED_HASHES.with(|erased| {
            erased.set(lm_password.is_none() && nt_password.is_none());
        });
    }
}
