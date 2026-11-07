//! Redacted diagnostics and value-attached erasure for decrypted credentials.

use core::fmt;

use zeroize::Zeroize as _;

use super::{NtlmSupplementalCredential, Pac, SecpkgSupplementalCredential};

impl fmt::Debug for Pac {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            c_buffers,
            version,
            buffers,
            data,
            zero_signature_data,
            kerb_validation_info,
            server_checksum,
            kdc_checksum,
            credentials_info,
            client_info,
            upn_dns_info,
            s4u_delegation_info,
            device_info,
            client_claims_info,
            device_claims_info,
        } = self;
        f.debug_struct("Pac")
            .field("c_buffers", c_buffers)
            .field("version", version)
            .field("buffers", buffers)
            .field("data_len", &data.len())
            .field("zero_signature_data_len", &zero_signature_data.len())
            .field("kerb_validation_info", kerb_validation_info)
            .field("server_checksum", server_checksum)
            .field("kdc_checksum", kdc_checksum)
            .field("credentials_info", credentials_info)
            .field("client_info", client_info)
            .field("upn_dns_info", upn_dns_info)
            .field("s4u_delegation_info", s4u_delegation_info)
            .field("device_info", device_info)
            .field("client_claims_info", client_claims_info)
            .field("device_claims_info", device_claims_info)
            .finish()
    }
}

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
