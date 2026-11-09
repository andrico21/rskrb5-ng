//! Redacted diagnostics and value-attached erasure for decrypted credentials.

use core::fmt;

use zeroize::Zeroize as _;

use super::{
    CredentialData, CredentialsInfo, KerbValidationInfo, NtlmSupplementalCredential, Pac,
    SecpkgSupplementalCredential,
};

impl fmt::Debug for KerbValidationInfo {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            logon_time,
            logoff_time,
            kickoff_time,
            password_last_set,
            password_can_change,
            password_must_change,
            effective_name,
            full_name,
            logon_script,
            profile_path,
            home_directory,
            home_directory_drive,
            logon_count,
            bad_password_count,
            user_id,
            primary_group_id,
            group_count,
            group_ids,
            user_flags,
            user_session_key,
            logon_server,
            logon_domain_name,
            logon_domain_id,
            reserved1,
            user_account_control,
            sub_auth_status,
            last_successful_ilogon,
            last_failed_ilogon,
            failed_ilogon_count,
            reserved3,
            sid_count,
            extra_sids,
            resource_group_domain_sid,
            resource_group_count,
            resource_group_ids,
        } = self;
        f.debug_struct("KerbValidationInfo")
            .field("logon_time", logon_time)
            .field("logoff_time", logoff_time)
            .field("kickoff_time", kickoff_time)
            .field("password_last_set", password_last_set)
            .field("password_can_change", password_can_change)
            .field("password_must_change", password_must_change)
            .field("effective_name", effective_name)
            .field("full_name", full_name)
            .field("logon_script", logon_script)
            .field("profile_path", profile_path)
            .field("home_directory", home_directory)
            .field("home_directory_drive", home_directory_drive)
            .field("logon_count", logon_count)
            .field("bad_password_count", bad_password_count)
            .field("user_id", user_id)
            .field("primary_group_id", primary_group_id)
            .field("group_count", group_count)
            .field("group_ids", group_ids)
            .field("user_flags", user_flags)
            .field("user_session_key", user_session_key)
            .field("logon_server", logon_server)
            .field("logon_domain_name", logon_domain_name)
            .field("logon_domain_id", logon_domain_id)
            .field("reserved1", reserved1)
            .field("user_account_control", user_account_control)
            .field("sub_auth_status", sub_auth_status)
            .field("last_successful_ilogon", last_successful_ilogon)
            .field("last_failed_ilogon", last_failed_ilogon)
            .field("failed_ilogon_count", failed_ilogon_count)
            .field("reserved3", reserved3)
            .field("sid_count", sid_count)
            .field("extra_sids", extra_sids)
            .field("resource_group_domain_sid", resource_group_domain_sid)
            .field("resource_group_count", resource_group_count)
            .field("resource_group_ids", resource_group_ids)
            .finish()
    }
}

impl fmt::Debug for CredentialData {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            credential_count,
            credentials,
        } = self;
        f.debug_struct("CredentialData")
            .field("credential_count", credential_count)
            .field("credentials", credentials)
            .finish()
    }
}

impl fmt::Debug for CredentialsInfo {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            version,
            encryption_type,
            encrypted_credential_data,
        } = self;
        f.debug_struct("CredentialsInfo")
            .field("version", version)
            .field("encryption_type", encryption_type)
            .field(
                "encrypted_credential_data_len",
                &encrypted_credential_data.len(),
            )
            .finish()
    }
}

/// Observe old payload bytes before replacement, never after deallocation.
#[cfg(test)]
pub(super) fn observe_bytes(value: &[u8]) {
    tests::BYTE_REPLACEMENTS
        .with_borrow_mut(|events| events.push((value.len(), value.iter().all(|byte| *byte == 0))));
}

/// Observe the old hash before its owner is replaced, never after deallocation.
#[cfg(test)]
pub(super) fn observe_replacement(value: Option<&zeroize::Zeroizing<[u8; 16]>>) {
    tests::REPLACEMENTS.with_borrow_mut(|events| {
        events.push(value.is_some_and(|bytes| bytes.iter().all(|byte| *byte == 0)));
    });
}

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "credential_replacement_tests.rs"]
mod tests;

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
