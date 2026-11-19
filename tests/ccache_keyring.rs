//! The `KEYRING` cache type (the `ccache-keyring` leaf, MIT 1.22.2
//! `cc_keyring.c`) against the kernel of this machine.
//!
//! A kernel or sandbox that filters the key calls answers `ENOSYS` or `EPERM`;
//! the tests then print `keyring: SKIP <test>: <reason>` and pass. With
//! `RSKRB5_KEYRING_REQUIRED=1`, which the hosted `keyring` job sets on an
//! `ubuntu-latest` VM, an unusable keyring fails every test instead. The
//! namespace tests start this test binary again as a child process.

/// Probing, required mode and shared helpers.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    reason = "test code is not rendered API documentation"
)]
#[path = "ccache_keyring/support.rs"]
mod support;

/// Lifecycle, collections and failures against the real kernel.
#[cfg(all(feature = "ccache-keyring", target_os = "linux"))]
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "ccache_keyring/kernel.rs"]
mod kernel;

/// Namespace isolation between threads and processes.
#[cfg(all(feature = "ccache-keyring", target_os = "linux"))]
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "ccache_keyring/namespaces.rs"]
mod namespaces;

/// Without the leaf, or off Linux, `KEYRING:` names are refused as before.
#[cfg(not(all(feature = "ccache-keyring", target_os = "linux")))]
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod inert {
    use rskrb5_ng::{
        ccache::{
            file_store,
            keyring::Keyring,
            stores::{CacheVersion, CredentialStore as _},
        },
        error::Ccache as Error,
    };

    use crate::support::TestError;

    /// The unsupported-store error stays when the leaf is off.
    #[test]
    fn keyring_names_stay_unsupported() -> Result<(), TestError> {
        assert!(
            matches!(
                file_store::resolve("KEYRING:process:krb", CacheVersion::V4),
                Err(Error::UnsupportedCacheType { ref cache_type }) if cache_type == "KEYRING"
            ),
            "resolve"
        );
        assert!(
            matches!(
                file_store::collection("KEYRING:process:krb", CacheVersion::V4),
                Err(Error::UnsupportedCacheType { cache_type: _ })
            ),
            "collection"
        );
        assert!(
            matches!(
                Keyring::new().resolve("process:krb"),
                Err(Error::UnsupportedCacheType { cache_type: _ })
            ),
            "store"
        );
        Ok(())
    }
}
