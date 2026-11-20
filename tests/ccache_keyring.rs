//! The `KEYRING` cache type against the kernel of this machine.
//!
//! This is the `ccache-keyring` leaf, MIT 1.22.2 `cc_keyring.c`.
//!
//! A kernel or sandbox that filters the key calls answers `ENOSYS` or `EPERM`;
//! the tests then print `keyring: SKIP <test>: <reason>` and pass. With
//! `RSKRB5_KEYRING_REQUIRED=1`, which the hosted `keyring` job sets on an
//! `ubuntu-latest` VM, an unusable keyring fails every test instead. The
//! namespace tests start this test binary again as a child process.

/// Probing, required mode and shared helpers.
#[cfg(all(feature = "ccache-keyring", target_os = "linux"))]
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

/// MIT's tools against the kernel keyring.
#[cfg(all(feature = "ccache-keyring", target_os = "linux"))]
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "ccache_keyring/mit.rs"]
mod mit;

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
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
mod inert {
    use rskrb5_ng::{
        ccache::{
            file_store,
            keyring::Keyring,
            stores::{CacheVersion, CredentialStore as _},
        },
        error::Ccache as Error,
    };

    /// The unsupported-store error stays when the leaf is off.
    #[test]
    fn keyring_names_stay_unsupported() {
        assert!(
            matches!(
                file_store::resolve("KEYRING:process:krb", CacheVersion::V4),
                Err(Error::UnsupportedCacheType { cache_type }) if cache_type == "KEYRING"
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
    }
}

/// `KEYRING` is a built-in cache type with the leaf on or off, so no store
/// provider can claim it.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    reason = "test code is not rendered API documentation"
)]
mod reserved {
    extern crate alloc;

    use alloc::sync::Arc;

    use rskrb5_ng::{
        ccache::{
            in_memory::MemoryStore,
            stores::{CacheCollection, CacheHandle, CredentialStore},
        },
        error::{Ccache as CacheError, Extensions as ExtensionError},
        extensions::{Extension, Registry, StoreProvider},
    };

    /// A provider whose cache type claims `prefix`.
    #[derive(Debug)]
    struct Claim {
        /// The claimed prefix.
        prefix: &'static str,
        /// Where its caches would live.
        caches: MemoryStore,
    }

    impl CredentialStore for Claim {
        fn cache_type(&self) -> &'static str {
            self.prefix
        }

        fn resolve(&self, residual: &str) -> Result<Box<dyn CacheHandle>, CacheError> {
            self.caches.resolve(residual)
        }

        fn collection(&self, residual: &str) -> Result<Box<dyn CacheCollection>, CacheError> {
            self.caches.collection(residual)
        }
    }

    impl StoreProvider for Claim {
        fn id(&self) -> &'static str {
            "keyring-claim"
        }

        fn prefix(&self) -> &str {
            self.prefix
        }

        fn credential_store(&self) -> Option<&dyn CredentialStore> {
            Some(self)
        }
    }

    /// A claim of `KEYRING`, in any letter case, is refused as taken.
    #[test]
    fn providers_cannot_claim_the_keyring_prefix() -> Result<(), String> {
        for prefix in ["KEYRING", "keyring", "KeyRing"] {
            let mut registry = Registry::new();
            match registry.register(Extension::StoreProvider(Arc::new(Claim {
                prefix,
                caches: MemoryStore::new(),
            }))) {
                Err(ExtensionError::PrefixTaken {
                    prefix: taken,
                    id: _,
                }) if taken == prefix => {}
                other => return Err(format!("{prefix}: {other:?}")),
            }
        }
        Ok(())
    }
}
