//! The `KCM` cache type on a platform without Unix domain sockets: every
//! operation reports a typed unsupported-store error that names the platform.

use super::{
    Error,
    stores::{CacheCollection, CacheHandle, CredentialStore},
};

/// The `KCM` cache type, unavailable on this platform.
#[derive(Clone, Copy, Debug, Default)]
#[non_exhaustive]
pub struct Store;

/// The platform this build targets, as far as a target without Unix sockets
/// is told apart.
#[cfg(windows)]
const PLATFORM: &str = "windows";
/// The platform this build targets, as far as a target without Unix sockets
/// is told apart.
#[cfg(not(windows))]
const PLATFORM: &str = "a target without Unix domain sockets";

/// The error of every operation.
const fn unsupported() -> Error {
    Error::UnsupportedPlatform {
        cache_type: "KCM",
        platform: PLATFORM,
    }
}

impl CredentialStore for Store {
    #[inline]
    fn cache_type(&self) -> &'static str {
        "KCM"
    }

    /// # Errors
    ///
    /// Always [`Error::UnsupportedPlatform`].
    #[inline]
    fn resolve(&self, _residual: &str) -> Result<Box<dyn CacheHandle>, Error> {
        Err(unsupported())
    }

    /// # Errors
    ///
    /// Always [`Error::UnsupportedPlatform`].
    #[inline]
    fn collection(&self, _residual: &str) -> Result<Box<dyn CacheCollection>, Error> {
        Err(unsupported())
    }
}

/// The cache a built-in `KCM:` name names.
///
/// # Errors
///
/// Always [`Error::UnsupportedPlatform`].
#[inline]
pub fn resolve(residual: &str) -> Result<Box<dyn CacheHandle>, Error> {
    Store.resolve(residual)
}

/// The collection a built-in `KCM:` name names.
///
/// # Errors
///
/// Always [`Error::UnsupportedPlatform`].
#[inline]
pub fn collection(residual: &str) -> Result<Box<dyn CacheCollection>, Error> {
    Store.collection(residual)
}
