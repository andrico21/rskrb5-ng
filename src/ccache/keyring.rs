//! The `KEYRING` cache type: credentials in the Linux kernel key-management
//! facility (MIT 1.22.2 `src/lib/krb5/ccache/cc_keyring.c`).
//!
//! A residual is `anchor:collection:subsidiary`, `anchor:collection` or
//! `collection` (`cc_keyring.c:46-92`). The anchor, `process`, `thread`,
//! `session`, `user`, `persistent` or `legacy` (the default, the session
//! keyring), says where the collection keyring `_krb_<collection>` lives. A
//! collection links one keyring per cache plus the user key
//! `krb_ccache:primary` that names the primary cache; a cache keyring holds the
//! user key `__krb5_princ__` and one key per credential, in the version 4 file
//! encoding, so MIT tools read what this crate writes and the reverse.
//!
//! The leaf `ccache-keyring` on a Linux target compiles the kernel backend,
//! `keyutils-raw` (docs/dependency-admission.md). Without it [`Keyring`]
//! refuses every name with [`Error::UnsupportedCacheType`], as before.
//!
//! # Security
//!
//! The namespaces are the kernel's: the process and thread keyrings are seen
//! by that process or thread only, the session keyring by the processes of the
//! session, the user keyring by every process of the user (and so by every
//! process running as that user, which no application can prevent). The
//! persistent keyring of another user is refused by the kernel without
//! `CAP_SETUID`, and this crate never retries under another name. Credentials
//! are serialized and read through zeroizing buffers; the kernel keeps them in
//! its own memory (`big_key` payloads may swap encrypted to tmpfs).
//!
//! # Cancel safety
//!
//! Every method is synchronous and finishes or fails before it returns. A
//! cache is never replaced atomically, as in MIT: another process can read a
//! cache that [`CacheHandle::replace`] is writing.

use thiserror::Error as ThisError;

use super::{
    Error,
    stores::{CacheCollection, CacheHandle, CredentialStore},
};

/// The kernel calls behind a trait.
#[cfg(any(test, all(feature = "ccache-keyring", target_os = "linux")))]
mod backend;
/// One cache keyring as a [`CacheHandle`].
#[cfg(any(test, all(feature = "ccache-keyring", target_os = "linux")))]
mod cache;
/// A keyring collection as a [`CacheCollection`].
#[cfg(any(test, all(feature = "ccache-keyring", target_os = "linux")))]
mod collection;
/// Collection lookup and the primary name.
#[cfg(any(test, all(feature = "ccache-keyring", target_os = "linux")))]
mod engine;
/// The in-memory kernel of the unit tests.
#[cfg(test)]
mod fake;
/// The real kernel.
#[cfg(all(feature = "ccache-keyring", target_os = "linux"))]
mod kernel;
/// What a cache keyring holds.
#[cfg(any(test, all(feature = "ccache-keyring", target_os = "linux")))]
mod listing;
/// Key payloads and expiry.
#[cfg(any(test, all(feature = "ccache-keyring", target_os = "linux")))]
mod payload;
/// Residual names and key descriptions.
#[cfg(any(test, all(feature = "ccache-keyring", target_os = "linux")))]
mod residual;
/// Unit tests of the cache logic.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests;

/// How the kernel refused a call, as far as this crate acts on it.
///
/// The values are Linux `errno` numbers read through `libc`; see
/// `keyctl(2)`, `add_key(2)` and `keyrings(7)`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, ThisError)]
#[non_exhaustive]
pub enum KernelError {
    /// `ENOSYS`: the kernel has no key-management facility, or a sandbox
    /// filters the call.
    #[error("the kernel has no key-management facility (ENOSYS)")]
    Unavailable,
    /// `EOPNOTSUPP`: the kernel does not support the operation, for example
    /// the persistent keyring (Linux before 3.13 or without the option).
    #[error("the kernel does not support the operation (EOPNOTSUPP)")]
    NotSupported,
    /// `EPERM`: the caller may not do this, for example a sandbox that filters
    /// the key calls, or the persistent keyring of another user without
    /// `CAP_SETUID`.
    #[error("the operation is not permitted (EPERM)")]
    PermissionDenied,
    /// `EACCES`: the permission mask of the key or keyring denies the access.
    #[error("the key or keyring denies the access (EACCES)")]
    AccessDenied,
    /// `EDQUOT`: the key quota of the user would be exceeded
    /// (`/proc/sys/kernel/keys/maxkeys` and `maxbytes`).
    #[error("the key quota of the user is exceeded (EDQUOT)")]
    QuotaExceeded,
    /// `ENOKEY`: no such key or keyring.
    #[error("no such key or keyring (ENOKEY)")]
    KeyNotFound,
    /// `EKEYREVOKED`: the key or keyring was revoked.
    #[error("the key or keyring was revoked (EKEYREVOKED)")]
    KeyRevoked,
    /// `EKEYEXPIRED`: the key or keyring expired.
    #[error("the key or keyring expired (EKEYEXPIRED)")]
    KeyExpired,
    /// `EINVAL`: the kernel rejected an argument, for example a description
    /// longer than it accepts.
    #[error("the kernel rejected an argument (EINVAL)")]
    InvalidArgument,
    /// `ENODEV`: the key type is not compiled into the kernel (`big_key`).
    #[error("the key type is not available in this kernel (ENODEV)")]
    NoDevice,
    /// Any other `errno`.
    #[error("keyctl failed with errno {0}")]
    Other(i32),
}

/// A failure of the `KEYRING` cache type.
#[derive(Clone, Debug, Eq, PartialEq, ThisError)]
#[non_exhaustive]
pub enum Fault {
    /// The anchor is not `process`, `thread`, `session`, `user`, `persistent`
    /// or `legacy` (MIT `KRB5_KCC_INVALID_ANCHOR`).
    #[error("unknown KEYRING anchor {anchor:?}")]
    InvalidAnchor {
        /// The anchor as written.
        anchor: String,
    },
    /// The collection of a `persistent` residual is not a user id (MIT
    /// `KRB5_KCC_INVALID_UID`), or the kernel has no persistent keyring and
    /// the id is not the caller's.
    #[error("the persistent KEYRING collection is not a usable user id")]
    InvalidUid,
    /// The primary-name key of a collection has a version other than 1 (MIT
    /// `KRB5_KCC_UNKNOWN_VERSION`).
    #[error("unknown KEYRING collection version {version}")]
    UnknownCollectionVersion {
        /// The version found.
        version: i32,
    },
    /// The primary-name key of a collection is shorter than its own length
    /// field, or its name is empty, not UTF-8 or holds a NUL (MIT
    /// `KRB5_CC_END`).
    #[error("malformed KEYRING primary name")]
    MalformedPrimary,
    /// A credential or principal key holds bytes after its encoding.
    #[error("malformed KEYRING credential payload")]
    MalformedPayload,
    /// 100 random names were all taken (MIT `KRB5_CC_BADNAME`).
    #[error("no unique KEYRING cache name found")]
    NameExhausted,
    /// A new cache was asked of a residual that already names one (MIT
    /// `KRB5_DCC_CANNOT_CREATE`).
    #[error("cannot create a new KEYRING cache in a collection that names a subsidiary cache")]
    SubsidiaryCollection,
    /// A kernel call failed.
    #[error("{operation}: {error}")]
    Kernel {
        /// The call that failed.
        operation: &'static str,
        /// How it failed.
        error: KernelError,
    },
}

/// The `KEYRING` cache type (MIT `krb5_krcc_ops`).
///
/// Without the `ccache-keyring` leaf, or on a target other than Linux, every
/// method returns [`Error::UnsupportedCacheType`]. The format version of the
/// store configuration does not apply: MIT writes version 4 into the kernel
/// (`cc_keyring.c:1215`).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub struct Keyring;

impl Keyring {
    /// The store.
    #[must_use]
    #[inline]
    pub const fn new() -> Self {
        Self
    }
}

#[cfg(all(feature = "ccache-keyring", target_os = "linux"))]
impl CredentialStore for Keyring {
    #[inline]
    fn cache_type(&self) -> &'static str {
        "KEYRING"
    }

    #[inline]
    fn resolve(&self, residual: &str) -> Result<Box<dyn CacheHandle>, Error> {
        engine::Engine::kernel().resolve(residual)
    }

    #[inline]
    fn collection(&self, residual: &str) -> Result<Box<dyn CacheCollection>, Error> {
        engine::Engine::kernel().collection(residual)
    }
}

#[cfg(not(all(feature = "ccache-keyring", target_os = "linux")))]
impl CredentialStore for Keyring {
    #[inline]
    fn cache_type(&self) -> &'static str {
        "KEYRING"
    }

    #[inline]
    fn resolve(&self, _residual: &str) -> Result<Box<dyn CacheHandle>, Error> {
        Err(Error::UnsupportedCacheType {
            cache_type: "KEYRING".to_owned(),
        })
    }

    #[inline]
    fn collection(&self, _residual: &str) -> Result<Box<dyn CacheCollection>, Error> {
        Err(Error::UnsupportedCacheType {
            cache_type: "KEYRING".to_owned(),
        })
    }
}
