//! The `KCM` cache type: credential caches kept by a Kerberos Credential
//! Manager daemon (Heimdal `kcm`, SSSD's `sssd_kcm`, macOS) over a Unix
//! socket (MIT 1.22.2 `src/lib/krb5/ccache/cc_kcm.c`; MIT-ccache-4).
//!
//! Names are `KCM:` (the daemon's primary cache), `KCM:<uid>` and
//! `KCM:<uid>:<name>`: the text after `KCM:` goes to the daemon unchanged,
//! which decides what it accepts (`src/doc/basic/ccache_def.rst`, "KCM").
//! The socket is `kcm_socket` of `[libdefaults]`
//! ([`Store::from_libdefaults`]); the built-in name dispatch of
//! [`file_store::resolve`](super::file_store::resolve) uses the default socket
//! [`wire::DEFAULT_SOCKET_PATH`]. [`wire`] holds the protocol without any I/O,
//! [`client`] a blocking client over any stream and, with the `tokio`
//! feature, `async_client` one for Tokio.
//!
//! The macOS Mach transport is not part of this module. On targets without
//! Unix sockets, [`Store`] reports
//! [`error::Ccache::UnsupportedPlatform`](crate::error::Ccache::UnsupportedPlatform).
//!
//! # Security
//!
//! The daemon socket must be a socket owned by root, by this process's
//! effective user or by a user named in [`socket::Trust`], never a symbolic
//! link; the Tokio client also checks the peer's user id. Replies are capped
//! at [`wire::MAX_REPLY_SIZE`] before any allocation, every call has a
//! deadline, and keys and tickets live in zeroizing buffers. A mutating
//! request whose reply is lost reports
//! [`error::Kcm::OutcomeUnknown`](crate::error::Kcm::OutcomeUnknown).
//! `store` and `remove` read the cache and write it back (`REPLACE`, or
//! `INITIALIZE` and `STORE` for a daemon without it, as MIT does), so two
//! writers can overwrite each other's changes.
//!
//! # Cancel safety
//!
//! The [`CredentialStore`] methods are synchronous. The Tokio client's calls
//! are cancel safe: a call dropped before it finishes leaves the connection
//! refusing further calls.

use alloc::sync::Arc;
use core::time::Duration;
use std::path::{Path, PathBuf};

use self::{
    cache::KcmCache,
    collection::KcmCollection,
    session::{Endpoint, Session},
    socket::Trust,
    wire::{Residual, calls},
};
use super::{
    Error,
    stores::{CacheCollection, CacheHandle, CredentialStore},
};
use crate::{config::LibDefaults, error::Kcm};

mod cache;
pub mod client;
mod collection;
mod session;
pub mod socket;
pub mod wire;

/// How long one request may take, from sending it to its whole reply.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// The `KCM` cache type, reaching the daemon at one socket path.
///
/// Handles and collections of one store share one connection, opened on
/// first use, and reconnect once when the daemon closed it while idle.
#[derive(Clone, Debug)]
pub struct Store {
    /// The shared connection.
    session: Arc<Session>,
}

impl Store {
    /// A store for the daemon at `socket`.
    #[must_use]
    #[inline]
    pub fn new<P>(socket: P) -> Self
    where
        P: Into<PathBuf>,
    {
        Self::with_endpoint(Endpoint::new(socket.into(), DEFAULT_TIMEOUT))
    }

    /// A store for the socket `kcm_socket` of `[libdefaults]` names (MIT
    /// `cc_kcm.c:306-316`).
    ///
    /// # Errors
    ///
    /// [`Kcm::NoServer`] when `kcm_socket` is `-` (Unix socket transport
    /// disabled) or empty.
    #[inline]
    pub fn from_libdefaults(defaults: &LibDefaults) -> Result<Self, Kcm> {
        match defaults.kcm_socket.as_str() {
            "-" | "" => Err(Kcm::NoServer),
            path => Ok(Self::new(path)),
        }
    }

    /// The same store with another per-request time limit.
    #[must_use]
    #[inline]
    pub fn with_timeout(self, timeout: Duration) -> Self {
        Self::with_endpoint(self.session.endpoint().clone().with_timeout(timeout))
    }

    /// The same store trusting `trust` as owners of the socket.
    #[must_use]
    #[inline]
    pub fn with_trust(self, trust: Trust) -> Self {
        Self::with_endpoint(self.session.endpoint().clone().with_trust(trust))
    }

    /// The socket path.
    #[must_use]
    #[inline]
    pub fn socket(&self) -> &Path {
        self.session.endpoint().path()
    }

    /// A store reaching the daemon as `endpoint` says.
    fn with_endpoint(endpoint: Endpoint) -> Self {
        Self {
            session: Arc::new(Session::new(endpoint)),
        }
    }
}

impl Default for Store {
    #[inline]
    fn default() -> Self {
        Self::new(wire::DEFAULT_SOCKET_PATH)
    }
}

impl CredentialStore for Store {
    #[inline]
    fn cache_type(&self) -> &'static str {
        "KCM"
    }

    /// An empty residual names the daemon's primary cache (`kcm_resolve`,
    /// `cc_kcm.c:741-770`); the daemon is contacted only for that.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidCacheName`] for a residual with a NUL byte or over
    /// [`wire::MAX_NAME_LENGTH`] bytes, and [`Error::Kcm`] for a failed
    /// request.
    #[inline]
    fn resolve(&self, residual: &str) -> Result<Box<dyn CacheHandle>, Error> {
        let name = if residual.is_empty() {
            self.session
                .call(&calls::get_default_cache())
                .map_err(Error::Kcm)?
        } else {
            Residual::new(residual).ok_or(Error::InvalidCacheName)?
        };
        Ok(Box::new(KcmCache::new(Arc::clone(&self.session), name)))
    }

    /// An empty residual names every cache the daemon shows this user.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidCacheName`] for a residual with a NUL byte or over
    /// [`wire::MAX_NAME_LENGTH`] bytes.
    #[inline]
    fn collection(&self, residual: &str) -> Result<Box<dyn CacheCollection>, Error> {
        let only = if residual.is_empty() {
            None
        } else {
            Some(Residual::new(residual).ok_or(Error::InvalidCacheName)?)
        };
        Ok(Box::new(KcmCollection::new(
            Arc::clone(&self.session),
            only,
        )))
    }
}

/// The cache a built-in `KCM:` name names, through the default socket: the
/// `KCM` arm of [`file_store::resolve`](super::file_store::resolve).
///
/// # Errors
///
/// The errors of [`CredentialStore::resolve`].
#[inline]
pub fn resolve(residual: &str) -> Result<Box<dyn CacheHandle>, Error> {
    Store::default().resolve(residual)
}

/// The collection a built-in `KCM:` name names, through the default socket:
/// the `KCM` arm of [`file_store::collection`](super::file_store::collection).
///
/// # Errors
///
/// The errors of [`CredentialStore::collection`].
#[inline]
pub fn collection(residual: &str) -> Result<Box<dyn CacheCollection>, Error> {
    Store::default().collection(residual)
}
