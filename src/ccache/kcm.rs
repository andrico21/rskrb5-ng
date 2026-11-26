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
//! [`wire::DEFAULT_SOCKET_PATH`], or the process-wide
//! [`seam::KcmTransport`] an application installed with
//! [`seam::install_transport`] (how macOS reaches its Mach service). The
//! configured routes
//! ([`file_store::resolve_configured`](super::file_store::resolve_configured)
//! and [`configured`](super::configured)) build the store from the
//! configuration they are given: its `kcm_socket`, and its
//! `kcm_mach_service` through the [`seam::TransportFactory`] an application
//! installed with [`seam::install_transport_factory`].
//! [`wire`] holds the protocol without any I/O, [`client`] a blocking client
//! over any stream and, with the `tokio` feature, [`async_client`] one for
//! Tokio.
//!
//! The macOS Mach transport is not part of this module (the companion crate
//! `rskrb5-ng-os` supplies the factory). On targets without
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
    session::{Endpoint, Route, Session},
    socket::Trust,
    wire::{DEFAULT_MACH_SERVICE, Residual, calls},
};
use super::{
    Error,
    stores::{CacheCollection, CacheHandle, CredentialStore},
};
use crate::{config::LibDefaults, error::Kcm};

#[cfg(feature = "tokio")]
pub mod async_client;
mod cache;
pub mod client;
mod collection;
pub mod seam;
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
        Self::with_endpoint(
            Endpoint::new(socket.into(), DEFAULT_TIMEOUT),
            Route::socket_only(),
        )
    }

    /// A store for the daemon `[libdefaults]` names: `kcm_socket` (MIT
    /// `cc_kcm.c:306-316`) and `kcm_mach_service` (`cc_kcm.c:189-215`).
    ///
    /// Requests go to, in order: the transport installed with
    /// [`seam::install_transport`], the transport the installed
    /// [`seam::TransportFactory`] makes for `kcm_mach_service` (when it is
    /// neither `-` nor empty), and the socket `kcm_socket` names (unless it
    /// is `-` or empty). A Mach transport that finds no service hands the
    /// request to the socket, as MIT does; a socket disabled with `-` is
    /// never replaced by the default socket.
    ///
    /// # Errors
    ///
    /// [`Kcm::NoMachTransport`] when `kcm_mach_service` names a service other
    /// than MIT's default and the process has neither a transport nor a
    /// factory: the setting cannot be honoured, and the socket does not stand
    /// in for a service the configuration asked for (the default service is
    /// MIT's own and falls back to the socket where Mach does not exist).
    /// [`Kcm::NoServer`] when the socket is disabled and nothing else can
    /// serve. The errors of the factory.
    #[inline]
    pub fn from_libdefaults(defaults: &LibDefaults) -> Result<Self, Kcm> {
        let socket = match defaults.kcm_socket.as_str() {
            "-" | "" => None,
            path => Some(path),
        };
        let mach = match (defaults.kcm_mach_service.as_str(), seam::factory()) {
            ("-" | "", _) => None,
            (_, _) if seam::installed().is_some() => None,
            (service, Some(factory)) => Some(factory.transport(service)?),
            (service, None) if service == DEFAULT_MACH_SERVICE => None,
            (service, None) => {
                return Err(Kcm::NoMachTransport {
                    service: service.to_owned(),
                });
            }
        };
        let route = Route::configured(mach);
        if socket.is_none() && !route.has_transport() {
            return Err(Kcm::NoServer);
        }
        let endpoint = socket.map_or_else(
            || Endpoint::disabled(DEFAULT_TIMEOUT),
            |path| Endpoint::new(path.into(), DEFAULT_TIMEOUT),
        );
        Ok(Self::with_endpoint(endpoint, route))
    }

    /// The same store with another per-request time limit.
    #[must_use]
    #[inline]
    pub fn with_timeout(self, timeout: Duration) -> Self {
        let endpoint = self.session.endpoint().clone().with_timeout(timeout);
        Self::with_endpoint(endpoint, self.session.route().clone())
    }

    /// The same store trusting `trust` as owners of the socket.
    #[must_use]
    #[inline]
    pub fn with_trust(self, trust: Trust) -> Self {
        let endpoint = self.session.endpoint().clone().with_trust(trust);
        Self::with_endpoint(endpoint, self.session.route().clone())
    }

    /// The socket path, `None` when `kcm_socket` disabled the socket.
    #[must_use]
    #[inline]
    pub fn socket(&self) -> Option<&Path> {
        self.session.endpoint().path()
    }

    /// A store reaching the daemon as `endpoint` and `route` say.
    fn with_endpoint(endpoint: Endpoint, route: Route) -> Self {
        Self {
            session: Arc::new(Session::new(endpoint, route)),
        }
    }
}

/// The built-in store: the default socket [`wire::DEFAULT_SOCKET_PATH`], or
/// the transport [`seam::install_transport`] installed.
impl Default for Store {
    #[inline]
    fn default() -> Self {
        Self::with_endpoint(
            Endpoint::new(wire::DEFAULT_SOCKET_PATH.into(), DEFAULT_TIMEOUT),
            Route::built_in(),
        )
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

/// The cache a built-in `KCM:` name names, through the default socket or the
/// installed transport: the `KCM` arm of
/// [`file_store::resolve`](super::file_store::resolve).
///
/// # Errors
///
/// The errors of [`CredentialStore::resolve`].
#[inline]
pub fn resolve(residual: &str) -> Result<Box<dyn CacheHandle>, Error> {
    Store::default().resolve(residual)
}

/// The collection a built-in `KCM:` name names, through the default socket or
/// the installed transport: the `KCM` arm of
/// [`file_store::collection`](super::file_store::collection).
///
/// # Errors
///
/// The errors of [`CredentialStore::collection`].
#[inline]
pub fn collection(residual: &str) -> Result<Box<dyn CacheCollection>, Error> {
    Store::default().collection(residual)
}

/// The cache a built-in `KCM:` name names, through the daemon `defaults` name:
/// the `KCM` arm of
/// [`file_store::resolve_configured`](super::file_store::resolve_configured).
///
/// # Errors
///
/// The errors of [`Store::from_libdefaults`] and of
/// [`CredentialStore::resolve`].
#[inline]
pub fn resolve_configured(
    defaults: &LibDefaults,
    residual: &str,
) -> Result<Box<dyn CacheHandle>, Error> {
    Store::from_libdefaults(defaults)
        .map_err(Error::Kcm)?
        .resolve(residual)
}

/// The collection a built-in `KCM:` name names, through the daemon
/// `defaults` name: the `KCM` arm of
/// [`file_store::collection_configured`](super::file_store::collection_configured).
///
/// # Errors
///
/// The errors of [`Store::from_libdefaults`] and of
/// [`CredentialStore::collection`].
#[inline]
pub fn collection_configured(
    defaults: &LibDefaults,
    residual: &str,
) -> Result<Box<dyn CacheCollection>, Error> {
    Store::from_libdefaults(defaults)
        .map_err(Error::Kcm)?
        .collection(residual)
}
