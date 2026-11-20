//! The credential-store abstraction: stores, collections, cursors and caches
//! (MIT `krb5_cc_ops` and the `krb5_cccol_*` collection API).
//!
//! A [`CredentialStore`] is one cache type (`FILE`, `DIR`, `MEMORY`, and the
//! platform stores later todos add); it resolves a residual to a
//! [`CacheHandle`] and opens a [`CacheCollection`]. Handles and collections are
//! trait objects so that an application or a registry can hold any store.
//!
//! # Cancel safety
//!
//! The traits are synchronous: every method finishes or fails before it
//! returns. File-backed methods block on file locks held by other writers.

use alloc::vec;
use core::{
    fmt,
    sync::atomic::{AtomicU64, Ordering},
};
use std::path::PathBuf;

use zeroize::Zeroizing;

use super::{CCache, Credential, Error, Principal, file_store};
use crate::{config::LibDefaults, extensions};

/// A credential-cache format version, 1 to 4, written into new caches (MIT
/// `ccache_type`; `src/lib/krb5/krb/init_ctx.c:292-293`).
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CacheVersion(u8);

impl CacheVersion {
    /// Version 4, MIT's default (`DEFAULT_CCACHE_TYPE`).
    pub const V4: Self = Self(4);

    /// A version from its number.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidCacheType`] outside 1 to 4.
    #[inline]
    pub fn new(version: i32) -> Result<Self, Error> {
        u8::try_from(version)
            .ok()
            .filter(|number| (1..=4).contains(number))
            .map(Self)
            .ok_or(Error::InvalidCacheType(version))
    }

    /// The version `ccache_type` of `[libdefaults]` configures.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidCacheType`] when `ccache_type` is outside 1 to 4,
    /// where MIT would write a file no reader accepts.
    #[inline]
    pub fn from_libdefaults(defaults: &LibDefaults) -> Result<Self, Error> {
        Self::new(defaults.ccache_type)
    }

    /// The version number.
    #[must_use]
    #[inline]
    pub const fn get(self) -> u8 {
        self.0
    }
}

impl Default for CacheVersion {
    #[inline]
    fn default() -> Self {
        Self::V4
    }
}

/// A process-unique token for one store instance whose caches form their own
/// namespace, such as one [`super::in_memory::MemoryStore`] table.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct StoreInstance(u64);

impl StoreInstance {
    /// A token no other store instance of this process holds.
    #[must_use]
    #[inline]
    pub fn unique() -> Self {
        /// The next token.
        static NEXT: AtomicU64 = AtomicU64::new(0);
        Self(NEXT.fetch_add(1, Ordering::Relaxed))
    }
}

/// Which cache a handle denotes: its store namespace plus the cache within it,
/// whatever name the handle shows.
///
/// # Security
///
/// Moves and switches compare identities, never names, so a handle of
/// another store that shows a member's name is not that member.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct CacheIdentity(Identity);

/// The namespaces a cache can live in.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
enum Identity {
    /// A cache file; the file system is one namespace.
    File(PathBuf),
    /// The cache of a residual in one store instance.
    Instance(StoreInstance, String),
    /// A cache name in a namespace every store instance shares.
    Named(String),
}

impl CacheIdentity {
    /// A cache named `name` in a namespace that every instance of its store
    /// shares (a KCM daemon, a kernel keyring); the default of
    /// [`CacheHandle::identity`].
    #[must_use]
    #[inline]
    pub const fn named(name: String) -> Self {
        Self(Identity::Named(name))
    }

    /// The cache `residual` of the store instance `instance`.
    #[must_use]
    #[inline]
    pub fn in_instance<R>(instance: StoreInstance, residual: R) -> Self
    where
        R: Into<String>,
    {
        Self(Identity::Instance(instance, residual.into()))
    }

    /// The cache file at `path`.
    pub(crate) const fn file(path: PathBuf) -> Self {
        Self(Identity::File(path))
    }

    /// The residual of a cache of `instance`, `None` for any other cache.
    pub(crate) fn residual_in(&self, instance: StoreInstance) -> Option<&str> {
        match &self.0 {
            Identity::Instance(owner, residual) if *owner == instance => Some(residual),
            Identity::File(_) | Identity::Instance(..) | Identity::Named(_) => None,
        }
    }
}

/// One credential cache of a store (MIT `krb5_ccache`).
///
/// # Security
///
/// A cache holds tickets and session keys. Removed and replaced credentials
/// are dropped into their zeroizing owners; file-backed caches are written
/// owner-only and replaced atomically, and refuse symlinks and files others
/// may write.
pub trait CacheHandle: fmt::Debug + Send + Sync {
    /// The full name, `TYPE:residual` (MIT `krb5_cc_get_full_name`).
    fn name(&self) -> String;

    /// Which cache this is: handles of one cache have equal identities. The
    /// default is the name, right for stores whose names are process-wide;
    /// a store with separate instances returns
    /// [`CacheIdentity::in_instance`].
    #[inline]
    fn identity(&self) -> CacheIdentity {
        CacheIdentity::named(self.name())
    }

    /// The whole cache: default principal, credentials and configuration
    /// entries (MIT `krb5_cc_get_principal` and a credential cursor).
    ///
    /// # Errors
    ///
    /// [`Error::CacheNotFound`] when the cache does not exist or is not
    /// initialized; storage and parse errors.
    fn load(&self) -> Result<CCache, Error>;

    /// Empty the cache and set its default principal (MIT
    /// `krb5_cc_initialize`), in the store's output version.
    ///
    /// # Errors
    ///
    /// Storage and serialization errors.
    fn initialize(&self, principal: &Principal) -> Result<(), Error>;

    /// Replace the whole cache at once, in the store's output version.
    ///
    /// # Errors
    ///
    /// Storage and serialization errors.
    fn replace(&self, cache: &CCache) -> Result<(), Error>;

    /// Add a credential, replacing one with the same client and server (MIT
    /// `krb5_cc_store_cred`).
    ///
    /// # Errors
    ///
    /// [`Error::CacheNotFound`] for an uninitialized cache; storage errors.
    fn store(&self, credential: Credential) -> Result<(), Error>;

    /// Remove the credentials for `server` (MIT `krb5_cc_remove_cred`);
    /// configuration entries stay. Returns how many were removed.
    ///
    /// # Errors
    ///
    /// [`Error::CacheNotFound`] for an uninitialized cache; storage errors.
    fn remove(&self, server: &Principal) -> Result<usize, Error>;

    /// Destroy the cache (MIT `krb5_cc_destroy`).
    ///
    /// # Errors
    ///
    /// [`Error::CacheNotFound`] when it does not exist; storage errors.
    fn destroy(&self) -> Result<(), Error>;

    /// Set a configuration entry (MIT `krb5_cc_set_config`).
    ///
    /// # Errors
    ///
    /// The errors of [`Self::load`] and [`Self::store`].
    #[inline]
    fn set_config(
        &self,
        key: &str,
        principal: Option<&str>,
        value: Zeroizing<Vec<u8>>,
    ) -> Result<(), Error> {
        let client = self.load()?.default_principal().clone();
        self.store(Credential::config_entry(
            client,
            key,
            principal.map(str::to_owned),
            value,
        ))
    }

    /// A configuration entry (MIT `krb5_cc_get_config`).
    ///
    /// # Errors
    ///
    /// The errors of [`Self::load`].
    #[inline]
    fn get_config(
        &self,
        key: &str,
        principal: Option<&str>,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, Error> {
        Ok(self
            .load()?
            .config_entry_value(key, principal)
            .map(|value| Zeroizing::new(value.to_vec())))
    }
}

/// The caches of one collection, primary first (MIT `krb5_cccol_cursor`).
///
/// The cursor is a snapshot of the names taken when it was created.
pub struct CacheCursor(vec::IntoIter<Box<dyn CacheHandle>>);

impl CacheCursor {
    /// A cursor over `caches`, in that order.
    #[must_use]
    #[inline]
    pub fn new(caches: Vec<Box<dyn CacheHandle>>) -> Self {
        Self(caches.into_iter())
    }
}

impl Iterator for CacheCursor {
    type Item = Box<dyn CacheHandle>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        self.0.next()
    }
}

impl fmt::Debug for CacheCursor {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("CacheCursor")
            .field(&self.0.as_slice())
            .finish()
    }
}

/// A collection of caches with a primary one (MIT `DIR` collections, the
/// `MEMORY` table, and a single `FILE` cache).
pub trait CacheCollection: fmt::Debug + Send + Sync {
    /// The collection name, for example `DIR:/run/user/1000/krb5cc`.
    fn name(&self) -> String;

    /// The caches, primary first (MIT `krb5_cccol_cursor_new`).
    ///
    /// # Errors
    ///
    /// Storage errors and a malformed primary pointer.
    fn caches(&self) -> Result<CacheCursor, Error>;

    /// The primary cache (MIT `krb5_cc_resolve` of the collection name).
    ///
    /// # Errors
    ///
    /// Storage errors and a malformed primary pointer.
    fn primary(&self) -> Result<Box<dyn CacheHandle>, Error>;

    /// Make `cache` the primary cache (MIT `krb5_cc_switch`).
    ///
    /// # Errors
    ///
    /// [`Error::OutsideCollection`] when `cache` is not a member of this
    /// collection; storage errors.
    fn switch(&self, cache: &dyn CacheHandle) -> Result<(), Error>;

    /// A new, empty, uninitialized cache with a unique name (MIT
    /// `krb5_cc_new_unique`).
    ///
    /// # Errors
    ///
    /// Storage errors.
    fn new_unique(&self) -> Result<Box<dyn CacheHandle>, Error>;

    /// The first cache whose default principal is `client` (MIT
    /// `krb5_cc_cache_match`, `src/lib/krb5/ccache/cccursor.c:184-221`); caches
    /// that cannot be read are skipped, as MIT does.
    ///
    /// # Errors
    ///
    /// The errors of [`Self::caches`].
    #[inline]
    fn cache_match(&self, client: &Principal) -> Result<Option<Box<dyn CacheHandle>>, Error> {
        Ok(self.caches()?.find(|cache| {
            cache.load().is_ok_and(|loaded| {
                let principal = loaded.default_principal();
                principal.realm == client.realm && principal.components == client.components
            })
        }))
    }

    /// Whether any cache holds a default principal (MIT
    /// `krb5_cccol_have_content`, `cccursor.c:232-280`).
    ///
    /// # Errors
    ///
    /// The errors of [`Self::caches`].
    #[inline]
    fn has_content(&self) -> Result<bool, Error> {
        Ok(self.caches()?.any(|cache| cache.load().is_ok()))
    }
}

/// A credential-cache type (MIT `krb5_cc_ops`): it resolves residuals to
/// caches and opens collections.
pub trait CredentialStore: fmt::Debug + Send + Sync {
    /// The type prefix of its names, for example `DIR`.
    fn cache_type(&self) -> &'static str;

    /// The cache a residual names (MIT `krb5_cc_resolve`).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidCacheName`] for a residual this store does not accept;
    /// storage errors.
    fn resolve(&self, residual: &str) -> Result<Box<dyn CacheHandle>, Error>;

    /// The collection a residual names.
    ///
    /// # Errors
    ///
    /// The errors of [`Self::resolve`].
    fn collection(&self, residual: &str) -> Result<Box<dyn CacheCollection>, Error>;
}

/// The cache an already-expanded `name` names when a store serves it.
///
/// That is a provider installed with
/// [`crate::extensions::Registry::install_stores`] that claims its prefix, else
/// a built-in non-file type (`KCM`, `KEYRING`) through the arms of
/// [`super::file_store::resolve`]; `None` for a file name.
///
/// # Errors
///
/// The errors of the store's [`CredentialStore::resolve`].
pub(crate) fn store_cache(name: &str) -> Result<Option<Box<dyn CacheHandle>>, Error> {
    let Some((provider, residual)) = extensions::stores::installed(name) else {
        return file_store::non_file(name).transpose();
    };
    provider
        .credential_store()
        .map(|store| store.resolve(residual))
        .transpose()
}

/// Move the contents of `source` into `destination` and destroy `source`
/// (MIT `krb5_cc_move`, `src/lib/krb5/ccache/ccbase.c:426-456`).
///
/// Moving a cache onto itself (an equal [`CacheHandle::identity`], whatever
/// the names) changes nothing, where MIT would destroy it.
///
/// # Errors
///
/// The errors of [`CacheHandle::load`], [`CacheHandle::replace`] and
/// [`CacheHandle::destroy`]; `source` is kept when the copy fails.
#[inline]
pub fn move_cache(source: &dyn CacheHandle, destination: &dyn CacheHandle) -> Result<(), Error> {
    if source.identity() == destination.identity() {
        return Ok(());
    }
    destination.replace(&source.load()?)?;
    source.destroy()
}
