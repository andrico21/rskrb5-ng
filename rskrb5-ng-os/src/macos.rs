//! The macOS stores.
//!
//! `API:` goes through Kerberos.framework CCAPI and `KCM:` over Mach RPC.
//! They are separate implementations with their own type,
//! errors and tests; neither falls back to the other.

use alloc::sync::Arc;

use rskrb5_ng::{
    ccache::{
        CCache, Credential, Principal,
        kcm::seam::{KcmTransport, TransportFactory},
        stores::{CacheCollection, CacheCursor, CacheHandle, CredentialStore},
    },
    error::{Ccache as Error, Kcm},
    extensions::StoreProvider,
};

use crate::{error::Platform, principal_text};

/// CCAPI bindings.
mod ccapi;
/// Mach RPC to a KCM service.
mod mach;
/// Tests against the real CCAPI and Mach services.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests;

/// The native macOS credential cache, `API:` (MIT 1.22.2
/// `src/lib/krb5/ccache/cc_api_macos.c`, krb5 commit 3bb429b1).
///
/// A residual names a CCAPI cache (on current macOS a UUID); an empty one
/// names the default cache.
///
/// # Security
///
/// The caches belong to the user's session and are shared with every
/// Kerberos client of that user, as they are for MIT.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub struct ApiStore;

impl ApiStore {
    /// The store.
    #[must_use]
    #[inline]
    pub const fn new() -> Self {
        Self
    }
}

/// Map a CCAPI failure for the cache `name`.
fn api_error(name: &str, error: Platform) -> Error {
    if error == ccapi::failure(ccapi::CACHE_NOT_FOUND) {
        Error::CacheNotFound {
            name: name.to_owned(),
        }
    } else {
        error.into()
    }
}

impl CredentialStore for ApiStore {
    #[inline]
    fn cache_type(&self) -> &'static str {
        "API"
    }

    /// An empty residual names the default cache (`api_macos_resolve`).
    #[inline]
    fn resolve(&self, residual: &str) -> Result<Box<dyn CacheHandle>, Error> {
        let name = if residual.is_empty() {
            ccapi::context()?.default_name()?
        } else {
            residual.to_owned()
        };
        Ok(Box::new(ApiCache(name)))
    }

    #[inline]
    fn collection(&self, _residual: &str) -> Result<Box<dyn CacheCollection>, Error> {
        Ok(Box::new(ApiCollection))
    }
}

/// The `API` provider: install it to reach `API:` names by name.
impl StoreProvider for ApiStore {
    #[inline]
    fn id(&self) -> &'static str {
        "API"
    }

    #[inline]
    fn prefix(&self) -> &'static str {
        "API"
    }

    #[inline]
    fn credential_store(&self) -> Option<&dyn CredentialStore> {
        Some(self)
    }
}

/// One CCAPI cache.
#[derive(Clone, Debug)]
struct ApiCache(String);

impl ApiCache {
    /// The open cache.
    /// # Errors
    /// Returns [`Error::CacheNotFound`] for a missing cache and CCAPI failures.
    fn open(&self) -> Result<ccapi::Cache, Error> {
        ccapi::context()?
            .open(&self.0)
            .map_err(|error| api_error(&self.name(), error))
    }
}

impl CacheHandle for ApiCache {
    fn name(&self) -> String {
        format!("API:{}", self.0)
    }

    fn load(&self) -> Result<CCache, Error> {
        let cache = self.open()?;
        let principal = cache
            .principal()
            .map_err(|error| api_error(&self.name(), error))?;
        let mut loaded = CCache::new(principal);
        let (credentials, _) = cache.credentials(|_| true)?;
        loaded.credentials_mut().extend(credentials);
        Ok(loaded)
    }

    /// `create_ccache` with the `API:`-prefixed name Apple's CCAPI requires
    /// (`api_macos_initialize`).
    fn initialize(&self, principal: &Principal) -> Result<(), Error> {
        let owner = principal_text::unparse(principal);
        ccapi::context()?.create(&self.name(), &owner).map(drop)?;
        Ok(())
    }

    fn replace(&self, cache: &CCache) -> Result<(), Error> {
        self.initialize(cache.default_principal())?;
        let open = self.open()?;
        for credential in cache.credentials() {
            open.store(credential)?;
        }
        Ok(())
    }

    fn store(&self, credential: Credential) -> Result<(), Error> {
        Ok(self.open()?.store(&credential)?)
    }

    /// Remove every ticket for `server` (`api_macos_remove_cred`).
    fn remove(&self, server: &Principal) -> Result<usize, Error> {
        let (_, removed) = self.open()?.credentials(|credential| {
            credential.server().realm != server.realm
                || credential.server().components != server.components
        })?;
        Ok(removed)
    }

    fn destroy(&self) -> Result<(), Error> {
        Ok(self.open()?.destroy()?)
    }
}

/// The CCAPI collection: every cache of the session.
#[derive(Clone, Copy, Debug)]
struct ApiCollection;

impl CacheCollection for ApiCollection {
    fn name(&self) -> String {
        "API:".to_owned()
    }

    fn caches(&self) -> Result<CacheCursor, Error> {
        let context = ccapi::context()?;
        let primary = context.default_name()?;
        let mut names = context.names()?;
        names.sort_by_key(|name| *name != primary);
        Ok(CacheCursor::new(
            names
                .into_iter()
                .map(|name| -> Box<dyn CacheHandle> { Box::new(ApiCache(name)) })
                .collect(),
        ))
    }

    fn primary(&self) -> Result<Box<dyn CacheHandle>, Error> {
        ApiStore.resolve("")
    }

    /// `set_default` (`api_macos_switch_to`).
    fn switch(&self, cache: &dyn CacheHandle) -> Result<(), Error> {
        let full = cache.name();
        let residual = full
            .strip_prefix("API:")
            .ok_or_else(|| Error::OutsideCollection {
                name: full.clone(),
                collection: self.name(),
            })?;
        Ok(ApiCache(residual.to_owned()).open()?.set_default()?)
    }

    /// `create_new_ccache` (`api_macos_gen_new`).
    fn new_unique(&self) -> Result<Box<dyn CacheHandle>, Error> {
        let name = ccapi::context()?.create_new()?.name()?;
        Ok(Box::new(ApiCache(name)))
    }
}

/// The factory of the Mach transport of the built-in `KCM:` store: the
/// service `kcm_mach_service` names becomes a [`mach::MachTransport`] (MIT
/// 1.22.2 `kcmio_mach_connect`, `src/lib/krb5/ccache/cc_kcm.c:189-215`).
///
/// [`crate::install_kcm_transport`] installs it. Creating a transport does
/// not contact the service: the lookup happens on each call, so a service
/// that starts later is reached.
///
/// # Security
///
/// Every call has its own reply port and a 30-second bound; replies are
/// checked as MIG checks them and bounded before they are parsed. The service
/// name is the configuration's: whoever can write `kcm_mach_service` chooses
/// which Mach service receives the credentials.
#[derive(Clone, Copy, Debug)]
pub(crate) struct MachFactory;

impl TransportFactory for MachFactory {
    fn transport(&self, service: &str) -> Result<Arc<dyn KcmTransport>, Kcm> {
        Ok(Arc::new(mach::MachTransport::new(service.to_owned())))
    }
}
