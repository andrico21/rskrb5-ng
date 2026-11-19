//! The `MEMORY` cache type: named caches in process memory (MIT 1.22.2
//! `src/lib/krb5/ccache/cc_memory.c`).

use alloc::sync::Arc;
use core::fmt;
use std::{
    io,
    sync::{Mutex, MutexGuard, PoisonError},
};

use super::{
    CCache, Credential, Error, Principal,
    file_store::remove_server,
    stores::{
        CacheCollection, CacheCursor, CacheHandle, CacheIdentity, CredentialStore, StoreInstance,
    },
};

/// A table of named in-memory caches (MIT `MEMORY:`).
///
/// Clones share the table; separate stores never see each other's caches,
/// where MIT keeps one table per process. Credentials removed, replaced or
/// destroyed are dropped into their zeroizing owners. The primary cache is
/// the one [`CacheCollection::switch`] named last, else the first cache
/// resolved (MIT has no `switch_to` for `MEMORY` and takes the context's
/// default name).
///
/// # Security
///
/// The caches live only in this process's memory; nothing is written to disk.
#[derive(Clone)]
pub struct MemoryStore {
    /// The shared table.
    table: Arc<Mutex<Table>>,
    /// The identity of the table, shared by clones.
    instance: StoreInstance,
}

/// The caches of one [`MemoryStore`].
#[derive(Default)]
struct Table {
    /// Residual and cache, in creation order; `None` until initialized.
    caches: Vec<(String, Option<CCache>)>,
    /// The residual [`CacheCollection::switch`] named last.
    primary: Option<String>,
}

impl Default for MemoryStore {
    #[inline]
    fn default() -> Self {
        Self {
            table: Arc::default(),
            instance: StoreInstance::unique(),
        }
    }
}

impl MemoryStore {
    /// An empty store.
    #[must_use]
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    /// The table, also after a panic in another thread (the table holds no
    /// invariant a panic can break).
    fn lock(&self) -> MutexGuard<'_, Table> {
        self.table.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The handle of `residual`, which exists in the table.
    fn handle(&self, residual: &str) -> Box<dyn CacheHandle> {
        Box::new(MemoryCache {
            store: self.clone(),
            residual: residual.to_owned(),
        })
    }
}

impl fmt::Debug for MemoryStore {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let table = self.lock();
        f.debug_struct("MemoryStore")
            .field(
                "caches",
                &table
                    .caches
                    .iter()
                    .map(|(residual, _)| residual)
                    .collect::<Vec<_>>(),
            )
            .field("primary", &table.primary)
            .finish()
    }
}

impl CredentialStore for MemoryStore {
    #[inline]
    fn cache_type(&self) -> &'static str {
        "MEMORY"
    }

    /// The cache `residual`, created empty and uninitialized when absent (MIT
    /// `krb5_mcc_resolve`).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidCacheName`] for an empty residual.
    #[inline]
    fn resolve(&self, residual: &str) -> Result<Box<dyn CacheHandle>, Error> {
        if residual.is_empty() {
            return Err(Error::InvalidCacheName);
        }
        let mut table = self.lock();
        if !table.caches.iter().any(|(name, _)| name == residual) {
            table.caches.push((residual.to_owned(), None));
        }
        drop(table);
        Ok(self.handle(residual))
    }

    #[inline]
    fn collection(&self, _residual: &str) -> Result<Box<dyn CacheCollection>, Error> {
        Ok(Box::new(self.clone()))
    }
}

impl CacheCollection for MemoryStore {
    #[inline]
    fn name(&self) -> String {
        "MEMORY:".to_owned()
    }

    #[inline]
    fn caches(&self) -> Result<CacheCursor, Error> {
        let table = self.lock();
        let primary = table.primary.clone();
        let mut names: Vec<String> = table.caches.iter().map(|(name, _)| name.clone()).collect();
        drop(table);
        if let Some(first) = primary.and_then(|name| names.iter().position(|item| *item == name)) {
            let name = names.remove(first);
            names.insert(0, name);
        }
        Ok(CacheCursor::new(
            names.iter().map(|name| self.handle(name)).collect(),
        ))
    }

    #[inline]
    fn primary(&self) -> Result<Box<dyn CacheHandle>, Error> {
        let table = self.lock();
        let name = table
            .primary
            .clone()
            .or_else(|| table.caches.first().map(|(name, _)| name.clone()))
            .ok_or_else(|| Error::CacheNotFound {
                name: "MEMORY:".to_owned(),
            })?;
        drop(table);
        Ok(self.handle(&name))
    }

    /// Make a cache of this store primary; a cache of another store is
    /// outside, whatever its name.
    #[inline]
    fn switch(&self, cache: &dyn CacheHandle) -> Result<(), Error> {
        let identity = cache.identity();
        let mut table = self.lock();
        let Some(residual) = identity
            .residual_in(self.instance)
            .filter(|residual| table.caches.iter().any(|(item, _)| item == residual))
        else {
            drop(table);
            return Err(Error::OutsideCollection {
                name: cache.name(),
                collection: "MEMORY:".to_owned(),
            });
        };
        table.primary = Some(residual.to_owned());
        drop(table);
        Ok(())
    }

    #[inline]
    fn new_unique(&self) -> Result<Box<dyn CacheHandle>, Error> {
        loop {
            let mut random = [0_u8; 8];
            getrandom::fill(&mut random).map_err(io::Error::other)?;
            let residual = format!("{:016x}", u64::from_be_bytes(random));
            let mut table = self.lock();
            if !table.caches.iter().any(|(name, _)| *name == residual) {
                table.caches.push((residual.clone(), None));
                drop(table);
                return Ok(self.handle(&residual));
            }
        }
    }
}

/// One cache of a [`MemoryStore`].
#[derive(Debug)]
struct MemoryCache {
    /// The store holding it.
    store: MemoryStore,
    /// Its residual.
    residual: String,
}

impl MemoryCache {
    /// Run `change` on the initialized cache.
    ///
    /// # Errors
    ///
    /// [`Error::CacheNotFound`] for an uninitialized or destroyed cache.
    fn update<T>(&self, change: impl FnOnce(&mut CCache) -> T) -> Result<T, Error> {
        let mut table = self.store.lock();
        match table
            .caches
            .iter_mut()
            .find(|(name, _)| *name == self.residual)
        {
            Some((_, Some(cache))) => Ok(change(cache)),
            _ => Err(self.not_found()),
        }
    }

    /// Set the cache, creating its entry when it was destroyed.
    fn set(&self, cache: CCache) {
        let mut table = self.store.lock();
        match table
            .caches
            .iter_mut()
            .find(|(name, _)| *name == self.residual)
        {
            Some((_, slot)) => *slot = Some(cache),
            None => table.caches.push((self.residual.clone(), Some(cache))),
        }
    }

    /// The error of an uninitialized or destroyed cache.
    fn not_found(&self) -> Error {
        Error::CacheNotFound { name: self.name() }
    }
}

impl CacheHandle for MemoryCache {
    fn name(&self) -> String {
        format!("MEMORY:{}", self.residual)
    }

    fn identity(&self) -> CacheIdentity {
        CacheIdentity::in_instance(self.store.instance, self.residual.as_str())
    }

    fn load(&self) -> Result<CCache, Error> {
        self.update(|cache| cache.clone())
    }

    fn initialize(&self, principal: &Principal) -> Result<(), Error> {
        self.set(CCache::new(principal.clone()));
        Ok(())
    }

    fn replace(&self, cache: &CCache) -> Result<(), Error> {
        self.set(cache.clone());
        Ok(())
    }

    fn store(&self, credential: Credential) -> Result<(), Error> {
        self.update(|cache| drop(cache.upsert_credential(credential)))
    }

    fn remove(&self, server: &Principal) -> Result<usize, Error> {
        self.update(|cache| remove_server(cache, server))
    }

    fn destroy(&self) -> Result<(), Error> {
        let mut table = self.store.lock();
        let index = table
            .caches
            .iter()
            .position(|(name, cache)| *name == self.residual && cache.is_some())
            .ok_or_else(|| self.not_found())?;
        drop(table.caches.remove(index));
        if table.primary.as_deref() == Some(self.residual.as_str()) {
            table.primary = None;
        }
        drop(table);
        Ok(())
    }
}
