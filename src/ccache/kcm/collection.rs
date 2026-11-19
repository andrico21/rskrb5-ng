//! The caches of a KCM daemon as a [`CacheCollection`] (`kcm_ptcursor_new`
//! and `kcm_ptcursor_next`, `cc_kcm.c:1139-1264`, and `kcm_switch_to`,
//! `cc_kcm.c:1331-1340`).

use alloc::sync::Arc;

use super::{
    cache::KcmCache,
    session::Session,
    wire::{self, Residual, calls},
};
use crate::{
    ccache::{
        Error,
        stores::{CacheCollection, CacheCursor, CacheHandle},
    },
    error::Kcm,
};

/// The most caches one collection lists.
const MAX_CACHES: usize = 0x4000;

/// The caches the daemon shows this user, or one named cache (`KCM:` and
/// `KCM:<uid>:<name>`).
#[derive(Clone, Debug)]
pub(super) struct KcmCollection {
    /// The connection.
    session: Arc<Session>,
    /// The one cache of a named collection; `None` for the daemon's whole
    /// collection.
    only: Option<Residual>,
}

impl KcmCollection {
    /// The collection of `only`, or of the whole daemon.
    pub(super) const fn new(session: Arc<Session>, only: Option<Residual>) -> Self {
        Self { session, only }
    }

    /// The handle of the cache the daemon names `residual`.
    fn cache(&self, residual: Residual) -> Box<dyn CacheHandle> {
        Box::new(KcmCache::new(Arc::clone(&self.session), residual))
    }

    /// Whether the cache holds a default principal (`name_exists`,
    /// `cc_kcm.c:1198-1208`).
    ///
    /// # Errors
    ///
    /// [`Error::Kcm`] for a failure other than the daemon's refusal.
    fn exists(&self, residual: &Residual) -> Result<bool, Error> {
        match self.session.call(&calls::get_principal(residual)) {
            Ok(principal) => Ok(principal.is_some()),
            Err(Kcm::Daemon { code: _, opcode: _ }) => Ok(false),
            Err(other) => Err(Error::Kcm(other)),
        }
    }

    /// The daemon's primary cache, or `None` when it names none.
    ///
    /// # Errors
    ///
    /// [`Error::Kcm`] for a failure other than the daemon's refusal.
    fn primary_name(&self) -> Result<Option<Residual>, Error> {
        match self.session.call(&calls::get_default_cache()) {
            Ok(name) => Ok(Some(name)),
            Err(Kcm::Daemon { code: _, opcode: _ }) => Ok(None),
            Err(other) => Err(Error::Kcm(other)),
        }
    }
}

impl CacheCollection for KcmCollection {
    fn name(&self) -> String {
        format!("KCM:{}", self.only.as_ref().map_or("", Residual::as_str))
    }

    fn caches(&self) -> Result<CacheCursor, Error> {
        if let Some(only) = &self.only {
            let present = self.exists(only)?;
            return Ok(CacheCursor::new(if present {
                vec![self.cache(only.clone())]
            } else {
                Vec::new()
            }));
        }
        let uuids = match self.session.call(&calls::get_cache_uuid_list()) {
            Ok(uuids) => uuids,
            Err(error) if wire::is_missing(&error) => {
                return Ok(CacheCursor::new(Vec::new()));
            }
            Err(other) => return Err(Error::Kcm(other)),
        };
        if uuids.len() > MAX_CACHES {
            return Err(Kcm::TooManyEntries { limit: MAX_CACHES }.into());
        }
        let primary = self.primary_name()?;
        let mut caches = Vec::new();
        if let Some(name) = &primary
            && self.exists(name)?
        {
            caches.push(self.cache(name.clone()));
        }
        for uuid in uuids {
            match self.session.call(&calls::get_cache_by_uuid(uuid)) {
                Ok(name) if primary.as_ref() != Some(&name) => caches.push(self.cache(name)),
                Ok(_primary) => {}
                Err(error) if wire::is_missing(&error) => {}
                Err(other) => return Err(Error::Kcm(other)),
            }
        }
        Ok(CacheCursor::new(caches))
    }

    fn primary(&self) -> Result<Box<dyn CacheHandle>, Error> {
        if let Some(only) = &self.only {
            return Ok(self.cache(only.clone()));
        }
        match self.session.call(&calls::get_default_cache()) {
            Ok(name) => Ok(self.cache(name)),
            Err(error) if wire::is_missing(&error) => {
                Err(Error::CacheNotFound { name: self.name() })
            }
            Err(other) => Err(Error::Kcm(other)),
        }
    }

    fn switch(&self, cache: &dyn CacheHandle) -> Result<(), Error> {
        let name = cache.name();
        let outside = || Error::OutsideCollection {
            name: name.clone(),
            collection: self.name(),
        };
        let residual = name
            .strip_prefix("KCM:")
            .and_then(Residual::new)
            .filter(|residual| self.only.as_ref().is_none_or(|only| only == residual))
            .ok_or_else(outside)?;
        self.session
            .call(&calls::set_default_cache(&residual))
            .map_err(Error::Kcm)
    }

    fn new_unique(&self) -> Result<Box<dyn CacheHandle>, Error> {
        let name = self.session.call(&calls::gen_new()).map_err(Error::Kcm)?;
        Ok(self.cache(name))
    }
}
