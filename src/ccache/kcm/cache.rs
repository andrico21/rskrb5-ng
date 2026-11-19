//! One KCM cache as a [`CacheHandle`] (the `kcm_*` operations of
//! `cc_kcm.c:741-1340`).

use alloc::sync::Arc;

use super::{
    session::Session,
    wire::{
        self, Residual,
        calls::{self, Call},
        shape::Shape,
    },
};
use crate::{
    ccache::{
        CCache, Credential, Error, HeaderField, Principal, file_store::remove_server,
        same_principal_identity, stores::CacheHandle,
    },
    error::Kcm,
};

/// The most credentials this client fetches one request at a time from a
/// daemon that cannot list them whole.
const MAX_ENTRIES: usize = 0x4000;
/// The tag of the KDC time offset field of a version 4 cache header.
const KDC_OFFSET_TAG: u16 = 1;

/// A cache the daemon knows by `residual`.
#[derive(Clone, Debug)]
pub(super) struct KcmCache {
    /// The connection.
    session: Arc<Session>,
    /// The daemon's name for the cache.
    residual: Residual,
}

impl KcmCache {
    /// A handle; the cache need not exist yet.
    pub(super) const fn new(session: Arc<Session>, residual: Residual) -> Self {
        Self { session, residual }
    }

    /// The error of an absent cache.
    fn not_found(&self) -> Error {
        Error::CacheNotFound { name: self.name() }
    }

    /// The error for a failed request about this cache: a status that says
    /// the cache does not exist is [`Error::CacheNotFound`].
    fn translate(&self, error: Kcm) -> Error {
        if wire::is_missing(&error) {
            self.not_found()
        } else {
            Error::Kcm(error)
        }
    }

    /// Send a call about this cache.
    ///
    /// # Errors
    ///
    /// [`Error::CacheNotFound`] and [`Error::Kcm`].
    fn call<S>(&self, call: &Call<S>) -> Result<S::Output, Error>
    where
        S: Shape,
    {
        self.session
            .call(call)
            .map_err(|error| self.translate(error))
    }

    /// The credentials: the whole list when the daemon offers it, else one
    /// request per UUID (`kcm_start_seq_get`, `cc_kcm.c:957-1005`).
    ///
    /// # Errors
    ///
    /// The errors of [`Self::call`] and [`Kcm::TooManyEntries`].
    fn credentials(&self) -> Result<Vec<Credential>, Error> {
        match self.session.call(&calls::get_cred_list(&self.residual)) {
            Err(error) if wire::is_unsupported(&error) => {
                let uuids = self.call(&calls::get_cred_uuid_list(&self.residual))?;
                if uuids.len() > MAX_ENTRIES {
                    return Err(Error::Kcm(Kcm::TooManyEntries { limit: MAX_ENTRIES }));
                }
                uuids
                    .into_iter()
                    .map(|uuid| self.call(&calls::get_cred_by_uuid(&self.residual, uuid)))
                    .collect()
            }
            other => other.map_err(|error| self.translate(error)),
        }
    }

    /// Replace the whole cache, atomically when the daemon can, else by
    /// initializing and storing (`k5_nonatomic_replace`, `cc_kcm.c:1309-1311`);
    /// initializing also creates a cache the daemon does not know yet.
    ///
    /// # Errors
    ///
    /// The errors of [`Self::call`].
    fn replace_all(&self, cache: &CCache) -> Result<(), Error> {
        match self.session.call(&calls::replace(&self.residual, cache)?) {
            Err(error) if wire::is_unsupported(&error) || wire::is_missing(&error) => {
                self.call(&calls::initialize(
                    &self.residual,
                    cache.default_principal(),
                )?)?;
                for credential in cache.credentials() {
                    self.call(&calls::store(&self.residual, credential)?)?;
                }
                Ok(())
            }
            other => other.map_err(|error| self.translate(error)),
        }
    }
}

impl CacheHandle for KcmCache {
    fn name(&self) -> String {
        format!("KCM:{}", self.residual.as_str())
    }

    fn load(&self) -> Result<CCache, Error> {
        let principal = self
            .call(&calls::get_principal(&self.residual))?
            .ok_or_else(|| self.not_found())?;
        let mut cache = CCache::new(principal);
        *cache.credentials_mut() = self.credentials()?;
        // A daemon that keeps no offset, or refuses the question, leaves the header empty.
        if let Ok(Some(offset)) = self.session.call(&calls::get_kdc_offset(&self.residual))
            && offset != 0_i32
        {
            let mut value = offset.to_be_bytes().to_vec();
            value.extend_from_slice(&0_i32.to_be_bytes());
            cache
                .header_mut()
                .fields
                .push(HeaderField::new(KDC_OFFSET_TAG, value)?);
        }
        Ok(cache)
    }

    fn initialize(&self, principal: &Principal) -> Result<(), Error> {
        self.call(&calls::initialize(&self.residual, principal)?)
    }

    fn replace(&self, cache: &CCache) -> Result<(), Error> {
        self.replace_all(cache)
    }

    fn store(&self, credential: Credential) -> Result<(), Error> {
        let mut cache = self.load()?;
        let replaces = cache.credentials().iter().any(|held| {
            same_principal_identity(held.client(), credential.client())
                && same_principal_identity(held.server(), credential.server())
        });
        if replaces {
            drop(cache.upsert_credential(credential));
            self.replace_all(&cache)
        } else {
            self.call(&calls::store(&self.residual, &credential)?)
        }
    }

    fn remove(&self, server: &Principal) -> Result<usize, Error> {
        let mut cache = self.load()?;
        let removed = remove_server(&mut cache, server);
        if removed > 0 {
            self.replace_all(&cache)?;
        }
        Ok(removed)
    }

    fn destroy(&self) -> Result<(), Error> {
        self.call(&calls::destroy(&self.residual))
    }
}
