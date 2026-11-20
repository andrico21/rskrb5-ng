//! One cache keyring as a [`CacheHandle`] (`cc_keyring.c:652-1530`).

use super::{
    Fault, KernelError,
    backend::{Kind, Ring, Serial},
    engine::Engine,
    listing::{expire_with_credentials, list},
    payload::{credential_bytes, parse_principal, principal_bytes, seconds_until},
    residual::{Anchor, PRINCIPAL_KEY, Residual, TIME_OFFSETS_KEY, unparse},
};
use crate::ccache::{
    CCache, Credential, Error, HEADER_FIELD_TAG_KDC_OFFSET, HeaderField, Principal,
    is_config_credential, stores::CacheHandle,
};

/// A cache of a collection, resolved by name at every call.
#[derive(Clone, Debug)]
pub(super) struct Handle {
    /// The cache logic.
    engine: Engine,
    /// The residual of the collection.
    residual: Residual,
    /// The collection keyring.
    collection: Serial,
    /// The cache name within the collection.
    subsidiary: String,
}

impl Handle {
    /// A handle of the cache `subsidiary` in `collection`.
    pub(super) const fn new(
        engine: Engine,
        residual: Residual,
        collection: Serial,
        subsidiary: String,
    ) -> Self {
        Self {
            engine,
            residual,
            collection,
            subsidiary,
        }
    }

    /// The keyring of this cache, when it exists.
    ///
    /// # Errors
    ///
    /// Kernel errors other than a missing keyring.
    pub(super) fn cache_ring(&self) -> Result<Option<Serial>, Error> {
        self.engine.lookup(
            Ring::Key(self.collection),
            Kind::Keyring,
            &self.subsidiary,
            None,
        )
    }

    /// The keyring of this cache, which must exist.
    ///
    /// # Errors
    ///
    /// [`Error::CacheNotFound`] for an uninitialized cache and kernel errors.
    fn existing(&self) -> Result<Serial, Error> {
        self.cache_ring()?
            .ok_or_else(|| Error::CacheNotFound { name: self.name() })
    }

    /// Whether this is the cache old code finds in the session keyring.
    fn is_legacy(&self) -> bool {
        self.residual.is_legacy_cache(&self.subsidiary)
    }

    /// Add a credential key and set its expiry (`krcc_store`, `add_cred_key`).
    /// Credentials of other than the legacy cache go into `big_key` keys when
    /// the kernel has them.
    ///
    /// # Errors
    ///
    /// Serialization and kernel errors.
    fn put(&self, cache: Serial, credential: &Credential) -> Result<(), Error> {
        let payload = credential_bytes(credential)?;
        let description = unparse(&credential.server);
        let backend = self.engine.backend();
        let ring = Ring::Key(cache);
        let preferred = if self.residual.anchor == Anchor::Legacy {
            Kind::User
        } else {
            Kind::BigKey
        };
        let key = match backend.add(ring, preferred, &description, &payload) {
            Err(KernelError::InvalidArgument | KernelError::NoDevice)
                if preferred == Kind::BigKey =>
            {
                backend.add(ring, Kind::User, &description, &payload)
            }
            other => other,
        };
        let added = Engine::call("add_key", key)?;
        if let Some(seconds) = seconds_until(credential.times.end_time) {
            Engine::call(
                "keyctl_set_timeout",
                backend.set_timeout(Ring::Key(added), seconds),
            )?;
        }
        Ok(())
    }

    /// Save the default principal key (MIT `save_principal`).
    ///
    /// # Errors
    ///
    /// Serialization and kernel errors.
    fn put_principal(&self, cache: Serial, principal: &Principal) -> Result<(), Error> {
        let payload = principal_bytes(principal)?;
        Engine::call(
            "add_key",
            self.engine
                .backend()
                .add(Ring::Key(cache), Kind::User, PRINCIPAL_KEY, &payload),
        )
        .map(drop)
    }
}

impl CacheHandle for Handle {
    fn name(&self) -> String {
        format!("KEYRING:{}", self.residual.cache_name(&self.subsidiary))
    }

    fn load(&self) -> Result<CCache, Error> {
        let cache = self.existing()?;
        let listing = list(&self.engine, cache)?;
        let Some(principal) = listing.principal else {
            return Err(Error::CacheNotFound { name: self.name() });
        };
        let payload = Engine::call(
            "keyctl_read",
            self.engine.backend().read(Ring::Key(principal)),
        )?;
        let mut loaded = CCache::new(parse_principal(&payload)?);
        loaded.credentials_mut().extend(
            listing
                .credentials
                .into_iter()
                .map(|(_, credential)| credential),
        );
        if let Some(offsets) = listing.offsets {
            let stored = Engine::call(
                "keyctl_read",
                self.engine.backend().read(Ring::Key(offsets)),
            )?;
            if let Some(value) = stored.get(..8) {
                loaded.header_mut().fields.push(HeaderField::new(
                    HEADER_FIELD_TAG_KDC_OFFSET,
                    value.to_vec(),
                )?);
            }
        }
        Ok(loaded)
    }

    fn initialize(&self, principal: &Principal) -> Result<(), Error> {
        let backend = self.engine.backend();
        let cache = match self.cache_ring()? {
            Some(cache) => {
                Engine::call("keyctl_clear", backend.clear(Ring::Key(cache)))?;
                cache
            }
            None => {
                self.engine
                    .find_or_create(Ring::Key(self.collection), None, &self.subsidiary)?
            }
        };
        if self.is_legacy() {
            // Old code looks for this cache in the session keyring
            // (`cc_keyring.c:350-353`).
            Engine::call(
                "keyctl_link",
                backend.link(Ring::Key(cache), self.engine.session_anchor()),
            )?;
        }
        self.put_principal(cache, principal)
    }

    fn replace(&self, cache: &CCache) -> Result<(), Error> {
        self.initialize(cache.default_principal())?;
        let ring = self.existing()?;
        for credential in cache.credentials() {
            self.put(ring, credential)?;
        }
        if !self.is_legacy()
            && let Some(offset) = cache
                .header()
                .fields
                .iter()
                .find(|field| field.tag == HEADER_FIELD_TAG_KDC_OFFSET)
        {
            Engine::call(
                "add_key",
                self.engine.backend().add(
                    Ring::Key(ring),
                    Kind::User,
                    TIME_OFFSETS_KEY,
                    &offset.value,
                ),
            )
            .map(drop)?;
        }
        expire_with_credentials(&self.engine, ring)
    }

    fn store(&self, credential: Credential) -> Result<(), Error> {
        let cache = self.existing()?;
        self.put(cache, &credential)?;
        expire_with_credentials(&self.engine, cache)
    }

    fn remove(&self, server: &Principal) -> Result<usize, Error> {
        let cache = self.existing()?;
        let mut removed = 0_usize;
        for (key, credential) in list(&self.engine, cache)?.credentials {
            if !is_config_credential(&credential)
                && credential.server.realm == server.realm
                && credential.server.components == server.components
            {
                Engine::call(
                    "keyctl_unlink",
                    self.engine
                        .backend()
                        .unlink(Ring::Key(key), Ring::Key(cache)),
                )?;
                removed = removed.saturating_add(1);
            }
        }
        Ok(removed)
    }

    fn destroy(&self) -> Result<(), Error> {
        let cache = self.existing()?;
        let backend = self.engine.backend();
        Engine::call("keyctl_clear", backend.clear(Ring::Key(cache)))?;
        Engine::call(
            "keyctl_unlink",
            backend.unlink(Ring::Key(cache), Ring::Key(self.collection)),
        )?;
        if self.is_legacy() {
            // The link old code looks for; it is gone when another process
            // destroyed the cache first.
            match backend.unlink(Ring::Key(cache), self.engine.session_anchor()) {
                Err(KernelError::KeyNotFound) | Ok(()) => {}
                Err(error) => {
                    return Err(Fault::Kernel {
                        operation: "keyctl_unlink",
                        error,
                    }
                    .into());
                }
            }
        }
        Ok(())
    }
}
