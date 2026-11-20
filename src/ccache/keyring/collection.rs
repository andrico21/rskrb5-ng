//! A keyring collection as a [`CacheCollection`] (`cc_keyring.c:1085-1220`).

use std::io;

use super::{
    Fault,
    backend::{Kind, Ring, Serial},
    cache::Handle,
    engine::Engine,
    residual::{Residual, UNIQUE_PREFIX, parse_description},
};
use crate::ccache::{
    Error,
    stores::{CacheCollection, CacheCursor, CacheHandle},
};

/// How often a unique name is drawn before giving up (`cc_keyring.c:600`).
const UNIQUE_ATTEMPTS: usize = 100;
/// The characters of the random part of a unique name.
const NAME_ALPHABET: &[u8; 62] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
/// The length of the random part of a unique name.
const NAME_RANDOM_CHARS: usize = 8;

/// The caches of a collection keyring, primary first.
#[derive(Clone, Debug)]
pub(super) struct Collection {
    /// The cache logic.
    engine: Engine,
    /// The residual of the collection (no subsidiary).
    residual: Residual,
    /// The collection keyring.
    ring: Serial,
}

impl Collection {
    /// The collection of `residual`, held by the keyring `collection`.
    pub(super) const fn new(engine: Engine, residual: Residual, collection: Serial) -> Self {
        Self {
            engine,
            residual,
            ring: collection,
        }
    }

    /// A handle of the cache `subsidiary` of this collection.
    fn handle(&self, subsidiary: String) -> Handle {
        Handle::new(
            self.engine.clone(),
            self.residual.clone(),
            self.ring,
            subsidiary,
        )
    }

    /// The name a cache of this collection has, as [`Handle`] reports it.
    fn prefix(&self) -> String {
        format!(
            "KEYRING:{}:{}:",
            self.residual.anchor.name(),
            self.residual.collection
        )
    }
}

/// A random cache keyring name: the prefix and eight letters or digits
/// (`krb5int_random_string`).
///
/// # Errors
///
/// The error of the system random source.
fn unique_name() -> Result<String, Error> {
    let mut random = String::with_capacity(NAME_RANDOM_CHARS);
    while random.len() < NAME_RANDOM_CHARS {
        let mut bytes = [0_u8; 16];
        getrandom::fill(&mut bytes).map_err(io::Error::other)?;
        // 248 is the largest multiple of 62 below 256: reject the rest so
        // that every character is equally likely.
        let wanted = NAME_RANDOM_CHARS.saturating_sub(random.len());
        random.extend(
            bytes
                .iter()
                .filter(|byte| **byte < 248)
                .filter_map(|byte| {
                    NAME_ALPHABET
                        .get(usize::from(byte.checked_rem(62)?))
                        .map(|letter| char::from(*letter))
                })
                .take(wanted),
        );
    }
    Ok(format!("{UNIQUE_PREFIX}{random}"))
}

impl CacheCollection for Collection {
    fn name(&self) -> String {
        format!(
            "KEYRING:{}:{}",
            self.residual.anchor.name(),
            self.residual.collection
        )
    }

    /// The primary cache first, then the other cache keyrings of the
    /// collection (`krcc_ptcursor_next`); a key that is not a keyring is skipped.
    fn caches(&self) -> Result<CacheCursor, Error> {
        let primary = self.engine.primary_name(&self.residual, self.ring)?;
        let mut caches: Vec<Box<dyn CacheHandle>> = Vec::new();
        if self
            .engine
            .lookup(Ring::Key(self.ring), Kind::Keyring, &primary, None)?
            .is_some()
        {
            caches.push(Box::new(self.handle(primary.clone())));
        }
        for key in self.engine.children(self.ring)? {
            let Ok(description) = self.engine.backend().describe(Ring::Key(key)) else {
                continue;
            };
            if let Some(("keyring", name)) = parse_description(&description)
                && name != primary
            {
                caches.push(Box::new(self.handle(name.to_owned())));
            }
        }
        Ok(CacheCursor::new(caches))
    }

    fn primary(&self) -> Result<Box<dyn CacheHandle>, Error> {
        let primary = self.engine.primary_name(&self.residual, self.ring)?;
        Ok(Box::new(self.handle(primary)))
    }

    /// Make `cache` the primary cache of its collection (`krcc_switch_to`);
    /// a cache of another collection is refused.
    fn switch(&self, cache: &dyn CacheHandle) -> Result<(), Error> {
        let name = cache.name();
        let Some(subsidiary) = name
            .strip_prefix(&self.prefix())
            .filter(|subsidiary| !subsidiary.is_empty())
        else {
            return Err(Error::OutsideCollection {
                name,
                collection: self.name(),
            });
        };
        self.engine.set_primary(self.ring, subsidiary)
    }

    /// A new, empty keyring with a random name (`krcc_generate_new`). The name
    /// is reserved at once; the cache is uninitialized until it gets a
    /// principal.
    fn new_unique(&self) -> Result<Box<dyn CacheHandle>, Error> {
        for _ in 0..UNIQUE_ATTEMPTS {
            let name = unique_name()?;
            let ring = Ring::Key(self.ring);
            if self
                .engine
                .lookup(ring, Kind::Keyring, &name, None)?
                .is_some()
            {
                continue;
            }
            Engine::call(
                "add_key",
                self.engine.backend().add(ring, Kind::Keyring, &name, &[]),
            )
            .map(drop)?;
            return Ok(Box::new(self.handle(name)));
        }
        Err(Fault::NameExhausted.into())
    }
}

/// The collection of one named cache: `KEYRING:anchor:collection:subsidiary`.
#[derive(Clone, Debug)]
pub(super) struct Single {
    /// The cache.
    cache: Handle,
}

impl Single {
    /// The collection of `cache`.
    pub(super) const fn new(cache: Handle) -> Self {
        Self { cache }
    }
}

impl CacheCollection for Single {
    fn name(&self) -> String {
        self.cache.name()
    }

    fn caches(&self) -> Result<CacheCursor, Error> {
        let present = self.cache.cache_ring()?.is_some();
        Ok(CacheCursor::new(if present {
            vec![Box::new(self.cache.clone())]
        } else {
            Vec::new()
        }))
    }

    fn primary(&self) -> Result<Box<dyn CacheHandle>, Error> {
        Ok(Box::new(self.cache.clone()))
    }

    /// Switching to the one cache changes nothing; any other cache is refused.
    fn switch(&self, cache: &dyn CacheHandle) -> Result<(), Error> {
        if cache.name() == self.cache.name() {
            Ok(())
        } else {
            Err(Error::OutsideCollection {
                name: cache.name(),
                collection: self.name(),
            })
        }
    }

    /// MIT refuses a new cache beside a subsidiary default
    /// (`KRB5_DCC_CANNOT_CREATE`, `cc_keyring.c:944-951`).
    fn new_unique(&self) -> Result<Box<dyn CacheHandle>, Error> {
        Err(Fault::SubsidiaryCollection.into())
    }
}
