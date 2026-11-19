//! The `KCM` credential store over any message exchange.
//!
//! The cache, the collection and their operations follow MIT 1.22.2
//! `src/lib/krb5/ccache/cc_kcm.c`, one KCM request each. macOS runs it over Mach RPC
//! ([`crate::macos::KcmMachStore`]); the tests run it against an in-memory
//! KCM server.

use alloc::sync::Arc;
use core::fmt;

use rskrb5_ng::{
    ccache::{
        CCache, Credential, Principal,
        stores::{CacheCollection, CacheCursor, CacheHandle},
    },
    error::Ccache as Error,
};

use crate::{
    Secret,
    error::Platform,
    kcm_wire::{self, Opcode},
    marshal,
};

#[cfg(test)]
mod tests;

/// `KRB5_FCC_NOFILE`: the server has no such cache.
const NO_CACHE: i32 = -1_765_328_189;
/// `KRB5_CC_NOTFOUND`: no matching credential.
const NOT_FOUND: i32 = -1_765_328_243;

/// One request-reply round trip to a KCM server.
pub(crate) trait Exchange: fmt::Debug + Send + Sync {
    /// Send `request` and return the whole reply, status included.
    ///
    /// # Errors
    ///
    /// Transport failures.
    fn call(&self, request: &[u8]) -> Result<Secret, Platform>;
}

/// A KCM client over an exchange.
#[derive(Debug)]
pub(crate) struct Kcm<E>(Arc<E>);

impl<E> Clone for Kcm<E> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl<E: Exchange + 'static> Kcm<E> {
    /// A client over `exchange`.
    pub(crate) fn new(exchange: E) -> Self {
        Self(Arc::new(exchange))
    }

    /// One operation; a missing cache is [`Error::CacheNotFound`] for `name`.
    /// # Errors
    /// Returns transport failures and the server's status.
    fn rpc(&self, opcode: Opcode, name: Option<&str>, args: &[u8]) -> Result<Vec<u8>, Error> {
        let request = kcm_wire::request(opcode, name, args)?;
        let reply = self.0.call(&request)?;
        match kcm_wire::result(&reply) {
            Ok(result) => Ok(result.to_vec()),
            Err(Platform::Kcm { code: NO_CACHE }) => Err(Error::CacheNotFound {
                name: format!("KCM:{}", name.unwrap_or_default()),
            }),
            Err(other) => Err(other.into()),
        }
    }

    /// A cache name from a name-returning operation.
    /// # Errors
    /// Returns the errors of [`Self::rpc`] and a malformed name.
    fn name(&self, opcode: Opcode, args: &[u8]) -> Result<String, Error> {
        Ok(kcm_wire::name(&self.rpc(opcode, None, args)?)?)
    }

    /// The handle of `residual`; an empty residual names the primary cache
    /// (`kcm_resolve`, `cc_kcm.c:741-768`).
    /// # Errors
    /// Returns the errors of [`Self::rpc`] for the primary name.
    pub(crate) fn resolve(&self, residual: &str) -> Result<Box<dyn CacheHandle>, Error> {
        let name = if residual.is_empty() {
            self.name(Opcode::GetDefaultCache, &[])?
        } else {
            residual.to_owned()
        };
        Ok(Box::new(Cache {
            name,
            kcm: self.clone(),
        }))
    }

    /// The collection of the server.
    pub(crate) fn collection(&self) -> Box<dyn CacheCollection> {
        Box::new(Collection(self.clone()))
    }
}

/// One KCM cache.
#[derive(Debug)]
struct Cache<E> {
    /// The residual name.
    name: String,
    /// The client.
    kcm: Kcm<E>,
}

impl<E: Exchange + 'static> Cache<E> {
    /// A cache operation on this cache.
    /// # Errors
    /// Returns the errors of [`Kcm::rpc`].
    fn rpc(&self, opcode: Opcode, args: &[u8]) -> Result<Vec<u8>, Error> {
        self.kcm.rpc(opcode, Some(&self.name), args)
    }
}

impl<E: Exchange + 'static> CacheHandle for Cache<E> {
    fn name(&self) -> String {
        format!("KCM:{}", self.name)
    }

    /// The principal, then every credential by UUID (`kcm_get_princ`,
    /// `kcm_start_seq_get` without the MIT-only `GET_CRED_LIST`).
    fn load(&self) -> Result<CCache, Error> {
        let principal = self.rpc(Opcode::GetPrincipal, &[])?;
        if principal.is_empty() {
            return Err(Error::CacheNotFound { name: self.name() });
        }
        let mut cache = CCache::new(marshal::parse_principal(&principal)?);
        for uuid in kcm_wire::uuids(&self.rpc(Opcode::GetCredUuidList, &[])?)? {
            let credential = Secret::from(self.rpc(Opcode::GetCredByUuid, &uuid)?);
            cache
                .credentials_mut()
                .push(marshal::parse_credential(&credential)?);
        }
        Ok(cache)
    }

    fn initialize(&self, principal: &Principal) -> Result<(), Error> {
        self.rpc(Opcode::Initialize, &marshal::principal(principal)?)
            .map(drop)
    }

    /// `INITIALIZE` and one `STORE` per credential: MIT's non-atomic replace
    /// (`kcm_replace` falls back to it, `cc_kcm.c:1280-1314`).
    fn replace(&self, cache: &CCache) -> Result<(), Error> {
        self.initialize(cache.default_principal())?;
        for credential in cache.credentials() {
            self.store(credential.clone())?;
        }
        Ok(())
    }

    fn store(&self, credential: Credential) -> Result<(), Error> {
        self.rpc(Opcode::Store, &marshal::credential(&credential)?)
            .map(drop)
    }

    /// One `REMOVE_CRED` matching the server, after counting the matches.
    fn remove(&self, server: &Principal) -> Result<usize, Error> {
        let count = self
            .load()?
            .entries()
            .iter()
            .filter(|credential| {
                credential.server().realm == server.realm
                    && credential.server().components == server.components
            })
            .count();
        if count == 0 {
            return Ok(0);
        }
        let args = kcm_wire::remove_server_args(&marshal::principal(server)?);
        match self.rpc(Opcode::RemoveCred, &args) {
            Ok(_) => Ok(count),
            Err(Error::Io(error))
                if error
                    .get_ref()
                    .and_then(|inner| inner.downcast_ref::<Platform>())
                    == Some(&Platform::Kcm { code: NOT_FOUND }) =>
            {
                Ok(0)
            }
            Err(other) => Err(other),
        }
    }

    fn destroy(&self) -> Result<(), Error> {
        self.rpc(Opcode::Destroy, &[]).map(drop)
    }
}

/// The caches of a KCM server, primary first (`kcm_ptcursor_*`).
#[derive(Debug)]
struct Collection<E>(Kcm<E>);

impl<E: Exchange + 'static> CacheCollection for Collection<E> {
    fn name(&self) -> String {
        "KCM:".to_owned()
    }

    fn caches(&self) -> Result<CacheCursor, Error> {
        let primary = self.0.name(Opcode::GetDefaultCache, &[])?;
        let uuids = kcm_wire::uuids(&self.0.rpc(Opcode::GetCacheUuidList, None, &[])?)?;
        let mut names = vec![primary.clone()];
        for uuid in uuids {
            let name = self.0.name(Opcode::GetCacheByUuid, &uuid)?;
            if name != primary {
                names.push(name);
            }
        }
        let caches = names
            .into_iter()
            .map(|name| -> Box<dyn CacheHandle> {
                Box::new(Cache {
                    name,
                    kcm: self.0.clone(),
                })
            })
            .collect();
        Ok(CacheCursor::new(caches))
    }

    fn primary(&self) -> Result<Box<dyn CacheHandle>, Error> {
        self.0.resolve("")
    }

    /// `SET_DEFAULT_CACHE` (`kcm_switch_to`, `cc_kcm.c:1331-1340`).
    fn switch(&self, cache: &dyn CacheHandle) -> Result<(), Error> {
        let full = cache.name();
        let residual = full
            .strip_prefix("KCM:")
            .ok_or_else(|| Error::OutsideCollection {
                name: full.clone(),
                collection: self.name(),
            })?;
        self.0
            .rpc(Opcode::SetDefaultCache, Some(residual), &[])
            .map(drop)
    }

    /// `GEN_NEW` (`kcm_gen_new`, `cc_kcm.c:796-822`).
    fn new_unique(&self) -> Result<Box<dyn CacheHandle>, Error> {
        let name = self.0.name(Opcode::GenNew, &[])?;
        self.0.resolve(&name)
    }
}
