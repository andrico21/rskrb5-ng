//! The Windows LSA credential cache `MSLSA:` (MIT 1.22.2
//! `src/lib/krb5/ccache/cc_mslsa.c`).
//!
//! It is the Kerberos ticket cache of the caller's logon session. Reads list
//! the cache (`KerbQueryTicketCacheEx2Message`) and retrieve each ticket with
//! its session key from the cache only (`KerbRetrieveEncodedTicketMessage`
//! with `KERB_RETRIEVE_TICKET_USE_CACHE_ONLY`); MIT may ask a KDC there, this
//! store never does. A store submits a KRB-CRED (`KerbSubmitTicketMessage`),
//! a removal purges single tickets (`KerbPurgeTicketCacheExMessage`) and a
//! destroy purges the cache (`KerbPurgeTicketCacheMessage`).
//!
//! # Security
//!
//! Every change affects the whole logon session, every process of it
//! included, so a store refuses changes unless it was built with
//! `MslsaStore::with_mutation(true)`. When a submission fails, the store
//! does not ask the LSA to fetch the ticket from a KDC as MIT does.

use alloc::sync::Arc;
use core::fmt;

use rskrb5_ng::{
    ccache::{
        CCache, Credential, Principal,
        stores::{CacheCollection, CacheCursor, CacheHandle, CredentialStore},
    },
    error::Ccache as Error,
    extensions::StoreProvider,
    keytab::EncryptionKey,
    krb_cred,
};

use crate::{Secret, error::Platform, lsa_wire::CacheInfo};

/// The Local Security Authority calls of the Windows build.
#[cfg(windows)]
mod lsa;
/// The store against an in-memory LSA.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests;

/// The cache type.
const CACHE_TYPE: &str = "MSLSA";
/// `aes256-cts-hmac-sha1-96`: the enctype of submitted KRB-CREDs.
const SUBMIT_ETYPE: i32 = 18;
/// The key that encrypts submitted KRB-CREDs.
///
/// It travels next to the KRB-CRED in the same request (`KERB_SUBMIT_TKT_REQUEST.Key`), so it is no
/// secret and protects nothing; MIT likewise uses a fixed key
/// (`KerbSubmitTicket`, `cc_mslsa.c:758-779`, an RC4 `0xdeadbeef...` key).
const SUBMIT_KEY: [u8; 32] = *b"rskrb5-ng-os MSLSA KRB-CRED key.";
/// `KRB5_NT_PRINCIPAL`.
const NT_PRINCIPAL: i32 = 1;

/// The Kerberos package calls the store makes.
pub(crate) trait Lsa: fmt::Debug + Send + Sync {
    /// The tickets of the logon session.
    ///
    /// # Errors
    ///
    /// LSA failures.
    fn entries(&self) -> Result<Vec<CacheInfo>, Platform>;

    /// The cached ticket of `info` with its session key; `None` without a key.
    ///
    /// # Errors
    ///
    /// LSA failures.
    fn retrieve(&self, info: &CacheInfo) -> Result<Option<Credential>, Platform>;

    /// Submit a KRB-CRED whose `enc-part` `key` encrypts.
    ///
    /// # Errors
    ///
    /// LSA failures.
    fn submit(&self, krb_cred: &[u8], key: &EncryptionKey) -> Result<(), Platform>;

    /// Purge the ticket `info`, or every ticket.
    ///
    /// # Errors
    ///
    /// LSA failures.
    fn purge(&self, info: Option<&CacheInfo>) -> Result<(), Platform>;
}

/// The `MSLSA:` store: read-only unless built with mutation authorized.
#[derive(Clone, Debug)]
pub struct MslsaStore {
    /// Whether changes to the logon session's cache are authorized.
    mutation: bool,
    /// The LSA.
    lsa: Arc<dyn Lsa>,
}

impl MslsaStore {
    /// A read-only store: every change fails with
    /// [`Platform::MutationNotAuthorized`].
    #[cfg(windows)]
    #[must_use]
    #[inline]
    pub fn new() -> Self {
        Self::with_mutation(false)
    }

    /// A store that may change the logon session's ticket cache when
    /// `mutation` is true.
    ///
    /// # Security
    ///
    /// A change applies to every process of the logon session.
    #[cfg(windows)]
    #[must_use]
    #[inline]
    pub fn with_mutation(mutation: bool) -> Self {
        Self {
            mutation,
            lsa: Arc::new(lsa::System),
        }
    }

    /// The cache handle of `residual`.
    fn cache(&self, residual: &str) -> MslsaCache {
        MslsaCache {
            name: format!("{CACHE_TYPE}:{residual}"),
            store: self.clone(),
        }
    }
}

#[cfg(windows)]
impl Default for MslsaStore {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl CredentialStore for MslsaStore {
    #[inline]
    fn cache_type(&self) -> &'static str {
        CACHE_TYPE
    }

    /// Every residual names the one cache (`krb5_lcc_resolve`).
    #[inline]
    fn resolve(&self, residual: &str) -> Result<Box<dyn CacheHandle>, Error> {
        Ok(Box::new(self.cache(residual)))
    }

    #[inline]
    fn collection(&self, residual: &str) -> Result<Box<dyn CacheCollection>, Error> {
        Ok(Box::new(Collection(self.cache(residual))))
    }
}

/// The `MSLSA` provider: install it to reach `MSLSA:` names by name.
impl StoreProvider for MslsaStore {
    #[inline]
    fn id(&self) -> &str {
        CACHE_TYPE
    }

    #[inline]
    fn prefix(&self) -> &str {
        CACHE_TYPE
    }

    #[inline]
    fn credential_store(&self) -> Option<&dyn CredentialStore> {
        Some(self)
    }
}

/// The logon session's cache.
#[derive(Clone, Debug)]
struct MslsaCache {
    /// The full name.
    name: String,
    /// The store.
    store: MslsaStore,
}

/// The principal of a cache entry's `/`-joined name in `realm`.
fn principal(name: &str, realm: &str) -> Principal {
    Principal::new(
        realm,
        NT_PRINCIPAL,
        name.split('/').map(str::to_owned).collect(),
    )
}

impl MslsaCache {
    /// Refuse a change unless the store authorizes it.
    /// # Errors
    /// Returns [`Platform::MutationNotAuthorized`].
    fn authorize(&self) -> Result<&dyn Lsa, Error> {
        if self.store.mutation {
            Ok(self.store.lsa.as_ref())
        } else {
            Err(Platform::MutationNotAuthorized {
                cache_type: CACHE_TYPE,
            }
            .into())
        }
    }

    /// Purge every entry `select` picks; returns how many.
    /// # Errors
    /// Returns LSA failures.
    fn purge_where<F>(&self, select: F) -> Result<usize, Error>
    where
        F: Fn(&CacheInfo) -> bool,
    {
        let lsa = self.authorize()?;
        let mut purged = 0_usize;
        for info in lsa.entries()?.iter().filter(|info| select(info)) {
            lsa.purge(Some(info))?;
            purged = purged.saturating_add(1);
        }
        Ok(purged)
    }
}

impl CacheHandle for MslsaCache {
    fn name(&self) -> String {
        self.name.clone()
    }

    /// The client of the first ticket is the default principal
    /// (`krb5_lcc_resolve`); tickets without a session key are skipped
    /// (`krb5_lcc_next_cred`).
    fn load(&self) -> Result<CCache, Error> {
        let lsa = self.store.lsa.as_ref();
        let entries = lsa.entries()?;
        let first = entries.first().ok_or_else(|| Error::CacheNotFound {
            name: self.name.clone(),
        })?;
        let mut cache = CCache::new(principal(first.client_name(), first.client_realm()));
        for info in &entries {
            if let Some(credential) = lsa.retrieve(info)? {
                cache.credentials_mut().push(credential);
            }
        }
        Ok(cache)
    }

    /// Remove the tickets of `principal` (`krb5_lcc_initialize`).
    fn initialize(&self, principal: &Principal) -> Result<(), Error> {
        let client = principal.components.join("/");
        self.purge_where(|info| {
            info.client_realm() == principal.realm && info.client_name() == client
        })
        .map(drop)
    }

    fn replace(&self, cache: &CCache) -> Result<(), Error> {
        self.initialize(cache.default_principal())?;
        for credential in cache.credentials() {
            self.store(credential.clone())?;
        }
        Ok(())
    }

    /// Submit the ticket as a KRB-CRED encrypted under a fixed AES key
    /// (`KerbSubmitTicket`, `cc_mslsa.c:730-843`, which uses RC4). The LSA
    /// cannot hold configuration entries; they are skipped, as MIT skips them.
    fn store(&self, credential: Credential) -> Result<(), Error> {
        let lsa = self.authorize()?;
        if credential.server().realm == "X-CACHECONF:" {
            return Ok(());
        }
        let key = EncryptionKey::new(SUBMIT_ETYPE, SUBMIT_KEY.to_vec());
        let krb_cred = Secret::from(
            krb_cred::encode_encrypted_ccache_credentials(&[credential], &key).map_err(
                |_encode| Platform::MalformedReply {
                    cache_type: CACHE_TYPE,
                    reason: "credential cannot be a KRB-CRED",
                },
            )?,
        );
        Ok(lsa.submit(&krb_cred, &key)?)
    }

    /// Purge each ticket for `server` (`PurgeTicketEx`).
    fn remove(&self, server: &Principal) -> Result<usize, Error> {
        self.purge_where(|info| info.is_for(&server.realm, &server.components))
    }

    /// Purge the whole cache of the logon session (`PurgeAllTickets`).
    fn destroy(&self) -> Result<(), Error> {
        Ok(self.authorize()?.purge(None)?)
    }
}

/// The one cache of the logon session.
#[derive(Clone, Debug)]
struct Collection(MslsaCache);

impl CacheCollection for Collection {
    fn name(&self) -> String {
        self.0.name()
    }

    /// The cache, when it holds a ticket (`krb5_lcc_ptcursor_next`).
    fn caches(&self) -> Result<CacheCursor, Error> {
        let present = !self.0.store.lsa.entries()?.is_empty();
        Ok(CacheCursor::new(if present {
            vec![Box::new(self.0.clone())]
        } else {
            Vec::new()
        }))
    }

    fn primary(&self) -> Result<Box<dyn CacheHandle>, Error> {
        Ok(Box::new(self.0.clone()))
    }

    /// MIT has no `switch_to` for `MSLSA`: only the one cache is accepted.
    fn switch(&self, cache: &dyn CacheHandle) -> Result<(), Error> {
        if cache.name() == self.0.name {
            Ok(())
        } else {
            Err(Error::OutsideCollection {
                name: cache.name(),
                collection: self.name(),
            })
        }
    }

    /// MIT refuses to generate a new `MSLSA` cache (`krb5_lcc_generate_new`).
    fn new_unique(&self) -> Result<Box<dyn CacheHandle>, Error> {
        Err(Platform::UnsupportedOperation {
            cache_type: CACHE_TYPE,
            operation: "new_unique",
        }
        .into())
    }
}
