//! Credential-store containers: MEMORY stores, cache cursors, selection results
//! and store providers redact the caches they hold (supervisor validation Y4-06).

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    reason = "test code is not rendered API documentation"
)]
pub(super) mod tests {
    extern crate alloc;

    use alloc::sync::Arc;
    use core::error::Error;

    use rskrb5_ng::{
        ccache::{
            self, CredentialTimes,
            in_memory::MemoryStore,
            selection::Selected,
            stores::{CacheCollection, CacheHandle, CredentialStore},
        },
        error::Ccache as CacheError,
        extensions::{Extension, Registry, StoreProvider},
    };

    use crate::tests::{pattern, redacted};

    /// A cache type over a MEMORY store, as a provider offers it.
    #[derive(Debug)]
    struct Caches(MemoryStore);

    impl CredentialStore for Caches {
        fn cache_type(&self) -> &'static str {
            "AUDITSTORE"
        }

        fn resolve(&self, residual: &str) -> Result<Box<dyn CacheHandle>, CacheError> {
            self.0.resolve(residual)
        }

        fn collection(&self, residual: &str) -> Result<Box<dyn CacheCollection>, CacheError> {
            self.0.collection(residual)
        }
    }

    /// A store provider holding populated caches.
    struct Provider(Caches);

    impl StoreProvider for Provider {
        fn id(&self) -> &'static str {
            "audit"
        }

        fn prefix(&self) -> &'static str {
            "AUDITSTORE"
        }

        fn credential_store(&self) -> Option<&dyn CredentialStore> {
            Some(&self.0)
        }
    }

    /// Every store container is exercised holding a cache with a key and a ticket.
    pub(crate) fn run_audit() -> Result<(), Box<dyn Error>> {
        let key = pattern(129);
        let ticket = pattern(145);
        let client = ccache::Principal::new("EXAMPLE.COM", 1, vec!["alice".to_owned()]);
        let server = ccache::Principal::new(
            "EXAMPLE.COM",
            2,
            vec!["krbtgt".to_owned(), "EXAMPLE.COM".to_owned()],
        );
        let store = MemoryStore::new();
        let cache = store.resolve("audit")?;
        cache.initialize(&client)?;
        cache.store(ccache::Credential::new(
            client,
            server,
            ccache::EncryptionKey::new(17, key.clone()),
            CredentialTimes::default(),
            [0; 4],
            ticket.clone().into(),
        ))?;
        let secrets: [&[u8]; 2] = [&key, &ticket];
        redacted(&store, &secrets);
        redacted(&store.caches()?, &secrets);
        redacted(&Selected::Cache(cache), &secrets);
        let extension = Extension::StoreProvider(Arc::new(Provider(Caches(store))));
        redacted(&extension, &secrets);
        let mut registry = Registry::new();
        registry.register(extension)?;
        redacted(&registry, &secrets);
        Ok(())
    }
}
