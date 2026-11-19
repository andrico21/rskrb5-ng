//! Store providers registered through `extensions::Registry`: registration
//! rules, process-wide installation and name resolution through the routes
//! `CCache`, `Keytab` and the client use (supervisor validation ORA-01).

/// Store registration tests.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    extern crate alloc;

    use alloc::sync::Arc;
    use core::error;

    use rskrb5_ng::{
        ccache::{
            CCache, Principal, file_store,
            in_memory::MemoryStore,
            stores::{CacheCollection, CacheHandle, CacheVersion, CredentialStore},
        },
        error::{Ccache as CacheError, Extensions as ExtensionError, Keytab as KeytabError},
        extensions::{Extension, Interface, Registry, StoreProvider},
        keytab::{
            self, EncryptionKey, Entry, Keytab,
            stores::{KeyStore, KeytabType, MemoryKeytab},
        },
    };

    /// Error type of the `Result`-returning tests.
    type TestError = Box<dyn error::Error>;

    /// A cache type that keeps its caches in a [`MemoryStore`] under its own prefix.
    #[derive(Debug)]
    struct FakeCaches {
        /// The claimed prefix.
        prefix: &'static str,
        /// Where the caches live.
        caches: MemoryStore,
    }

    impl CredentialStore for FakeCaches {
        fn cache_type(&self) -> &'static str {
            self.prefix
        }

        fn resolve(&self, residual: &str) -> Result<Box<dyn CacheHandle>, CacheError> {
            self.caches.resolve(residual)
        }

        fn collection(&self, residual: &str) -> Result<Box<dyn CacheCollection>, CacheError> {
            self.caches.collection(residual)
        }
    }

    /// A keytab type over a [`MemoryKeytab`] table.
    #[derive(Debug)]
    struct FakeKeytabs(MemoryKeytab);

    impl KeytabType for FakeKeytabs {
        fn resolve(&self, residual: &str) -> Result<Box<dyn KeyStore>, KeytabError> {
            self.0.resolve(residual)
        }
    }

    /// An external store provider, as a companion crate would write one.
    struct Fake {
        /// Its id.
        id: &'static str,
        /// The prefix it claims.
        prefix: &'static str,
        /// Its cache type, if any.
        caches: Option<FakeCaches>,
        /// Its keytab type, if any.
        keytabs: Option<FakeKeytabs>,
    }

    impl StoreProvider for Fake {
        fn id(&self) -> &str {
            self.id
        }

        fn prefix(&self) -> &str {
            self.prefix
        }

        fn credential_store(&self) -> Option<&dyn CredentialStore> {
            self.caches
                .as_ref()
                .map(|caches| -> &dyn CredentialStore { caches })
        }

        fn keytab_type(&self) -> Option<&dyn KeytabType> {
            self.keytabs
                .as_ref()
                .map(|keytabs| -> &dyn KeytabType { keytabs })
        }
    }

    /// A provider of both a cache type and a keytab type under `prefix`.
    fn fake(id: &'static str, prefix: &'static str) -> Arc<Fake> {
        Arc::new(Fake {
            id,
            prefix,
            caches: Some(FakeCaches {
                prefix,
                caches: MemoryStore::new(),
            }),
            keytabs: Some(FakeKeytabs(MemoryKeytab::new())),
        })
    }

    /// The registration of `provider`.
    fn store(provider: Arc<Fake>) -> Extension {
        Extension::StoreProvider(provider)
    }

    /// A principal of `realm`.
    fn principal(name: &str, realm: &str) -> Principal {
        Principal::new(realm, 1, vec![name.to_owned()])
    }

    /// The prefix a registration refused as taken.
    fn taken(result: Result<(), ExtensionError>) -> Option<String> {
        match result {
            Err(ExtensionError::PrefixTaken { prefix, id: _ }) => Some(prefix),
            _ => None,
        }
    }

    /// A registration error that is not a prefix collision.
    fn invalid(result: &Result<(), ExtensionError>) -> bool {
        matches!(
            result,
            Err(ExtensionError::InvalidRegistration {
                interface: Interface::StoreProvider,
                id: _,
                reason: _,
            })
        )
    }

    /// The interface is not configured by `[plugins]` and keeps registration order.
    #[test]
    fn store_interface_is_not_configurable() -> Result<(), TestError> {
        assert!(!Interface::StoreProvider.configurable());
        assert_eq!(Interface::StoreProvider.name(), "store");
        let mut registry = Registry::new();
        registry.register(store(fake("second", "FAKEORDB")))?;
        registry.register(store(fake("first", "FAKEORDA")))?;
        assert_eq!(registry.ids(Interface::StoreProvider), ["second", "first"]);
        Ok(())
    }

    /// A built-in prefix, in any case, and a prefix a provider already claims
    /// are refused with the typed collision error; malformed claims are refused.
    #[test]
    fn taken_and_malformed_prefixes_are_refused() -> Result<(), TestError> {
        let mut registry = Registry::new();
        registry.register(store(fake("first", "FAKEREG")))?;
        for (id, prefix) in [
            ("file", "FILE"),
            ("wrfile", "wrfile"),
            ("dir", "Dir"),
            ("memory", "MEMORY"),
            ("again", "FAKEREG"),
            ("again-case", "fakereg"),
        ] {
            assert_eq!(
                taken(registry.register(store(fake(id, prefix)))).as_deref(),
                Some(prefix),
                "{prefix}"
            );
        }
        for prefix in ["", "C", "A:B", "SP ACE", "\u{dc}-TYPE"] {
            assert!(
                invalid(&registry.register(store(fake("bad", prefix)))),
                "{prefix:?}"
            );
        }
        let neither = Arc::new(Fake {
            id: "neither",
            prefix: "FAKENONE",
            caches: None,
            keytabs: None,
        });
        assert!(invalid(&registry.register(store(neither))));
        let mismatched = Arc::new(Fake {
            id: "mismatched",
            prefix: "FAKEMIS",
            caches: Some(FakeCaches {
                prefix: "OTHER",
                caches: MemoryStore::new(),
            }),
            keytabs: None,
        });
        assert!(invalid(&registry.register(store(mismatched))));
        assert_eq!(registry.ids(Interface::StoreProvider), ["first"]);
        Ok(())
    }

    /// Installing publishes a registry's providers process-wide once: the same
    /// provider again changes nothing, another provider of an installed prefix
    /// is refused and nothing of that registry is installed.
    #[test]
    fn installation_refuses_a_second_provider_of_a_prefix() -> Result<(), TestError> {
        let mut first = Registry::new();
        first.register(store(fake("one", "FAKEINST")))?;
        first.install_stores()?;
        first.install_stores()?;
        let mut second = Registry::new();
        second.register(store(fake("fresh", "FAKEINSTB")))?;
        second.register(store(fake("other", "FAKEINST")))?;
        assert_eq!(taken(second.install_stores()).as_deref(), Some("FAKEINST"));
        assert!(matches!(
            CCache::load_name("FAKEINSTB:app"),
            Err(CacheError::UnsupportedCacheType { cache_type: _ })
        ));
        Ok(())
    }

    /// An installed external store is resolved by `CCache` names, by the
    /// store-level name dispatch and by `Keytab` names; unknown and case-variant
    /// prefixes stay unsupported, and path APIs stay file-only.
    #[test]
    fn installed_store_resolves_cache_and_keytab_names() -> Result<(), TestError> {
        let provider = fake("routed", "FAKEROUTE");
        let mut registry = Registry::new();
        registry.register(store(Arc::clone(&provider)))?;
        registry.install_stores()?;
        let caches = provider.credential_store().ok_or("cache type")?;
        let alice = principal("alice", "FAKE.TEST");
        caches.resolve("app")?.initialize(&alice)?;

        assert_eq!(
            CCache::load_name("FAKEROUTE:app")?.default_principal(),
            &alice
        );
        let bob = CCache::new(principal("bob", "FAKE.TEST"));
        bob.save_name("FAKEROUTE:saved")?;
        assert_eq!(caches.resolve("saved")?.load()?, bob);
        let handle = file_store::resolve("FAKEROUTE:app", CacheVersion::V4)?;
        assert_eq!(handle.load()?.default_principal(), &alice);
        for name in ["fakeroute:app", "FAKEABSENT:app"] {
            assert!(
                matches!(
                    CCache::load_name(name),
                    Err(CacheError::UnsupportedCacheType { cache_type: _ })
                ),
                "{name}"
            );
        }
        assert!(matches!(
            CCache::file_path_from_cache_name("FAKEROUTE:app"),
            Err(CacheError::UnsupportedCacheType { cache_type: _ })
        ));

        let keytabs = provider.keytab_type().ok_or("keytab type")?;
        keytabs.resolve("service")?.add(Entry::new(
            keytab::Principal::new("FAKE.TEST", 1, ["svc"]),
            1,
            3,
            EncryptionKey::new(18, vec![7; 32]),
            3,
        ))?;
        assert_eq!(Keytab::load_name("FAKEROUTE:service")?.entries().len(), 1);
        assert!(matches!(
            Keytab::load_name("FAKEABSENT:service"),
            Err(KeytabError::UnsupportedKeytabType { keytab_type: _ })
        ));
        Ok(())
    }

    /// The client's default-cache lookup (`default_ccache_name`) and its named
    /// lookup resolve an installed external store.
    #[cfg(feature = "tokio")]
    #[test]
    fn client_default_cache_lookup_resolves_an_installed_store() -> Result<(), TestError> {
        use rskrb5_ng::{TokioClient, client::transport::KdcProtocol, config::Config};

        let provider = fake("client", "FAKECLIENT");
        let mut registry = Registry::new();
        registry.register(store(Arc::clone(&provider)))?;
        registry.install_stores()?;
        let carol = principal("carol", "FAKE.TEST");
        provider
            .credential_store()
            .ok_or("cache type")?
            .resolve("default")?
            .initialize(&carol)?;
        let config = Config::parse("[libdefaults]\n default_ccache_name = FAKECLIENT:default\n")?;

        let client = TokioClient::from_default_ccache_name(config, KdcProtocol::Tcp)?;
        assert_eq!(client.to_ccache()?.default_principal(), &carol);
        let named =
            TokioClient::from_ccache_name(Config::new(), KdcProtocol::Tcp, "FAKECLIENT:default")?;
        assert_eq!(named.to_ccache()?.default_principal(), &carol);
        Ok(())
    }
}
