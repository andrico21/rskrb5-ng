//! Credential stores: MEMORY isolation and concurrency, DIR collections,
//! switching and contention, the configured output version, file checks and
//! cache selection over a collection.

/// Credential store tests.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::{error, iter};
    #[cfg(unix)]
    use std::os::unix::fs::{PermissionsExt as _, symlink};
    use std::{
        env, fs, io,
        path::{Path, PathBuf},
        process,
        sync::Barrier,
        thread,
        time::{SystemTime, UNIX_EPOCH},
    };

    use rskrb5_ng::{
        ccache::{
            self, CCache, CacheCollection as _, CacheHandle, CacheVersion, Credential,
            CredentialStore as _, CredentialTimes, DirStore, EncryptionKey, FileStore, MemoryStore,
            Principal, Selected,
        },
        config::Config,
        error::Ccache as Error,
        extensions::Registry,
    };

    /// Error type of the `Result`-returning tests.
    type TestError = Box<dyn error::Error>;

    /// A fresh scratch directory.
    fn scratch(label: &str) -> Result<PathBuf, TestError> {
        let directory = env::temp_dir().join(format!(
            "ccache-store-{label}-{}-{}",
            process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
        ));
        fs::create_dir_all(&directory)?;
        Ok(directory)
    }

    /// A principal of `realm`.
    fn principal(name: &str, realm: &str) -> Principal {
        Principal::new(realm, 1, vec![name.to_owned()])
    }

    /// A credential of `client` for `server` with a recognizable ticket.
    fn credential(client: &Principal, server: &str, tag: u8) -> Credential {
        let mut times = CredentialTimes::default();
        times.auth_time = 1;
        times.end_time = 2_000_000_000;
        Credential::new(
            client.clone(),
            Principal::new(
                client.realm.clone(),
                2,
                vec![server.to_owned(), client.realm.clone()],
            ),
            EncryptionKey::new(18, vec![tag; 32]),
            times,
            [0x40, 0, 0, 0],
            vec![tag; 24].into(),
        )
    }

    /// Two MEMORY stores never share a cache; clones of one store do.
    #[test]
    fn memory_stores_are_isolated() -> Result<(), TestError> {
        // Given two stores and a clone of the first.
        let first = MemoryStore::new();
        let second = MemoryStore::new();
        let shared = first.clone();
        let alice = principal("alice", "A.TEST");
        // When the first store initializes MEMORY:app.
        first.resolve("app")?.initialize(&alice)?;
        first
            .resolve("app")?
            .store(credential(&alice, "krbtgt", 1))?;
        // Then only the first store and its clone see it.
        assert!(matches!(
            second.resolve("app")?.load(),
            Err(Error::CacheNotFound { name: _ })
        ));
        assert_eq!(shared.resolve("app")?.load()?.entries().len(), 1);
        assert_eq!(first.resolve("app")?.name(), "MEMORY:app");
        assert_eq!(second.caches()?.count(), 1);
        Ok(())
    }

    /// Concurrent writers to one MEMORY cache keep every credential.
    #[test]
    fn memory_concurrent_stores_keep_every_credential() -> Result<(), TestError> {
        let store = MemoryStore::new();
        let alice = principal("alice", "A.TEST");
        store.resolve("shared")?.initialize(&alice)?;
        let barrier = Barrier::new(8);
        thread::scope(|scope| -> Result<(), TestError> {
            let workers: Vec<_> = (0_u8..8)
                .map(|tag| {
                    let (memory, client, gate) = (&store, &alice, &barrier);
                    scope.spawn(move || -> Result<(), Error> {
                        let _wait = gate.wait();
                        memory.resolve("shared")?.store(credential(
                            client,
                            &format!("svc{tag}"),
                            tag,
                        ))
                    })
                })
                .collect();
            for worker in workers {
                worker.join().map_err(|_panic| "worker panicked")??;
            }
            Ok(())
        })?;
        assert_eq!(store.resolve("shared")?.load()?.entries().len(), 8);
        Ok(())
    }

    /// Removal, configuration entries, destruction and moving between stores.
    #[test]
    fn memory_remove_config_destroy_and_move() -> Result<(), TestError> {
        let store = MemoryStore::new();
        let alice = principal("alice", "A.TEST");
        let cache = store.resolve("one")?;
        cache.initialize(&alice)?;
        cache.store(credential(&alice, "HTTP", 7))?;
        cache.store(credential(&alice, "host", 8))?;
        cache.set_config("pa_type", None, b"138".to_vec().into())?;
        let server = Principal::new("A.TEST", 2, vec!["HTTP".to_owned(), "A.TEST".to_owned()]);
        assert_eq!(cache.remove(&server)?, 1);
        assert_eq!(cache.remove(&server)?, 0);
        assert_eq!(
            cache.get_config("pa_type", None)?.as_deref(),
            Some(&b"138".to_vec())
        );
        assert_eq!(cache.load()?.entries().len(), 1);
        // Moving to another store copies everything and destroys the source.
        let other = MemoryStore::new();
        ccache::move_cache(cache.as_ref(), other.resolve("two")?.as_ref())?;
        assert!(matches!(
            cache.load(),
            Err(Error::CacheNotFound { name: _ })
        ));
        assert_eq!(other.resolve("two")?.load()?.entries().len(), 1);
        // Moving a cache onto its own name keeps it.
        let two = other.resolve("two")?;
        ccache::move_cache(two.as_ref(), two.as_ref())?;
        assert_eq!(two.load()?.entries().len(), 1);
        two.destroy()?;
        assert!(matches!(
            two.destroy(),
            Err(Error::CacheNotFound { name: _ })
        ));
        Ok(())
    }

    /// MEMORY primary selection, switching, enumeration order and new caches.
    #[test]
    fn memory_collection_switches_and_enumerates() -> Result<(), TestError> {
        let store = MemoryStore::new();
        let (alice, bob) = (principal("alice", "A.TEST"), principal("bob", "B.TEST"));
        store.resolve("first")?.initialize(&alice)?;
        let unique = store.new_unique()?;
        unique.initialize(&bob)?;
        assert_eq!(store.primary()?.name(), "MEMORY:first");
        store.switch(unique.as_ref())?;
        let names: Vec<String> = store.caches()?.map(|cache| cache.name()).collect();
        assert_eq!(names.first(), Some(&unique.name()));
        assert_eq!(names.len(), 2);
        let found = store.cache_match(&bob)?.ok_or("bob's cache")?;
        assert_eq!(found.name(), unique.name());
        // A cache of another store type is not a member.
        let directory = scratch("memory-switch")?;
        let file = FileStore::default().resolve(&directory.join("cc").to_string_lossy())?;
        assert!(matches!(
            store.switch(file.as_ref()),
            Err(Error::OutsideCollection {
                name: _,
                collection: _
            })
        ));
        fs::remove_dir_all(directory)?;
        Ok(())
    }

    /// A DIR collection: primary creation, new caches, switching, enumeration
    /// order, matching and the primary pointer MIT reads.
    #[test]
    fn dir_collection_switches_and_enumerates() -> Result<(), TestError> {
        let directory = scratch("dir")?;
        let residual = directory.join("collection");
        let store = DirStore::default();
        let collection = store.collection(&residual.to_string_lossy())?;
        // The primary of a new collection is `tkt`, recorded in `primary`.
        let primary = collection.primary()?;
        assert_eq!(
            primary.name(),
            format!("DIR::{}", residual.join("tkt").display())
        );
        assert_eq!(fs::read(residual.join("primary"))?, b"tkt\n");
        let (alice, bob) = (principal("alice", "A.TEST"), principal("bob", "B.TEST"));
        primary.initialize(&alice)?;
        let other = collection.new_unique()?;
        other.initialize(&bob)?;
        other.store(credential(&bob, "krbtgt", 3))?;
        // Switching rewrites the pointer; the new primary is listed first.
        collection.switch(other.as_ref())?;
        let file = other
            .name()
            .rsplit(['/', '\\'])
            .next()
            .ok_or("name")?
            .to_owned();
        assert_eq!(
            fs::read(residual.join("primary"))?,
            format!("{file}\n").as_bytes()
        );
        let names: Vec<String> = collection.caches()?.map(|cache| cache.name()).collect();
        assert_eq!(names, [other.name(), primary.name()]);
        assert_eq!(
            store.resolve(&residual.to_string_lossy())?.name(),
            other.name()
        );
        assert_eq!(
            collection.cache_match(&alice)?.ok_or("alice")?.name(),
            primary.name()
        );
        assert!(collection.has_content()?);
        // A malformed pointer is refused for the primary but enumeration lists the files.
        fs::write(residual.join("primary"), b"../escape\n")?;
        assert!(matches!(collection.primary(), Err(Error::InvalidCacheName)));
        assert_eq!(collection.caches()?.count(), 2);
        fs::remove_dir_all(directory)?;
        Ok(())
    }

    /// QA failure scenario: switching the DIR primary to a cache outside the
    /// collection directory is rejected, and the pointer is unchanged.
    #[test]
    fn dir_switch_outside_the_collection_is_rejected() -> Result<(), TestError> {
        let directory = scratch("dir-outside")?;
        let residual = directory.join("collection");
        let store = DirStore::default();
        let collection = store.collection(&residual.to_string_lossy())?;
        collection
            .primary()?
            .initialize(&principal("alice", "A.TEST"))?;
        let elsewhere = directory.join("elsewhere");
        let foreign = [
            store.resolve(&format!(":{}", elsewhere.join("tkt1").display()))?,
            store.resolve(&format!(
                ":{}",
                residual.join("nested").join("tkt1").display()
            ))?,
            FileStore::default().resolve(&residual.join("tkt1").to_string_lossy())?,
            MemoryStore::new().resolve("tkt1")?,
        ];
        for cache in &foreign {
            assert!(
                matches!(
                    collection.switch(cache.as_ref()),
                    Err(Error::OutsideCollection {
                        name: _,
                        collection: _
                    })
                ),
                "{} was accepted",
                cache.name()
            );
        }
        assert_eq!(fs::read(residual.join("primary"))?, b"tkt\n");
        fs::remove_dir_all(directory)?;
        Ok(())
    }

    /// Concurrent writers of one DIR cache keep every credential, and
    /// concurrent switches leave a whole pointer naming a member.
    #[test]
    fn dir_contention_keeps_every_update() -> Result<(), TestError> {
        let directory = scratch("dir-contention")?;
        let residual = directory.join("collection").to_string_lossy().into_owned();
        let store = DirStore::default();
        let collection = store.collection(&residual)?;
        let alice = principal("alice", "A.TEST");
        let shared = collection.primary()?;
        shared.initialize(&alice)?;
        let members: Vec<Box<dyn CacheHandle>> = iter::repeat_with(|| collection.new_unique())
            .take(4)
            .collect::<Result<_, _>>()?;
        let barrier = Barrier::new(8);
        thread::scope(|scope| -> Result<(), TestError> {
            let workers: Vec<_> = (0_u8..8)
                .map(|tag| {
                    let (cache, candidates, target, client, gate) =
                        (&shared, &members, &collection, &alice, &barrier);
                    scope.spawn(move || -> Result<(), Error> {
                        let _wait = gate.wait();
                        cache.store(credential(client, &format!("svc{tag}"), tag))?;
                        let member = usize::from(tag)
                            .checked_rem(candidates.len())
                            .and_then(|index| candidates.get(index))
                            .ok_or(Error::InvalidCacheName)?;
                        target.switch(member.as_ref())
                    })
                })
                .collect();
            for worker in workers {
                worker.join().map_err(|_panic| "worker panicked")??;
            }
            Ok(())
        })?;
        assert_eq!(shared.load()?.entries().len(), 8);
        let pointer = fs::read_to_string(Path::new(&residual).join("primary"))?;
        assert!(
            members
                .iter()
                .any(|member| member.name().ends_with(pointer.trim_end())),
            "{pointer:?} names no member"
        );
        fs::remove_dir_all(directory)?;
        Ok(())
    }

    /// `ccache_type` 1-4 selects the version new caches are written in; the
    /// version of an existing cache is kept when a credential is added.
    #[test]
    fn configured_version_applies_to_new_caches() -> Result<(), TestError> {
        let directory = scratch("versions")?;
        let alice = Principal::new("A.TEST", 0, vec!["alice".to_owned()]);
        for number in 1_u8..=4 {
            let config = Config::parse(&format!("[libdefaults]\n ccache_type = {number}\n"))?;
            let version = CacheVersion::from_libdefaults(&config.libdefaults)?;
            assert_eq!(version.get(), number);
            let path = directory.join(format!("v{number}"));
            let cache = FileStore::new(version).resolve(&path.to_string_lossy())?;
            cache.initialize(&alice)?;
            let mut stored = credential(&alice, "krbtgt", number);
            stored.client_mut().name_type = 0_i32;
            stored.server_mut().name_type = 0_i32;
            cache.store(stored)?;
            assert_eq!(fs::read(&path)?.get(..2), Some(&[5, number][..]));
            let loaded = cache.load()?;
            assert_eq!((loaded.version(), loaded.entries().len()), (number, 1));
            // A version-4 store keeps the older version when it adds a credential.
            FileStore::default()
                .resolve(&path.to_string_lossy())?
                .store(credential(&alice, "HTTP", 9))
                .or_else(|error| match (number, error) {
                    (1, Error::UnrepresentableNameType(_)) => Ok(()),
                    (_, other) => Err(other),
                })?;
            assert_eq!(fs::read(&path)?.get(..2), Some(&[5, number][..]));
        }
        for invalid in [0_i32, 5_i32, -1_i32, i32::MAX] {
            let config = Config::parse(&format!("[libdefaults]\n ccache_type = {invalid}\n"))?;
            assert!(matches!(
                CacheVersion::from_libdefaults(&config.libdefaults),
                Err(Error::InvalidCacheType(value)) if value == invalid
            ));
        }
        fs::remove_dir_all(directory)?;
        Ok(())
    }

    /// Store files are owner-only; symlinks and files others may write are refused.
    #[cfg(unix)]
    #[test]
    fn file_caches_refuse_untrusted_files() -> Result<(), TestError> {
        let directory = scratch("trust")?;
        let path = directory.join("cache");
        let cache = FileStore::default().resolve(&path.to_string_lossy())?;
        cache.initialize(&principal("alice", "A.TEST"))?;
        assert_eq!(fs::metadata(&path)?.permissions().mode() & 0o777, 0o600);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o622))?;
        assert!(
            matches!(cache.load(), Err(Error::Io(error)) if error.kind() == io::ErrorKind::PermissionDenied)
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        let link = directory.join("link");
        symlink(&path, &link)?;
        let linked = FileStore::default().resolve(&link.to_string_lossy())?;
        assert!(
            matches!(linked.load(), Err(Error::Io(error)) if error.kind() == io::ErrorKind::InvalidInput)
        );
        drop(
            linked
                .store(credential(&principal("alice", "A.TEST"), "x", 1))
                .err()
                .ok_or("a symlinked cache was written")?,
        );
        // A collection directory that others may write is refused unless sticky.
        let open = directory.join("open");
        fs::create_dir_all(&open)?;
        fs::set_permissions(&open, fs::Permissions::from_mode(0o777))?;
        assert!(matches!(
            DirStore::default().collection(&open.to_string_lossy()),
            Err(Error::Io(_))
        ));
        fs::set_permissions(&open, fs::Permissions::from_mode(0o1777))?;
        drop(DirStore::default().collection(&open.to_string_lossy())?);
        fs::remove_dir_all(directory)?;
        Ok(())
    }

    /// Destroying a file cache removes it; built-in names resolve to stores.
    #[test]
    fn built_in_names_resolve_and_destroy() -> Result<(), TestError> {
        let directory = scratch("names")?;
        let collection = directory.join("collection");
        let primary = ccache::resolve(&format!("DIR:{}", collection.display()), CacheVersion::V4)?;
        assert_eq!(
            primary.name(),
            format!("DIR::{}", collection.join("tkt").display())
        );
        primary.initialize(&principal("alice", "A.TEST"))?;
        assert_eq!(
            ccache::collection(&format!("DIR:{}", collection.display()), CacheVersion::V4)?
                .caches()?
                .count(),
            1
        );
        let file = directory.join("file");
        let cache = ccache::resolve(&format!("FILE:{}", file.display()), CacheVersion::V4)?;
        cache.initialize(&principal("bob", "B.TEST"))?;
        assert_eq!(CCache::load(&file)?.client_name(), "bob");
        cache.destroy()?;
        assert!(!file.exists());
        assert!(matches!(
            cache.load(),
            Err(Error::CacheNotFound { name: _ })
        ));
        assert!(matches!(
            ccache::resolve("KCM:", CacheVersion::V4),
            Err(Error::UnsupportedCacheType { cache_type }) if cache_type == "KCM"
        ));
        fs::remove_dir_all(directory)?;
        Ok(())
    }

    /// `krb5_cc_select` over a collection, also for a server in the referral realm.
    #[test]
    fn selection_runs_over_a_collection() -> Result<(), TestError> {
        let store = MemoryStore::new();
        store
            .resolve("alice")?
            .initialize(&principal("alice", "A.TEST"))?;
        store
            .resolve("bob")?
            .initialize(&principal("bob", "B.TEST"))?;
        let registry = Registry::with_builtins(None);
        let config = Config::parse("[libdefaults]\n default_realm = B.TEST\n")?;
        let server = |realm: &str| {
            Principal::new(realm, 3, vec!["HTTP".to_owned(), "www.example".to_owned()])
        };
        for realm in ["B.TEST", ""] {
            let Selected::Cache(cache) =
                ccache::select_cache(&registry, &config, &store, &server(realm))?
            else {
                return Err(format!("no cache for realm {realm:?}").into());
            };
            assert_eq!(cache.name(), "MEMORY:bob");
        }
        let unknown = Config::parse("[libdefaults]\n")?;
        assert!(matches!(
            ccache::select_cache(&registry, &unknown, &store, &server(""))?,
            Selected::NotFound
        ));
        Ok(())
    }

    /// The client write-back creates caches in the configured version (MIT
    /// `fcc_default_format`) and refuses a `ccache_type` outside 1 to 4.
    #[cfg(feature = "tokio")]
    #[test]
    fn client_write_back_uses_the_configured_version() -> Result<(), TestError> {
        use rskrb5_ng::{
            TokioClient, client::transport::KdcProtocol, error::Client as ClientError,
        };
        let alice = principal("alice", "A.TEST");
        for (number, expected) in [(3_i32, Some(3_u8)), (1_i32, Some(1_u8)), (5_i32, None)] {
            let config = Config::parse(&format!("[libdefaults]\n ccache_type = {number}\n"))?;
            let client =
                TokioClient::from_ccache(config, KdcProtocol::Udp, &CCache::new(alice.clone()));
            match (client.to_ccache(), expected) {
                (Ok(cache), Some(version)) => assert_eq!(cache.version(), version),
                (Err(ClientError::CCache(Error::InvalidCacheType(5_i32))), None) => {}
                (other, _) => return Err(format!("ccache_type {number}: {other:?}").into()),
            }
        }
        Ok(())
    }
}
