//! Cache identity is the store instance plus the residual, not the name
//! string: moves between independent stores and switches to foreign handles
//! (supervisor validation ORA-04 and Y4-01).

/// Cache identity tests.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::error;
    use std::{
        env, fs,
        path::PathBuf,
        process,
        time::{SystemTime, UNIX_EPOCH},
    };

    use rskrb5_ng::{
        ccache::{
            CCache, Credential, Principal,
            dir_store::DirStore,
            file_store::FileStore,
            in_memory::MemoryStore,
            stores::{self, CacheCollection as _, CacheHandle, CredentialStore as _},
        },
        error::Ccache as Error,
    };

    /// Error type of the `Result`-returning tests.
    type TestError = Box<dyn error::Error>;

    /// A handle that only claims a name: another store's cache, as a
    /// third-party store could hand out.
    #[derive(Debug)]
    struct Impostor(String);

    impl CacheHandle for Impostor {
        fn name(&self) -> String {
            self.0.clone()
        }

        fn load(&self) -> Result<CCache, Error> {
            Err(Error::CacheNotFound { name: self.name() })
        }

        fn initialize(&self, _principal: &Principal) -> Result<(), Error> {
            Err(Error::InvalidCacheName)
        }

        fn replace(&self, _cache: &CCache) -> Result<(), Error> {
            Err(Error::InvalidCacheName)
        }

        fn store(&self, _credential: Credential) -> Result<(), Error> {
            Err(Error::InvalidCacheName)
        }

        fn remove(&self, _server: &Principal) -> Result<usize, Error> {
            Err(Error::InvalidCacheName)
        }

        fn destroy(&self) -> Result<(), Error> {
            Err(Error::InvalidCacheName)
        }
    }

    /// A fresh scratch directory.
    fn scratch(label: &str) -> Result<PathBuf, TestError> {
        let directory = env::temp_dir().join(format!(
            "ccache-identity-{label}-{}-{}",
            process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
        ));
        fs::create_dir_all(&directory)?;
        Ok(directory)
    }

    /// A principal of `TEST`.
    fn principal(name: &str) -> Principal {
        Principal::new("TEST", 1, vec![name.to_owned()])
    }

    /// Whether `result` is the refusal of a cache outside the collection.
    fn outside(result: &Result<(), Error>) -> bool {
        matches!(
            result,
            Err(Error::OutsideCollection {
                name: _,
                collection: _
            })
        )
    }

    /// A move between two independent MEMORY stores' `app` caches moves the
    /// contents and destroys the source.
    #[test]
    fn move_between_independent_memory_stores_with_equal_residuals() -> Result<(), TestError> {
        let (first, second) = (MemoryStore::new(), MemoryStore::new());
        let source = first.resolve("app")?;
        let destination = second.resolve("app")?;
        source.initialize(&principal("alice"))?;
        destination.initialize(&principal("bob"))?;
        stores::move_cache(&*source, &*destination)?;
        assert_eq!(destination.load()?.default_principal(), &principal("alice"));
        assert!(matches!(
            source.load(),
            Err(Error::CacheNotFound { name: _ })
        ));
        Ok(())
    }

    /// Moving a cache onto itself changes nothing, through two handles of one
    /// MEMORY store and through the `FILE:` and `DIR::` names of one file.
    #[test]
    fn genuine_self_moves_keep_the_cache() -> Result<(), TestError> {
        let store = MemoryStore::new();
        store.resolve("app")?.initialize(&principal("alice"))?;
        stores::move_cache(&*store.resolve("app")?, &*store.resolve("app")?)?;
        assert_eq!(
            store.resolve("app")?.load()?.default_principal(),
            &principal("alice")
        );

        let directory = scratch("self-move")?;
        let file = directory.join("tkt1");
        let as_file = FileStore::default().resolve(&file.to_string_lossy())?;
        as_file.initialize(&principal("alice"))?;
        let as_dir = DirStore::default().resolve(&format!(":{}", file.display()))?;
        stores::move_cache(&*as_file, &*as_dir)?;
        assert_eq!(as_file.load()?.default_principal(), &principal("alice"));
        fs::remove_dir_all(directory)?;
        Ok(())
    }

    /// A handle of another MEMORY store, or one that only claims a member's
    /// name, is outside the collection; the primary stays unchanged.
    #[test]
    fn foreign_handles_are_outside_memory_collections() -> Result<(), TestError> {
        let (first, second) = (MemoryStore::new(), MemoryStore::new());
        for (store, name) in [(&first, "alice"), (&second, "bob")] {
            store.resolve("x")?.initialize(&principal(name))?;
            store.resolve("y")?.initialize(&principal(name))?;
        }
        first.switch(&*first.resolve("y")?)?;
        assert!(outside(&first.switch(&*second.resolve("x")?)));
        assert!(outside(&first.switch(&Impostor("MEMORY:x".to_owned()))));
        assert_eq!(first.primary()?.name(), "MEMORY:y");
        first.switch(&*first.resolve("x")?)?;
        assert_eq!(first.primary()?.name(), "MEMORY:x");
        Ok(())
    }

    /// A handle that only claims the name of a FILE cache or of a DIR member
    /// is outside the collection; the genuine handles switch.
    #[test]
    fn foreign_handles_are_outside_file_and_dir_collections() -> Result<(), TestError> {
        let directory = scratch("foreign")?;
        let file = directory.join("tktfile");
        let single = FileStore::default().collection(&file.to_string_lossy())?;
        assert!(outside(
            &single.switch(&Impostor(format!("FILE:{}", file.display())))
        ));
        single.switch(&*single.primary()?)?;

        let collection = DirStore::default().collection(&directory.to_string_lossy())?;
        let member = collection.new_unique()?;
        member.initialize(&principal("alice"))?;
        drop(collection.primary()?);
        let pointer = directory.join("primary");
        let before = fs::read(&pointer)?;
        assert!(outside(&collection.switch(&Impostor(member.name()))));
        assert_eq!(fs::read(&pointer)?, before);
        collection.switch(&*member)?;
        assert_eq!(collection.primary()?.name(), member.name());
        fs::remove_dir_all(directory)?;
        Ok(())
    }
}
