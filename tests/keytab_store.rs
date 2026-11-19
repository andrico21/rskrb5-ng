//! Keytab stores: MEMORY keytab isolation and lookups, file keytabs through
//! the store, and removal.

/// Keytab store tests.
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
        env, fs, process,
        time::{SystemTime, UNIX_EPOCH},
    };

    use rskrb5_ng::{
        error::Keytab as Error,
        keytab::{self, EncryptionKey, Entry, KeyStore, MemoryKeytab, Principal},
    };

    /// Error type of the `Result`-returning tests.
    type TestError = Box<dyn error::Error>;

    /// The client principal of the tests.
    fn client() -> Principal {
        Principal::new("A.TEST", 1, ["alice"])
    }

    /// An entry of the client with `kvno`, `etype` and a recognizable key.
    fn entry(kvno: u32, etype: i32, tag: u8) -> Entry {
        Entry::new(
            client(),
            u32::from(tag),
            kvno.to_le_bytes().first().copied().unwrap_or_default(),
            EncryptionKey::new(etype, vec![tag; 32]),
            kvno,
        )
    }

    /// Exercise the lookups every key store offers.
    fn lookups(store: &dyn KeyStore) -> Result<(), TestError> {
        store.add(entry(1, 18, 1))?;
        store.add(entry(2, 18, 2))?;
        store.add(entry(2, 17, 3))?;
        // The newest key of any kvno, a fixed kvno, and no match.
        let (key, kvno) = store.find(&client(), 0, 18)?;
        assert_eq!((key.value().as_ref(), kvno), (&[2_u8; 32][..], 2));
        assert_eq!(store.find(&client(), 1, 18)?.1, 1);
        drop(
            store
                .find(&client(), 3, 18)
                .err()
                .filter(|error| {
                    matches!(
                        error,
                        Error::NoMatchingKey {
                            principal: _,
                            realm: _,
                            kvno: _,
                            etype: _
                        }
                    )
                })
                .ok_or("an absent kvno matched")?,
        );
        // Removal by kvno and enctype, then everything of the principal.
        assert_eq!(store.remove(&client(), 2, Some(17_i32))?, 1);
        assert_eq!(store.load()?.entries().len(), 2);
        assert_eq!(store.remove(&client(), 0, None)?, 2);
        assert_eq!(store.load()?.entries().len(), 0);
        Ok(())
    }

    /// MEMORY keytabs: lookups, isolation between tables, sharing by name and destruction.
    #[test]
    fn memory_keytabs_are_named_and_isolated() -> Result<(), TestError> {
        let table = MemoryKeytab::new();
        let store = table.resolve("client")?;
        assert_eq!(store.name(), "MEMORY:client");
        lookups(store.as_ref())?;
        store.add(entry(5, 18, 5))?;
        // The same name in the same table is the same keytab; another table is empty.
        assert_eq!(table.resolve("client")?.load()?.entries().len(), 1);
        assert_eq!(
            MemoryKeytab::new()
                .resolve("client")?
                .load()?
                .entries()
                .len(),
            0
        );
        assert!(table.destroy("client"));
        assert!(!table.destroy("client"));
        assert_eq!(table.resolve("client")?.load()?.entries().len(), 0);
        assert!(matches!(table.resolve(""), Err(Error::InvalidKeytabName)));
        Ok(())
    }

    /// File keytabs: created on the first entry, read back by name, owner-only.
    #[test]
    fn file_keytabs_through_the_store() -> Result<(), TestError> {
        let directory = env::temp_dir().join(format!(
            "keytab-store-{}-{}",
            process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
        ));
        fs::create_dir_all(&directory)?;
        let path = directory.join("client.keytab");
        let store = keytab::resolve(&format!("FILE:{}", path.display()))?;
        assert!(matches!(store.load(), Err(Error::Io(_))));
        lookups(store.as_ref())?;
        store.add(entry(7, 18, 7))?;
        assert_eq!(keytab::Keytab::load(&path)?.entries().len(), 1);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(fs::metadata(&path)?.permissions().mode() & 0o777, 0o600);
        }
        assert!(matches!(
            keytab::resolve("MEMORY:client"),
            Err(Error::UnsupportedKeytabType { keytab_type }) if keytab_type == "MEMORY"
        ));
        fs::remove_dir_all(directory)?;
        Ok(())
    }
}
