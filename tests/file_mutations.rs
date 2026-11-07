//! Keytab and credential-cache file boundary regressions.

/// File-format tests using isolated filesystem fixtures.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::error::Error;
    use std::{env, fs, io, path::PathBuf};

    use rskrb5_ng::{
        ccache::{
            CCache, Credential, CredentialTimes, EncryptionKey as CacheKey,
            Principal as CachePrincipal,
        },
        error::{Ccache as CacheError, Keytab as KeytabError},
        keytab::{EncryptionKey, Entry, Keytab, Principal},
    };

    /// Create a unique directory for a DIR collection fixture.
    fn fixture_directory() -> Result<PathBuf, Box<dyn Error>> {
        let mut random = [0_u8; 16];
        getrandom::fill(&mut random)?;
        let path = env::temp_dir().join(format!(
            "mutants-b-cache-{:032x}",
            u128::from_be_bytes(random)
        ));
        fs::create_dir_all(&path)?;
        Ok(path)
    }

    /// Deleted keytab slots are skipped before parsing subsequent live entries.
    #[test]
    fn keytab_skips_deleted_slots() -> Result<(), Box<dyn Error>> {
        let mut keytab = Keytab::new();
        keytab.entries_mut().push(Entry::new(
            Principal::new("EXAMPLE", 1, ["alice"]),
            1,
            1,
            EncryptionKey::new(18, vec![7; 32]),
            1,
        ));
        let encoded = keytab.to_bytes()?;
        let mut bytes = vec![5_u8, 2];
        bytes.extend_from_slice(&(-4_i32).to_be_bytes());
        bytes.extend_from_slice(&[0x7f_u8; 4]);
        bytes.extend_from_slice(encoded.get(2..).ok_or("keytab body")?);
        let parsed = Keytab::parse(&bytes)?;
        assert_eq!(parsed.entries(), keytab.entries());
        Ok(())
    }

    /// A zero long key version cannot silently become the nonzero legacy version.
    #[test]
    fn keytab_rejects_ambiguous_zero_key_version() -> Result<(), Box<dyn Error>> {
        let mut keytab = Keytab::parse(&[5, 2])?;
        let mut entry = Entry::new(
            Principal::new("EXAMPLE", 1, ["alice"]),
            1,
            1,
            EncryptionKey::new(18, vec![7; 32]),
            1,
        );
        entry.kvno = 0;
        keytab.entries_mut().push(entry);
        assert!(matches!(
            keytab.to_bytes(),
            Err(KeytabError::LengthOverflow)
        ));
        Ok(())
    }

    /// An empty cache does not report a service credential it cannot return.
    #[test]
    fn cache_reports_missing_server() {
        assert!(
            !CCache::new(CachePrincipal::new("EXAMPLE", 1, vec!["alice".to_owned()]))
                .contains_server(&["HTTP", "missing.example"])
        );
    }

    /// Legacy ccache versions read host-order integers rather than network order.
    #[test]
    #[cfg(target_endian = "little")]
    fn cache_reads_legacy_host_order() -> Result<(), Box<dyn Error>> {
        for version in [1_u8, 2] {
            let mut wire = vec![5_u8, version];
            if version == 2 {
                wire.extend_from_slice(&1_u32.to_le_bytes());
            }
            wire.extend_from_slice(&(if version == 1 { 2_u32 } else { 1_u32 }).to_le_bytes());
            wire.extend_from_slice(&7_u32.to_le_bytes());
            wire.extend_from_slice(b"EXAMPLE");
            wire.extend_from_slice(&5_u32.to_le_bytes());
            wire.extend_from_slice(b"alice");
            let cache = CCache::parse(&wire)?;
            assert_eq!(cache.default_principal().realm, "EXAMPLE");
            assert_eq!(cache.default_principal().components, ["alice"]);
        }
        Ok(())
    }

    /// A missing DIR cache resolves without publishing a premature primary file.
    #[test]
    fn missing_dir_cache_leaves_primary_unpublished() -> Result<(), Box<dyn Error>> {
        let directory = fixture_directory()?;
        let resolved = CCache::file_path_from_cache_name(&format!("DIR:{}", directory.display()))?;
        assert_eq!(resolved, directory.join("tkt"));
        assert!(!directory.join("primary").try_exists()?);
        fs::remove_dir_all(directory)?;
        Ok(())
    }

    /// Invalid UTF-8 in the primary file is an I/O error, not absence.
    #[test]
    fn dir_primary_preserves_read_error() -> Result<(), Box<dyn Error>> {
        let directory = fixture_directory()?;
        fs::write(directory.join("primary"), [0xff_u8])?;
        let result = CCache::file_path_from_cache_name(&format!("DIR:{}", directory.display()));
        assert!(
            matches!(result, Err(CacheError::Io(error)) if error.kind() == io::ErrorKind::InvalidData)
        );
        fs::remove_dir_all(directory)?;
        Ok(())
    }

    /// Either separator independently rejects a DIR primary cache basename.
    #[test]
    fn dir_primary_rejects_each_path_separator() -> Result<(), Box<dyn Error>> {
        let directory = fixture_directory()?;
        for contents in ["tkt/escape\n", "tkt\\escape\n", "wrong\n"] {
            fs::write(directory.join("primary"), contents)?;
            assert!(matches!(
                CCache::file_path_from_cache_name(&format!("DIR:{}", directory.display())),
                Err(CacheError::InvalidCacheName)
            ));
        }
        fs::remove_dir_all(directory)?;
        Ok(())
    }

    /// A wrong configuration marker or surplus principal is not an X-CACHECONF entry.
    #[test]
    fn cache_rejects_malformed_config_principals() -> Result<(), Box<dyn Error>> {
        for components in [
            vec!["wrong", "key"],
            vec!["krb5_ccache_conf_data", "key", "one", "two"],
        ] {
            let client = CachePrincipal::new("EXAMPLE", 1, vec!["alice".to_owned()]);
            let mut cache = CCache::new(client.clone());
            cache.credentials_mut().push(Credential::new(
                client,
                CachePrincipal::new(
                    "X-CACHECONF:",
                    0,
                    components.into_iter().map(str::to_owned).collect(),
                ),
                CacheKey::new(0, Vec::new()),
                CredentialTimes::default(),
                [0; 4],
                vec![1],
            ));
            assert!(
                CCache::parse(&cache.to_bytes()?)?
                    .config_entries()
                    .is_empty(),
                "malformed config principal accepted"
            );
        }
        Ok(())
    }
}
