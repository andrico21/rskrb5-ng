//! Proofs of the store rules todo 11 recorded (FU-STO-P02 and FU-STO-P04):
//! each trust check on its own, FILE unique-cache placement, DIR enumeration
//! order and skipped entries (supervisor validation of waves 0-2, y4 table).

/// Store trust and layout proofs.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::error;
    #[cfg(target_os = "linux")]
    use std::path::Path;
    use std::{
        env, fs,
        path::PathBuf,
        process,
        time::{SystemTime, UNIX_EPOCH},
    };

    use rskrb5_ng::ccache::{
        Principal, dir_store::DirStore, file_store::FileStore, stores::CredentialStore as _,
    };

    /// Error type of the `Result`-returning tests.
    type TestError = Box<dyn error::Error>;

    /// A fresh scratch directory.
    fn scratch(label: &str) -> Result<PathBuf, TestError> {
        let directory = env::temp_dir().join(format!(
            "store-proofs-{label}-{}-{}",
            process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
        ));
        fs::create_dir_all(&directory)?;
        Ok(directory)
    }

    /// A principal of `A.TEST`.
    fn principal(name: &str) -> Principal {
        Principal::new("A.TEST", 1, vec![name.to_owned()])
    }

    /// The last path component of a cache name.
    fn file_of(name: &str) -> Option<&str> {
        name.rsplit(['/', '\\']).next()
    }

    /// FU-STO-P04: `new_unique` of a FILE collection creates an empty
    /// owner-only `tkt` plus 16 hex digits file next to the cache file.
    #[test]
    fn file_unique_caches_are_placed_next_to_the_file() -> Result<(), TestError> {
        let directory = scratch("unique")?;
        let single =
            FileStore::default().collection(&directory.join("krb5cc").to_string_lossy())?;
        let unique = single.new_unique()?;
        let name = unique.name();
        let file = file_of(&name).ok_or("a file name")?;
        let digits = file.strip_prefix("tkt").ok_or("a tkt name")?;
        assert_eq!(digits.len(), 16, "{name}");
        assert!(
            digits.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "{name}"
        );
        assert_eq!(name, format!("FILE:{}", directory.join(file).display()));
        let created = fs::metadata(directory.join(file))?;
        assert_eq!(created.len(), 0);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(created.permissions().mode() & 0o777, 0o600);
        }
        fs::remove_dir_all(directory)?;
        Ok(())
    }

    /// FU-STO-P04: a DIR collection lists the primary, then the other `tkt*`
    /// regular files in name order, whatever their creation order, and skips
    /// files without the `tkt` prefix and symlinks.
    #[test]
    fn dir_enumeration_order_and_skipped_entries() -> Result<(), TestError> {
        let directory = scratch("order")?;
        let collection = DirStore::default().collection(&directory.to_string_lossy())?;
        let store = DirStore::default();
        for (file, name) in [("tktc", "carol"), ("tkta", "alice"), ("tktb", "bob")] {
            store
                .resolve(&format!(":{}", directory.join(file).display()))?
                .initialize(&principal(name))?;
        }
        collection.switch(&*store.resolve(&format!(":{}", directory.join("tktb").display()))?)?;
        fs::write(directory.join("other"), b"not a cache")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            symlink(directory.join("tkta"), directory.join("tktz"))?;
        }
        let listed: Vec<String> = collection
            .caches()?
            .map(|cache| file_of(&cache.name()).unwrap_or_default().to_owned())
            .collect();
        assert_eq!(listed, ["tktb", "tkta", "tktc"]);
        fs::remove_dir_all(directory)?;
        Ok(())
    }

    /// FU-STO-P02: each trust check refuses on its own.
    ///
    /// For reading and writing caches and keytabs: write permission for the
    /// group only, for others only, a path that is not a regular file and
    /// (Linux) a file of another user.
    #[cfg(unix)]
    #[test]
    fn every_trust_check_refuses_on_its_own() -> Result<(), TestError> {
        use std::{io, os::unix::fs::PermissionsExt as _};

        use rskrb5_ng::{
            error::{Ccache as CacheError, Keytab as KeytabError},
            keytab::{self, stores as keytab_stores},
        };

        /// The kind of an I/O refusal from either store.
        fn kind<T>(cache: Result<T, CacheError>) -> Option<io::ErrorKind> {
            match cache {
                Err(CacheError::Io(error)) => Some(error.kind()),
                _ => None,
            }
        }
        /// The kind of an I/O refusal of a keytab store.
        fn keytab_kind<T>(result: Result<T, KeytabError>) -> Option<io::ErrorKind> {
            match result {
                Err(KeytabError::Io(error)) => Some(error.kind()),
                _ => None,
            }
        }

        let directory = scratch("trust")?;
        let path = directory.join("cache");
        let cache = FileStore::default().resolve(&path.to_string_lossy())?;
        cache.initialize(&principal("alice"))?;
        let keytab_path = directory.join("keytab");
        let keytab = keytab_stores::resolve(&keytab_path.to_string_lossy())?;
        keytab.add(keytab::Entry::new(
            keytab::Principal::new("A.TEST", 1, ["alice"]),
            1,
            1,
            keytab::EncryptionKey::new(18, vec![1; 32]),
            1,
        ))?;
        for mode in [0o620, 0o602] {
            for file in [&path, &keytab_path] {
                fs::set_permissions(file, fs::Permissions::from_mode(mode))?;
            }
            let denied = Some(io::ErrorKind::PermissionDenied);
            assert_eq!(kind(cache.load()), denied, "{mode:o} cache read");
            assert_eq!(
                kind(cache.initialize(&principal("bob"))),
                denied,
                "{mode:o} cache write"
            );
            assert_eq!(keytab_kind(keytab.load()), denied, "{mode:o} keytab read");
            let removed = keytab.remove(&keytab::Principal::new("A.TEST", 1, ["alice"]), 0, None);
            assert_eq!(keytab_kind(removed), denied, "{mode:o} keytab write");
            for file in [&path, &keytab_path] {
                fs::set_permissions(file, fs::Permissions::from_mode(0o600))?;
            }
        }
        let not_regular = directory.join("subdirectory");
        fs::create_dir_all(&not_regular)?;
        let invalid = Some(io::ErrorKind::InvalidInput);
        let at_directory = FileStore::default().resolve(&not_regular.to_string_lossy())?;
        assert_eq!(kind(at_directory.load()), invalid, "cache read");
        assert_eq!(
            kind(at_directory.initialize(&principal("bob"))),
            invalid,
            "cache write"
        );
        let keytab_at_directory = keytab_stores::resolve(&not_regular.to_string_lossy())?;
        assert_eq!(
            keytab_kind(keytab_at_directory.load()),
            invalid,
            "keytab read"
        );
        #[cfg(target_os = "linux")]
        {
            let foreign = foreign_file(&directory)?;
            let denied = Some(io::ErrorKind::PermissionDenied);
            let owned = FileStore::default().resolve(&foreign.to_string_lossy())?;
            assert_eq!(kind(owned.load()), denied, "{}", foreign.display());
            assert_eq!(
                keytab_kind(keytab_stores::resolve(&foreign.to_string_lossy())?.load()),
                denied,
                "{}",
                foreign.display()
            );
        }
        fs::remove_dir_all(directory)?;
        Ok(())
    }

    /// A regular, owner-only-writable file that another user owns: a file of
    /// root, or (when the test runs as root) a file given to `nobody`.
    #[cfg(target_os = "linux")]
    fn foreign_file(directory: &Path) -> Result<PathBuf, TestError> {
        let status = fs::read_to_string("/proc/self/status")?;
        let effective = status
            .lines()
            .find_map(|line| line.strip_prefix("Uid:"))
            .and_then(|ids| ids.split_whitespace().nth(1))
            .ok_or("the effective uid")?;
        if effective != "0" {
            return Ok(PathBuf::from("/etc/passwd"));
        }
        let path = directory.join("foreign");
        fs::write(&path, b"")?;
        let changed = process::Command::new("chown")
            .args(["65534"])
            .arg(&path)
            .status()?;
        if changed.success() {
            Ok(path)
        } else {
            Err(format!("chown 65534 {}: {changed}", path.display()).into())
        }
    }
}
