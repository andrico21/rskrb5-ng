use core::{
    mem,
    ops::{Deref, DerefMut},
};
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::{
    fs::{self, OpenOptions},
    io::{self, Write as _},
    path::{Path, PathBuf},
};

use zeroize::{Zeroize as _, Zeroizing};

#[cfg(test)]
#[path = "file_name/mutation_tests.rs"]
mod mutation_tests;

/// Internal credential bytes with erasure attached to their lifetime.
pub(crate) struct SecretBytes(Zeroizing<Vec<u8>>);

impl SecretBytes {
    /// Adopt an allocation without copying its contents.
    pub(crate) fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Transfer raw exported bytes to the caller's cleanup responsibility.
    pub(crate) fn into_vec(mut self) -> Vec<u8> {
        mem::take(&mut *self.0)
    }
}

impl Deref for SecretBytes {
    type Target = Vec<u8>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for SecretBytes {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

// Drop audit: live-slice erasure is in-place, nonblocking and infallible;
// test-only observation inspects live storage before the allocation is released.
impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.0.as_mut_slice().zeroize();
        #[cfg(test)]
        {
            assert!(self.0.iter().all(|byte| *byte == 0));
            tests::ERASED_BYTES.with(|count| count.set(count.get().saturating_add(self.0.len())));
            tests::ERASED_LENGTHS.with(|lengths| lengths.borrow_mut().push(self.0.len()));
        }
    }
}

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
pub(crate) mod tests {
    use core::{
        cell::{Cell, RefCell},
        error::Error as StdError,
    };
    use std::{
        env, fs,
        io::{self, Write as _},
        sync::{Barrier, BarrierWaitResult},
        thread,
        time::{SystemTime, UNIX_EPOCH},
    };

    use crate::{
        ccache::{CCache, Principal as CachePrincipal},
        error::Keytab as KeytabError,
        keytab::{EncryptionKey, Entry, Keytab, Principal},
    };

    std::thread_local! {
        pub(super) static ERASED_BYTES: Cell<usize> = const { Cell::new(0) };
        pub(super) static ERASED_LENGTHS: RefCell<Vec<usize>> = const { RefCell::new(Vec::new()) };
    }

    /// Secret serialization must fit the allocation acquired before copying bytes.
    pub(crate) fn assert_capacity(capacity: usize, length: usize) {
        assert!(
            capacity >= length,
            "secret serialization grew: {capacity} < {length}"
        );
    }

    /// File reads and save serialization erase internal credential allocations.
    #[test]
    fn credential_file_buffers_are_erased() -> Result<(), Box<dyn StdError>> {
        // Given real cache/keytab file operations and an erasure counter.
        let directory = env::temp_dir().join(format!(
            "file-erasure-{}",
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
        ));
        fs::create_dir_all(&directory)?;
        let mut keytab = Keytab::new();
        keytab.entries_mut().push(Entry::new(
            Principal::new("REALM", 1, ["user"]),
            1,
            1,
            EncryptionKey::new(18, vec![7; 16]),
            1,
        ));
        let cache = CCache::new(CachePrincipal::new("REALM", 1, vec!["user".to_owned()]));
        let keytab_len = keytab.to_bytes()?.len();
        let cache_len = cache.to_bytes()?.len();
        for operation in 0_u8..4 {
            ERASED_LENGTHS.with(|lengths| lengths.borrow_mut().clear());
            // When persisting or reading one real format in isolation.
            match operation {
                0 => keytab.save(directory.join("keytab"))?,
                1 => drop(Keytab::load(directory.join("keytab"))?),
                2 => cache.save(directory.join("cache"))?,
                _ => drop(CCache::load(directory.join("cache"))?),
            }
            // Then that operation erases its complete file allocation.
            let expected = if operation < 2 { keytab_len } else { cache_len };
            assert!(
                ERASED_LENGTHS.with(|lengths| lengths.borrow().contains(&expected)),
                "operation {operation} did not erase its file buffer"
            );
        }
        fs::remove_dir_all(directory)?;
        Ok(())
    }

    /// Partial keytab output is erased when a later entry cannot serialize.
    #[test]
    fn partial_serialization_is_erased() -> Result<(), Box<dyn StdError>> {
        // Given one secret-bearing entry followed by an invalid entry.
        let mut keytab = Keytab::parse(&[5, 2])?;
        let entry = Entry::new(
            Principal::new("REALM", 1, ["user"]),
            1,
            1,
            EncryptionKey::new(18, vec![7; 16]),
            1,
        );
        keytab.entries_mut().push(entry.clone());
        let partial_len = keytab.to_bytes()?.len();
        let mut invalid = entry;
        invalid.key.etype = i32::MAX;
        keytab.entries_mut().push(invalid);
        ERASED_BYTES.with(|count| count.set(0));
        ERASED_LENGTHS.with(|lengths| lengths.borrow_mut().clear());

        // When serialization fails after writing the first entry.
        let result = keytab.to_bytes();

        // Then the partial secret output is erased on the error path.
        assert!(matches!(result, Err(KeytabError::LengthOverflow)));
        assert!(
            ERASED_LENGTHS.with(|lengths| lengths.borrow().contains(&partial_len)),
            "partial output was not erased"
        );
        Ok(())
    }

    /// Failed replacement preserves the destination and removes the stage.
    #[test]
    fn failed_private_rename_preserves_destination() -> Result<(), Box<dyn StdError>> {
        // Given a nonempty directory where a credential file should be.
        let directory = env::temp_dir().join(format!(
            "private-rename-{}",
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
        ));
        let destination = directory.join("keytab");
        fs::create_dir_all(&destination)?;
        fs::write(destination.join("keep"), b"existing")?;
        // When the real staged write cannot replace that directory.
        let result = super::write_private(&destination, b"secret");
        // Then the error is returned without damaging the existing destination.
        assert!(result.is_err());
        assert_eq!(fs::read(destination.join("keep"))?, b"existing");
        assert_eq!(fs::read_dir(&directory)?.count(), 1);
        fs::remove_dir_all(directory)?;
        Ok(())
    }

    /// A failing stage cleanup must preserve the original write error.
    #[test]
    fn failed_private_cleanup_preserves_primary_error() -> Result<(), Box<dyn StdError>> {
        // Given a directory stage: remove_file fails on every supported platform.
        let directory = env::temp_dir().join(format!(
            "private-cleanup-{}",
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
        ));
        fs::create_dir_all(&directory)?;
        // When cleanup also fails after an interrupted write.
        let result =
            super::finish_private_stage(Err(io::ErrorKind::Interrupted.into()), &directory);
        fs::remove_dir_all(directory)?;
        // Then the write error wins over the real filesystem cleanup error.
        assert_eq!(
            result.err().map(|error| error.kind()),
            Some(io::ErrorKind::Interrupted)
        );
        Ok(())
    }

    /// Concurrent initializers publish one complete primary without replacing it.
    #[test]
    fn concurrent_primary_initialization_agrees() -> Result<(), Box<dyn StdError>> {
        // Given two initializers released together against one absent primary.
        let directory = env::temp_dir().join(format!(
            "primary-race-{}",
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
        ));
        fs::create_dir_all(&directory)?;
        let path = directory.join("primary");
        let barrier = Barrier::new(2);
        // When both try to publish a complete primary.
        let results = thread::scope(|scope| {
            let first = scope.spawn(|| {
                let _: BarrierWaitResult = barrier.wait();
                super::create_primary(&path, b"tkt\n")
            });
            let second = scope.spawn(|| {
                let _: BarrierWaitResult = barrier.wait();
                super::create_primary(&path, b"tkt\n")
            });
            (first.join(), second.join())
        });
        // Then neither fails because another initializer won, and contents are complete.
        results.0.map_err(|_panic| "first initializer panicked")??;
        results
            .1
            .map_err(|_panic| "second initializer panicked")??;
        assert_eq!(fs::read(&path)?, b"tkt\n");
        fs::remove_dir_all(directory)?;
        Ok(())
    }

    /// Interrupted staging never publishes a partial primary and removes the private stage.
    #[test]
    fn primary_partial_stage_cannot_hide_concurrent_saved_cache() -> Result<(), Box<dyn StdError>> {
        use core::time::Duration;
        use std::sync::mpsc;

        use crate::ccache::{CCache, Principal};
        let directory = env::temp_dir().join(format!(
            "primary-overlap-{}",
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
        ));
        fs::create_dir_all(&directory)?;
        let path = directory.join("primary");
        let name = format!("DIR:{}", directory.display());
        let (ready_tx, ready_rx) = mpsc::channel();
        let (resume_tx, resume_rx) = mpsc::channel();
        let result = thread::scope(|scope| -> Result<(), Box<dyn StdError>> {
            let primary = &path;
            let writer = scope.spawn(move || {
                super::create_primary_with(primary, |file| {
                    file.write_all(b"t")?;
                    ready_tx.send(()).map_err(io::Error::other)?;
                    resume_rx
                        .recv_timeout(Duration::from_secs(10))
                        .map_err(io::Error::other)?;
                    Err(io::ErrorKind::Interrupted.into())
                })
            });
            ready_rx.recv_timeout(Duration::from_secs(10))?;
            let cache = CCache::new(Principal::new("R", 1, vec!["alice".to_owned()]));
            let saved = cache.save_name(&name);
            let resolved = CCache::file_path_from_cache_name(&name);
            resume_tx.send(())?;
            let failed = writer.join().map_err(|_panic| "writer panicked")?;
            assert_eq!(
                failed.err().map(|error| error.kind()),
                Some(io::ErrorKind::Interrupted)
            );
            saved?;
            assert_eq!(resolved?, directory.join("tkt"));
            assert_eq!(CCache::load_name(&name)?, cache);
            assert_eq!(fs::read(&path)?, b"tkt\n");
            assert_eq!(fs::read_dir(&directory)?.count(), 2);
            Ok(())
        });
        fs::remove_dir_all(directory)?;
        result
    }

    /// Interrupted staging never publishes a partial primary and removes the private stage.
    #[test]
    fn primary_partial_write_failure_cleans_stage() -> Result<(), Box<dyn StdError>> {
        // Given an absent primary and a writer that fails after one byte.
        let directory = env::temp_dir().join(format!(
            "primary-failure-{}",
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
        ));
        fs::create_dir_all(&directory)?;
        // When the real staged publication encounters the interrupted write.
        let result = super::create_primary_with(&directory.join("primary"), |file| {
            file.write_all(b"t")?;
            Err(io::ErrorKind::Interrupted.into())
        });
        // Then the causal error is returned and no partial public or private file remains.
        assert_eq!(
            result.err().map(|error| error.kind()),
            Some(io::ErrorKind::Interrupted)
        );
        assert_eq!(fs::read_dir(&directory)?.count(), 0);
        fs::remove_dir_all(directory)?;
        Ok(())
    }
}

/// Why a credential file name could not be resolved to a path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Error {
    /// The name, or the residual after its type prefix, is empty.
    Empty,
    /// Process identities are unavailable on this platform or from procfs.
    IdentityUnavailable,
    /// The name carries a type prefix that the caller does not accept.
    UnsupportedType {
        /// The rejected type prefix as written in the name.
        name_type: String,
    },
}

/// Resolve a `TYPE:residual` credential file name to a filesystem path.
///
/// A name without a type prefix, or one that looks like a Windows drive path
/// such as `C:\\krb5cc`, is taken as a path as written. Path tokens such as
/// `%{uid}` are expanded in the resulting path.
///
/// # Errors
///
/// Returns [`Error::Empty`] when `name` or its residual is empty, and
/// [`Error::UnsupportedType`] when the prefix is not one of `allowed_types`
/// (compared case-insensitively). [`Error::IdentityUnavailable`] means identity
/// tokens cannot read Linux procfs or are unsupported on this platform.
pub(crate) fn file_path_from_name(name: &str, allowed_types: &[&str]) -> Result<PathBuf, Error> {
    let path = literal_file_path(name, allowed_types)?;
    expand_path_tokens(&path.to_string_lossy()).map(PathBuf::from)
}

/// Interpret a resolved store name without rescanning replacement data.
///
/// # Errors
/// Rejects empty names and unsupported store prefixes.
pub(crate) fn literal_file_path(name: &str, allowed_types: &[&str]) -> Result<PathBuf, Error> {
    if name.is_empty() {
        return Err(Error::Empty);
    }

    let Some((prefix, path)) = name.split_once(':') else {
        return Ok(PathBuf::from(name));
    };

    if is_windows_drive_path(prefix, path) {
        return Ok(PathBuf::from(name));
    }

    if allowed_types
        .iter()
        .any(|allowed| prefix.eq_ignore_ascii_case(allowed))
    {
        if path.is_empty() {
            return Err(Error::Empty);
        }
        Ok(PathBuf::from(path))
    } else {
        Err(Error::UnsupportedType {
            name_type: prefix.to_owned(),
        })
    }
}

/// Whether `prefix:path` is a Windows drive path such as `C:\\krb5cc` rather
/// than a typed name.
fn is_windows_drive_path(prefix: &str, path: &str) -> bool {
    prefix.len() == 1
        && prefix
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphabetic)
        && (path.starts_with('\\') || path.starts_with('/'))
}

/// Expand the `%{uid}` and `%{euid}` tokens in a credential file path.
///
/// Linux reads real/effective identities from `/proc/self/status`. Other
/// platforms reject these tokens; no environment variable supplies identity.
///
/// # Errors
///
/// Returns [`Error::IdentityUnavailable`] when process identity cannot be read.
pub(crate) fn expand_path_tokens(value: &str) -> Result<String, Error> {
    if !value.contains("%{uid}") && !value.contains("%{euid}") {
        return Ok(value.to_owned());
    }
    let (real, effective) = process_identity()?;
    Ok(value
        .replace("%{uid}", &real.to_string())
        .replace("%{euid}", &effective.to_string()))
}

/// Real and effective Linux identities, without consulting ambient UID text.
///
/// # Errors
///
/// Returns [`Error::IdentityUnavailable`] for unsupported or unavailable procfs.
#[cfg(target_os = "linux")]
pub(crate) fn process_identity() -> Result<(u32, u32), Error> {
    let status =
        fs::read_to_string("/proc/self/status").map_err(|_io| Error::IdentityUnavailable)?;
    let mut ids = status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .ok_or(Error::IdentityUnavailable)?
        .split_whitespace();
    let real = ids
        .next()
        .ok_or(Error::IdentityUnavailable)?
        .parse()
        .map_err(|_parse| Error::IdentityUnavailable)?;
    let effective = ids
        .next()
        .ok_or(Error::IdentityUnavailable)?
        .parse()
        .map_err(|_parse| Error::IdentityUnavailable)?;
    Ok((real, effective))
}

/// Unsupported platforms cannot infer identities for token expansion.
///
/// # Errors
///
/// Always returns [`Error::IdentityUnavailable`].
#[cfg(not(target_os = "linux"))]
pub(crate) const fn process_identity() -> Result<(u32, u32), Error> {
    Err(Error::IdentityUnavailable)
}

/// Replace a credential file using an exclusively created same-directory stage.
///
/// Unix staging is owner-only before the first write and never widens the
/// destination's existing owner permissions. Windows callers must provide a
/// directory with an owner-only ACL; std does not expose ACL construction.
///
/// # Errors
///
/// Returns filesystem errors from staging, writing, syncing or renaming.
/// A Unix directory-sync error can occur after replacement has completed.
/// Cleanup failures never replace the original error.
pub(crate) fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    reject_symlink(path)?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut random = [0_u8; 16];
    getrandom::fill(&mut random).map_err(io::Error::other)?;
    let suffix = u128::from_be_bytes(random);
    let temporary = parent.join(format!(".rskrb5-{suffix:032x}.tmp"));
    let mut options = OpenOptions::new();
    let _: &mut OpenOptions = options.write(true).create_new(true);
    #[cfg(unix)]
    let _: &mut OpenOptions = options.mode(0o600);
    let mut file = options.open(&temporary)?;
    let result = (|| {
        #[cfg(unix)]
        if let Ok(metadata) = fs::metadata(path) {
            let mode = metadata.permissions().mode() & 0o600;
            file.set_permissions(fs::Permissions::from_mode(mode))?;
        }
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        reject_symlink(path)?;
        fs::rename(&temporary, path)?;
        Ok(())
    })();
    finish_private_stage(result, &temporary)?;
    #[cfg(unix)]
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}

/// Clean up a failed stage, preserving the primary error if removal also fails.
///
/// # Errors
/// Returns the original staging result, never a secondary cleanup error.
fn finish_private_stage(result: io::Result<()>, temporary: &Path) -> io::Result<()> {
    if result.is_err() {
        let _cleanup = fs::remove_file(temporary);
    }
    result
}

/// Reject only a final-component symlink; parent aliases remain supported.
///
/// # Errors
///
/// Returns `InvalidInput` for a symlink and propagates metadata errors except
/// an absent final entry, which is admissible for exclusive creation.
pub(crate) fn reject_symlink(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "credential destination is a symlink",
        )),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

/// Initialize a missing DIR primary without following or replacing an entry.
///
/// # Errors
///
/// Returns stage/write/sync or publication errors. An existing regular primary
/// wins without replacement; existing symlinks are rejected.
pub(crate) fn create_primary(path: &Path, bytes: &[u8]) -> io::Result<()> {
    create_primary_with(path, |file| file.write_all(bytes))
}

/// Stage a primary using the same fallible write boundary as production.
///
/// # Errors
/// Returns write, sync, publication or cleanup errors, preserving the write cause.
fn create_primary_with<F>(path: &Path, write: F) -> io::Result<()>
where
    F: FnOnce(&mut fs::File) -> io::Result<()>,
{
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let mut random = [0_u8; 16];
    getrandom::fill(&mut random).map_err(io::Error::other)?;
    let temporary = parent.join(format!(
        ".rskrb5-primary-{:032x}.tmp",
        u128::from_be_bytes(random)
    ));
    let mut options = OpenOptions::new();
    let _: &mut OpenOptions = options.write(true).create_new(true);
    #[cfg(unix)]
    let _: &mut OpenOptions = options.mode(0o600);
    let mut file = options.open(&temporary)?;
    let result = (|| {
        write(&mut file)?;
        file.sync_all()?;
        drop(file);
        match fs::hard_link(&temporary, path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => reject_symlink(path),
            Err(error) => Err(error),
        }
    })();
    let cleanup = fs::remove_file(&temporary);
    result?;
    cleanup?;
    #[cfg(unix)]
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}
