//! Locked reads and atomic rewrites of credential files (`std::fs::File::lock`).
//!
//! Every writer takes an exclusive lock on the current file, re-checks that the
//! path still names the file it locked (another writer may have replaced it),
//! and publishes the new contents with [`super::write_private`] (a private
//! stage renamed over the path), so a reader never sees a partial file and two
//! writers that respect the lock never lose an update. A writer that finds no
//! file creates an empty owner-only one and locks it before it decides, so a
//! concurrent writer waits for it instead of also starting from nothing (MIT
//! creates absent keytabs and caches the same way, `kt_file.c:739-749`).
//! Readers take a shared lock. The locks are advisory `flock`-style locks on Unix and byte-range locks
//! on Windows; MIT krb5 uses `fcntl` record locks, which do not interact with
//! them on Linux, so MIT and this crate serialize only through the atomic
//! rename.

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
#[cfg(windows)]
use std::os::windows::fs::MetadataExt as _;
use std::{
    fs::{self, File, Metadata, OpenOptions},
    io::{self, Seek as _, SeekFrom, Write as _},
    path::Path,
};

use super::{SecretBytes, reject_symlink, write_private};

/// Creation serialization regressions.
#[cfg(test)]
#[path = "locked_tests.rs"]
mod creation_tests;

/// How often a lock is retaken when the path was replaced while waiting.
const ATTEMPTS: usize = 16;

/// What a rewrite does with the file.
pub(crate) enum Change {
    /// Publish these bytes atomically.
    Write(SecretBytes),
    /// Overwrite the file with zeros and remove it.
    Remove,
}

/// Read a credential file under a shared lock; `None` when it does not exist.
///
/// # Errors
/// Returns filesystem errors, `InvalidInput` for a symlink or a non-regular
/// file, and `PermissionDenied` for a file that others may write or (Linux)
/// that another user owns.
pub(crate) fn read_shared(path: &Path) -> io::Result<Option<SecretBytes>> {
    let Some(file) = open_shared(path)? else {
        return Ok(None);
    };
    read_all(&file).map(Some)
}

/// Rewrite a credential file under an exclusive lock.
///
/// `change` receives the current contents (`None` when the file does not
/// exist) and returns the new state and a result. An absent file is created
/// empty, owner-only and locked before `change` runs, and removed again when
/// `change` fails.
///
/// # Errors
/// Returns the errors of [`read_shared`], the creation error, the error of
/// `change` (or the error of removing the file this call created), and the
/// errors of the publication or removal.
pub(crate) fn rewrite<T, E, F>(path: &Path, change: F) -> Result<T, E>
where
    E: From<io::Error>,
    F: FnOnce(Option<&[u8]>) -> Result<(Change, T), E>,
{
    let (mut file, created) = open_for_rewrite(path)?;
    let current = if created {
        None
    } else {
        Some(read_all(&file)?)
    };
    let (next, result) = match change(current.as_deref().map(Vec::as_slice)) {
        Ok(outcome) => outcome,
        Err(error) => {
            if created {
                fs::remove_file(path)?;
            }
            return Err(error);
        }
    };
    match next {
        Change::Write(bytes) => write_private(path, &bytes)?,
        Change::Remove => {
            wipe(&mut file)?;
            fs::remove_file(path)?;
        }
    }
    drop(file);
    Ok(result)
}

/// Create a new empty private file; `AlreadyExists` when the name is taken.
///
/// # Errors
/// Returns the creation error.
pub(crate) fn create_empty(path: &Path) -> io::Result<()> {
    create_private(path)?.sync_all()
}

/// Create and open a new owner-only file for reading and writing;
/// `AlreadyExists` when the name is taken.
///
/// # Errors
/// Returns the creation error.
fn create_private(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    let _: &mut OpenOptions = options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        let _: &mut OpenOptions = options.mode(0o600);
    }
    options.open(path)
}

/// Open and share-lock the file the path names, retrying while it is being
/// replaced; `None` when it does not exist.
///
/// # Errors
/// Returns open, lock and trust errors.
fn open_shared(path: &Path) -> io::Result<Option<File>> {
    for _ in 0..ATTEMPTS {
        reject_symlink(path)?;
        let file = match OpenOptions::new().read(true).open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        if let Some(locked) = lock_current(path, file, false)? {
            return Ok(Some(locked));
        }
    }
    Err(still_changing())
}

/// Open and exclusively lock the file the path names, creating it empty and
/// owner-only when absent, retrying while it is being replaced. Returns the
/// file and whether this call created it.
///
/// # Errors
/// Returns open, creation, lock and trust errors.
fn open_for_rewrite(path: &Path) -> io::Result<(File, bool)> {
    for _ in 0..ATTEMPTS {
        reject_symlink(path)?;
        let (file, created) = match OpenOptions::new().read(true).write(true).open(path) {
            Ok(file) => (file, false),
            Err(absent) if absent.kind() == io::ErrorKind::NotFound => match create_private(path) {
                Ok(file) => (file, true),
                Err(taken) if taken.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(failure) => return Err(failure),
            },
            Err(error) => return Err(error),
        };
        if let Some(locked) = lock_current(path, file, true)? {
            return Ok((locked, created));
        }
    }
    Err(still_changing())
}

/// Check and lock `file`, and keep it only while the path still names it.
///
/// # Errors
/// Returns metadata, trust and lock errors.
fn lock_current(path: &Path, file: File, exclusive: bool) -> io::Result<Option<File>> {
    let locked = file.metadata()?;
    check_trusted(&locked)?;
    if exclusive {
        file.lock()?;
    } else {
        file.lock_shared()?;
    }
    match fs::symlink_metadata(path) {
        Ok(current) if same_file(&locked, &current) => Ok(Some(file)),
        Ok(_) => Ok(None),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

/// The error of a path that kept naming another file after every lock.
fn still_changing() -> io::Error {
    io::Error::other("credential file kept changing while it was locked")
}

/// Refuse a file that is not regular, that others may write, or (Linux) that
/// another user owns.
///
/// # Errors
/// Returns `InvalidInput` or `PermissionDenied`.
fn check_trusted(metadata: &Metadata) -> io::Result<()> {
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "credential file is not a regular file",
        ));
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o022 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "credential file is writable by group or others",
        ));
    }
    #[cfg(target_os = "linux")]
    {
        let (_, effective) = super::process_identity()
            .map_err(|_unavailable| io::Error::other("process identity is unavailable"))?;
        if metadata.uid() != effective {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "credential file is owned by another user",
            ));
        }
    }
    Ok(())
}

/// Whether two metadata records describe the same file.
#[cfg(unix)]
fn same_file(left: &Metadata, right: &Metadata) -> bool {
    left.dev() == right.dev() && left.ino() == right.ino()
}

/// Whether two metadata records describe the same file: Windows offers no
/// stable file index in `std`, so creation time, write time and size stand in.
#[cfg(windows)]
fn same_file(left: &Metadata, right: &Metadata) -> bool {
    left.creation_time() == right.creation_time()
        && left.last_write_time() == right.last_write_time()
        && left.file_size() == right.file_size()
}

/// Platforms without file identities trust the path.
#[cfg(not(any(unix, windows)))]
const fn same_file(_left: &Metadata, _right: &Metadata) -> bool {
    true
}

/// Read a locked file into erased storage.
///
/// # Errors
/// Returns the read error.
fn read_all(mut file: &File) -> io::Result<SecretBytes> {
    let mut bytes = SecretBytes::new(Vec::new());
    let _: u64 = io::copy(&mut file, &mut *bytes)?;
    Ok(bytes)
}

/// Overwrite a locked file with zeros before it is removed (MIT `fcc_destroy`).
///
/// # Errors
/// Returns the write error.
fn wipe(file: &mut File) -> io::Result<()> {
    let zeros = [0_u8; 4096];
    let mut left = file.metadata()?.len();
    let _: u64 = file.seek(SeekFrom::Start(0))?;
    while left > 0 {
        let step = left.min(4096);
        let Some(chunk) = zeros.get(..usize::try_from(step).map_err(io::Error::other)?) else {
            break;
        };
        file.write_all(chunk)?;
        left = left.saturating_sub(step);
    }
    file.sync_all()
}
