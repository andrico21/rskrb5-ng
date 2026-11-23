//! The `file2` store: MIT-format evidence in a shared, locked file.

use alloc::sync::Arc;
use std::{
    io::ErrorKind,
    path::{Path, PathBuf},
    time::UNIX_EPOCH,
};

use super::{
    Admission, Evidence, File2ReplayStore, OsFileSystem, Store, FileSystem, dfl, table,
};
use crate::error::Replay as Error;

/// MIT's size bound (`rc_file2.c:MAX_SIZE`, `INT32_MAX`).
const MAXIMUM_BYTES: u64 = 0x7fff_ffff;

impl File2ReplayStore {
    /// A store on `path`, created owner-only when absent.
    #[must_use]
    #[inline]
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            files: Arc::new(OsFileSystem),
            maximum_bytes: MAXIMUM_BYTES,
            private_file: false,
        }
    }

    /// MIT's `dfl` file, `krb5_<euid>.rcache2` in `KRB5RCACHEDIR`, `TMPDIR` or
    /// `/var/tmp`, opened with MIT's checks: not a symlink, owned by the
    /// effective user.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IdentityUnavailable`] when the user id cannot be read.
    #[inline]
    pub fn dfl() -> Result<Self, Error> {
        let mut store = Self::new(dfl::default_path()?);
        store.private_file = true;
        Ok(store)
    }

    /// Open the file through another [`FileSystem`], for fault injection.
    #[must_use]
    #[inline]
    pub fn with_file_system(mut self, files: Arc<dyn FileSystem>) -> Self {
        self.files = files;
        self
    }

    /// Refuse new evidence once the file would exceed `maximum_bytes`
    /// (default 2 GiB - 1, MIT's bound). Live evidence is never evicted: a
    /// full file returns [`Error::FileFull`].
    #[must_use]
    #[inline]
    pub const fn with_maximum_bytes(mut self, maximum_bytes: u64) -> Self {
        self.maximum_bytes = maximum_bytes;
        self
    }

    /// The cache file.
    #[must_use]
    #[inline]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Whole seconds since the Unix epoch as MIT's 32-bit timestamp; zero marks an
/// empty slot, so it is not a valid presentation time.
///
/// # Errors
///
/// Returns [`Error::TimeOutOfRange`] before the epoch, at zero or past 2106.
fn timestamp(evidence: &Evidence) -> Result<u32, Error> {
    let seconds = evidence
        .presented_at
        .duration_since(UNIX_EPOCH)
        .map_err(|_before_epoch| Error::TimeOutOfRange)?
        .as_secs();
    match u32::try_from(seconds) {
        Ok(0) | Err(_) => Err(Error::TimeOutOfRange),
        Ok(value) => Ok(value),
    }
}

impl Store for File2ReplayStore {
    #[inline]
    fn admit(&self, evidence: &Evidence) -> Result<Admission, Error> {
        let now = timestamp(evidence)?;
        let retention = u32::try_from(evidence.skew.saturating_mul(3).as_secs()).unwrap_or(u32::MAX);
        let mut file = self
            .files
            .open_locked(&self.path, self.private_file)
            .map_err(|source| match source.kind() {
                ErrorKind::InvalidInput | ErrorKind::PermissionDenied if self.private_file => {
                    Error::UnsafeFile {
                        path: self.path.clone(),
                        reason: "not a private regular file owned by this user",
                    }
                }
                ErrorKind::NotFound
                | ErrorKind::AlreadyExists
                | ErrorKind::InvalidInput
                | ErrorKind::PermissionDenied
                | ErrorKind::WouldBlock
                | ErrorKind::Interrupted
                | ErrorKind::OutOfMemory
                | ErrorKind::Unsupported
                | ErrorKind::Other
                | _ => Error::Io {
                    operation: "open",
                    path: self.path.clone(),
                    source,
                },
            })?;
        table::Run::new(&evidence.tag, &self.path)
            .at(now, retention)
            .bounded(self.maximum_bytes)
            .store(&mut *file)
    }
}
