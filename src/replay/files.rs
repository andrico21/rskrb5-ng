//! The operating-system [`FileSystem`]: a regular file under `File::lock`.

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::{
    fs::{File, OpenOptions, symlink_metadata},
    io::{self, Read as _, Seek as _, SeekFrom, Write as _},
    path::Path,
};

use super::{FileSystem, OpenFile, OsFileSystem};

/// An open cache file; dropping it closes the descriptor and releases the lock.
struct LockedFile {
    /// The file, exclusively locked.
    file: File,
}

impl FileSystem for OsFileSystem {
    #[inline]
    fn open_locked(&self, path: &Path, private_file: bool) -> io::Result<Box<dyn OpenFile>> {
        let mut options = OpenOptions::new();
        let _: &mut OpenOptions = options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        let _: &mut OpenOptions = options.mode(0o600);
        let file = options.open(path)?;
        if private_file {
            check_private(&file, path)?;
        }
        file.lock()?;
        Ok(Box::new(LockedFile { file }))
    }
}

/// MIT `dfl` safety (`rc_dfl.c:open_file`): the opened file is the regular
/// file at `path` (not a symlink swapped in after the open) and its owner is
/// the effective user.
///
/// # Errors
///
/// Returns `InvalidInput` for a symlink or a replaced file, `PermissionDenied`
/// for a foreign owner, and the I/O errors of the queries.
#[cfg(unix)]
fn check_private(file: &File, path: &Path) -> io::Result<()> {
    let opened = file.metadata()?;
    let named = symlink_metadata(path)?;
    if named.file_type().is_symlink() || !opened.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the replay cache file is a symlink or not a regular file",
        ));
    }
    if named.dev() != opened.dev() || named.ino() != opened.ino() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the replay cache file was replaced while it was opened",
        ));
    }
    let owner = super::dfl::effective_uid()
        .map_err(|_unavailable| io::Error::other("the effective user id is unavailable"))?;
    if opened.uid() != owner {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "the replay cache file is not owned by the effective user",
        ));
    }
    Ok(())
}

/// Windows has no owner check here; a symlink is still refused.
///
/// # Errors
///
/// Returns `InvalidInput` for a symlink and the I/O errors of the queries.
#[cfg(not(unix))]
fn check_private(file: &File, path: &Path) -> io::Result<()> {
    if symlink_metadata(path)?.file_type().is_symlink() || !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the replay cache file is a symlink or not a regular file",
        ));
    }
    Ok(())
}

impl OpenFile for LockedFile {
    #[inline]
    fn size(&mut self) -> io::Result<u64> {
        Ok(self.file.metadata()?.len())
    }

    #[inline]
    fn read_at(&mut self, offset: u64, buffer: &mut [u8]) -> io::Result<usize> {
        let _position: u64 = self.file.seek(SeekFrom::Start(offset))?;
        let mut filled = 0_usize;
        while let Some(rest) = buffer.get_mut(filled..).filter(|rest| !rest.is_empty()) {
            let count = self.file.read(rest)?;
            if count == 0 {
                break;
            }
            filled = filled.saturating_add(count);
        }
        Ok(filled)
    }

    #[inline]
    fn write_at(&mut self, offset: u64, data: &[u8]) -> io::Result<()> {
        let _position: u64 = self.file.seek(SeekFrom::Start(offset))?;
        self.file.write_all(data)
    }

    #[inline]
    fn sync(&mut self) -> io::Result<()> {
        self.file.sync_data()
    }
}
