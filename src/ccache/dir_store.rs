//! The `DIR` cache type: collections of `tkt*` caches with a `primary` pointer
//! (MIT 1.22.2 `src/lib/krb5/ccache/cc_dir.c`).

use core::str;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;
use std::{
    fs::{self, DirBuilder, File},
    io::{self, Read as _},
    path::{Path, PathBuf},
};

use super::{
    DIR_DEFAULT_PRIMARY_CACHE, DIR_PRIMARY_FILE, Error,
    file_store::{FileCache, Single},
    parse_dir_primary_name,
    stores::{CacheCollection, CacheCursor, CacheHandle, CacheVersion, CredentialStore},
    validate_dir_subsidiary_path,
};
use crate::file_name::{self, locked};

/// The longest `primary` line MIT reads, newline included (`fgets` into a
/// 64-byte buffer, `cc_dir.c:150-166`).
const MAX_PRIMARY_LINE: usize = 63;
/// How often a unique name is drawn before giving up.
const UNIQUE_ATTEMPTS: usize = 16;

/// The `DIR` cache type: a directory of `tkt*` caches with a `primary` pointer.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DirStore {
    /// The format version of new and replaced caches.
    version: CacheVersion,
}

impl DirStore {
    /// A store that writes new and replaced caches in `version`.
    #[must_use]
    #[inline]
    pub const fn new(version: CacheVersion) -> Self {
        Self { version }
    }

    /// A subsidiary `tkt*` cache whose directory is verified (MIT `verify_dir`).
    ///
    /// # Errors
    ///
    /// The errors of [`validate_dir_subsidiary_path`] and [`verify_dir`].
    fn subsidiary(self, path: &str) -> Result<FileCache, Error> {
        let file = validate_dir_subsidiary_path(path)?;
        if let Some(parent) = file.parent() {
            verify_dir(parent)?;
        }
        Ok(FileCache::new(format!("DIR::{path}"), file, self.version))
    }

    /// A collection directory, created owner-only when absent.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidCacheName`] for an empty residual and the errors of
    /// [`verify_dir`].
    fn directory(self, residual: &str) -> Result<DirCollection, Error> {
        if residual.is_empty() {
            return Err(Error::InvalidCacheName);
        }
        let directory = PathBuf::from(residual);
        verify_dir(&directory)?;
        Ok(DirCollection {
            directory,
            version: self.version,
        })
    }
}

impl CredentialStore for DirStore {
    #[inline]
    fn cache_type(&self) -> &'static str {
        "DIR"
    }

    /// `:path` names a subsidiary cache; any other residual names a
    /// collection directory and resolves to its primary cache.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidCacheName`] for an empty or malformed residual; `Io`
    /// for a directory that cannot be created or is open to others.
    #[inline]
    fn resolve(&self, residual: &str) -> Result<Box<dyn CacheHandle>, Error> {
        match residual.strip_prefix(':') {
            Some(path) => Ok(Box::new(self.subsidiary(path)?)),
            None => self.directory(residual)?.primary(),
        }
    }

    /// A subsidiary name is a collection of that one cache, as in MIT
    /// (`cc_dir.c:589-597`).
    ///
    /// # Errors
    ///
    /// The errors of [`Self::resolve`].
    #[inline]
    fn collection(&self, residual: &str) -> Result<Box<dyn CacheCollection>, Error> {
        match residual.strip_prefix(':') {
            Some(path) => Ok(Box::new(Single::new(self.subsidiary(path)?))),
            None => Ok(Box::new(self.directory(residual)?)),
        }
    }
}
/// A `DIR` collection.
#[derive(Clone, Debug)]
struct DirCollection {
    /// The collection directory.
    directory: PathBuf,
    /// The format version of new and replaced caches.
    version: CacheVersion,
}

impl DirCollection {
    /// The subsidiary cache `file` of this directory.
    fn cache(&self, file: &str) -> FileCache {
        let path = self.directory.join(file);
        FileCache::new(format!("DIR::{}", path.display()), path, self.version)
    }

    /// The primary file name, `None` when the pointer file does not exist.
    ///
    /// # Errors
    ///
    /// The errors of [`read_primary`].
    fn primary_name(&self) -> Result<Option<String>, Error> {
        read_primary(&self.directory.join(DIR_PRIMARY_FILE))
    }
}

impl CacheCollection for DirCollection {
    fn name(&self) -> String {
        format!("DIR:{}", self.directory.display())
    }

    /// The primary cache when it exists, then every other `tkt*` regular file
    /// in name order; a malformed pointer lists the files only (MIT
    /// `dcc_ptcursor_new` ignores it, `cc_dir.c:608-612`). Nothing is written.
    fn caches(&self) -> Result<CacheCursor, Error> {
        let primary = self.primary_name().ok().flatten();
        let mut names = Vec::new();
        for item in fs::read_dir(&self.directory)? {
            let entry = item?;
            let Ok(file) = entry.file_name().into_string() else {
                continue;
            };
            let kind = entry.file_type()?;
            if file.starts_with(DIR_DEFAULT_PRIMARY_CACHE)
                && !kind.is_dir()
                && !kind.is_symlink()
                && primary.as_deref() != Some(file.as_str())
            {
                names.push(file);
            }
        }
        names.sort_unstable();
        let mut caches: Vec<Box<dyn CacheHandle>> = Vec::new();
        if let Some(file) = primary.filter(|file| self.directory.join(file).is_file()) {
            caches.push(Box::new(self.cache(&file)));
        }
        caches.extend(
            names
                .iter()
                .map(|file| -> Box<dyn CacheHandle> { Box::new(self.cache(file)) }),
        );
        Ok(CacheCursor::new(caches))
    }

    /// The cache the `primary` file names; an absent pointer is created naming
    /// `tkt` (MIT `dcc_resolve`, `cc_dir.c:358-368`).
    fn primary(&self) -> Result<Box<dyn CacheHandle>, Error> {
        if let Some(file) = self.primary_name()? {
            return Ok(Box::new(self.cache(&file)));
        }
        let pointer = self.directory.join(DIR_PRIMARY_FILE);
        file_name::create_primary(
            &pointer,
            format!("{DIR_DEFAULT_PRIMARY_CACHE}\n").as_bytes(),
        )?;
        let file = read_primary(&pointer)?.ok_or(Error::InvalidCacheName)?;
        Ok(Box::new(self.cache(&file)))
    }

    /// Point `primary` at `cache`, which must be a `DIR::` cache directly
    /// inside this directory (MIT `dcc_switch_to`, `cc_dir.c:720-739`); the
    /// pointer is replaced atomically.
    fn switch(&self, cache: &dyn CacheHandle) -> Result<(), Error> {
        let name = cache.name();
        let outside = || Error::OutsideCollection {
            name: name.clone(),
            collection: self.name(),
        };
        let path = name
            .strip_prefix("DIR::")
            .and_then(|path| validate_dir_subsidiary_path(path).ok())
            .ok_or_else(outside)?;
        if path.parent() != Some(self.directory.as_path()) {
            return Err(outside());
        }
        let file = path
            .file_name()
            .and_then(|file| file.to_str())
            .filter(|file| file.len() < MAX_PRIMARY_LINE)
            .ok_or_else(outside)?;
        file_name::write_private(
            &self.directory.join(DIR_PRIMARY_FILE),
            format!("{file}\n").as_bytes(),
        )?;
        Ok(())
    }

    fn new_unique(&self) -> Result<Box<dyn CacheHandle>, Error> {
        let path = create_unique(&self.directory)?;
        Ok(Box::new(FileCache::new(
            format!("DIR::{}", path.display()),
            path,
            self.version,
        )))
    }
}

/// Read a collection's `primary` pointer: `None` when it does not exist.
///
/// At most one 63-byte line is read, as MIT does; the line must end in a
/// newline and name a `tkt*` file without a path separator.
///
/// # Errors
///
/// [`Error::InvalidCacheName`] for a malformed pointer, `Io` for a symlink or
/// a read failure.
pub(super) fn read_primary(pointer: &Path) -> Result<Option<String>, Error> {
    file_name::reject_symlink(pointer)?;
    let file = match File::open(pointer) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let mut line = Vec::new();
    let _: usize = file.take(64).read_to_end(&mut line)?;
    let end = line
        .iter()
        .position(|byte| *byte == b'\n')
        .filter(|end| *end < MAX_PRIMARY_LINE)
        .ok_or(Error::InvalidCacheName)?;
    let text = line.get(..=end).ok_or(Error::InvalidCacheName)?;
    parse_dir_primary_name(str::from_utf8(text).map_err(|_utf8| Error::InvalidCacheName)?).map(Some)
}

/// Verify a cache directory, creating it owner-only when absent (MIT
/// `verify_dir`, `cc_dir.c:204-224`). A directory that others may write is
/// refused unless it is sticky.
///
/// # Errors
///
/// `Io` for a path that is not a directory or is open to others, and for
/// creation and metadata failures.
fn verify_dir(directory: &Path) -> Result<(), Error> {
    let metadata = match fs::metadata(directory) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            #[cfg(unix)]
            let builder = {
                use std::os::unix::fs::DirBuilderExt as _;
                let mut owner_only = DirBuilder::new();
                let _: &mut DirBuilder = owner_only.mode(0o700);
                owner_only
            };
            #[cfg(not(unix))]
            let builder = DirBuilder::new();
            builder.create(directory)?;
            return Ok(());
        }
        Err(error) => return Err(error.into()),
    };
    if !metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "credential cache directory is not a directory",
        )
        .into());
    }
    #[cfg(unix)]
    {
        let mode = metadata.permissions().mode();
        if mode & 0o022 != 0 && mode & 0o1000 == 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "credential cache directory is writable by others and not sticky",
            )
            .into());
        }
    }
    Ok(())
}

/// Create an empty owner-only `tkt` + 16 hex digits file in `directory`.
///
/// # Errors
///
/// Randomness and creation errors.
pub(super) fn create_unique(directory: &Path) -> Result<PathBuf, Error> {
    for _ in 0..UNIQUE_ATTEMPTS {
        let mut random = [0_u8; 8];
        getrandom::fill(&mut random).map_err(io::Error::other)?;
        let path = directory.join(format!(
            "{DIR_DEFAULT_PRIMARY_CACHE}{:016x}",
            u64::from_be_bytes(random)
        ));
        match locked::create_empty(&path) {
            Ok(()) => return Ok(path),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
    }
    Err(io::Error::from(io::ErrorKind::AlreadyExists).into())
}
