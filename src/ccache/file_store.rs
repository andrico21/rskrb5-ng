//! The `FILE` cache type and the cache file handle `DIR` shares (MIT 1.22.2
//! `src/lib/krb5/ccache/cc_file.c`), and the built-in file name resolution.

use std::path::{Path, PathBuf};

use super::{
    CCache, Credential, Error, Principal,
    dir_store::{DirStore, create_unique},
    direct_file_path_from_cache_name, file_name_error, is_config_credential,
    stores::{CacheCollection, CacheCursor, CacheHandle, CacheVersion, CredentialStore},
};
use crate::file_name::{
    self, SecretBytes,
    locked::{self, Change},
};

/// The `FILE` cache type: one cache per file.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FileStore {
    /// The format version of new and replaced caches.
    version: CacheVersion,
}

impl FileStore {
    /// A store that writes new and replaced caches in `version`.
    #[must_use]
    #[inline]
    pub const fn new(version: CacheVersion) -> Self {
        Self { version }
    }

    /// The cache a residual path names.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidCacheName`] for an empty residual.
    fn file(self, residual: &str) -> Result<FileCache, Error> {
        if residual.is_empty() {
            return Err(Error::InvalidCacheName);
        }
        Ok(FileCache {
            name: format!("FILE:{residual}"),
            path: PathBuf::from(residual),
            version: self.version,
        })
    }
}

impl CredentialStore for FileStore {
    #[inline]
    fn cache_type(&self) -> &'static str {
        "FILE"
    }

    #[inline]
    fn resolve(&self, residual: &str) -> Result<Box<dyn CacheHandle>, Error> {
        Ok(Box::new(self.file(residual)?))
    }

    #[inline]
    fn collection(&self, residual: &str) -> Result<Box<dyn CacheCollection>, Error> {
        Ok(Box::new(Single(self.file(residual)?)))
    }
}

/// The handle of a built-in file cache name: a bare path, `FILE:`, `WRFILE:`,
/// `DIR:directory` (its primary cache) or `DIR::path`, after `%{uid}` and
/// `%{euid}` expansion.
///
/// # Errors
///
/// [`Error::UnsupportedCacheType`] for any other type, the name errors of
/// [`super::CacheName::parse`], and the errors of [`CredentialStore::resolve`].
#[inline]
pub fn resolve(name: &str, version: CacheVersion) -> Result<Box<dyn CacheHandle>, Error> {
    let expanded = file_name::expand_path_tokens(name).map_err(file_name_error)?;
    match expanded.split_once(':') {
        Some((prefix, residual)) if prefix.eq_ignore_ascii_case("DIR") => {
            DirStore::new(version).resolve(residual)
        }
        _ => FileStore::new(version)
            .resolve(&direct_file_path_from_cache_name(&expanded)?.to_string_lossy()),
    }
}

/// The collection of a built-in file cache name, as [`resolve`] reads it.
///
/// # Errors
///
/// The errors of [`resolve`].
#[inline]
pub fn collection(name: &str, version: CacheVersion) -> Result<Box<dyn CacheCollection>, Error> {
    let expanded = file_name::expand_path_tokens(name).map_err(file_name_error)?;
    match expanded.split_once(':') {
        Some((prefix, residual)) if prefix.eq_ignore_ascii_case("DIR") => {
            DirStore::new(version).collection(residual)
        }
        _ => FileStore::new(version)
            .collection(&direct_file_path_from_cache_name(&expanded)?.to_string_lossy()),
    }
}

/// One cache file (`FILE:path` or `DIR::path`).
#[derive(Clone, Debug)]
pub(super) struct FileCache {
    /// The full name.
    name: String,
    /// The file.
    path: PathBuf,
    /// The format version of new and replaced caches.
    version: CacheVersion,
}

impl FileCache {
    /// A cache file handle.
    pub(super) const fn new(name: String, path: PathBuf, version: CacheVersion) -> Self {
        Self {
            name,
            path,
            version,
        }
    }

    /// Publish `cache` in this store's version.
    ///
    /// # Errors
    ///
    /// Serialization and storage errors.
    fn write(&self, mut cache: CCache) -> Result<(), Error> {
        cache.set_version(self.version);
        let bytes = SecretBytes::new(cache.to_bytes()?);
        locked::rewrite(&self.path, |_current| {
            Ok::<_, Error>((Change::Write(bytes), ()))
        })
    }

    /// Change an initialized cache under the exclusive lock, keeping its version.
    ///
    /// # Errors
    ///
    /// [`Error::CacheNotFound`] for an uninitialized cache; storage errors.
    fn update<T>(&self, change: impl FnOnce(&mut CCache) -> T) -> Result<T, Error> {
        locked::rewrite(&self.path, |current| {
            let mut cache = self.parse(current)?;
            let result = change(&mut cache);
            Ok((Change::Write(SecretBytes::new(cache.to_bytes()?)), result))
        })
    }

    /// Parse file contents; an absent or empty file is not initialized.
    ///
    /// # Errors
    ///
    /// [`Error::CacheNotFound`] and the errors of [`CCache::parse`].
    fn parse(&self, contents: Option<&[u8]>) -> Result<CCache, Error> {
        match contents {
            Some(bytes) if !bytes.is_empty() => CCache::parse(bytes),
            _ => Err(Error::CacheNotFound {
                name: self.name.clone(),
            }),
        }
    }
}

impl CacheHandle for FileCache {
    fn name(&self) -> String {
        self.name.clone()
    }

    fn load(&self) -> Result<CCache, Error> {
        let bytes = locked::read_shared(&self.path)?;
        self.parse(bytes.as_deref().map(Vec::as_slice))
    }

    fn initialize(&self, principal: &Principal) -> Result<(), Error> {
        self.write(CCache::new(principal.clone()))
    }

    fn replace(&self, cache: &CCache) -> Result<(), Error> {
        self.write(cache.clone())
    }

    fn store(&self, credential: Credential) -> Result<(), Error> {
        self.update(|cache| drop(cache.upsert_credential(credential)))
    }

    fn remove(&self, server: &Principal) -> Result<usize, Error> {
        self.update(|cache| remove_server(cache, server))
    }

    fn destroy(&self) -> Result<(), Error> {
        locked::rewrite(&self.path, |current| match current {
            Some(_) => Ok((Change::Remove, ())),
            None => Err(Error::CacheNotFound {
                name: self.name.clone(),
            }),
        })
    }
}

/// Remove the non-configuration credentials for `server`; their payloads are
/// erased when they drop.
pub(super) fn remove_server(cache: &mut CCache, server: &Principal) -> usize {
    let before = cache.credentials.len();
    cache.credentials.retain(|credential| {
        is_config_credential(credential)
            || credential.server.realm != server.realm
            || credential.server.components != server.components
    });
    before.saturating_sub(cache.credentials.len())
}

/// A collection of one cache: a `FILE` cache or a `DIR::path` subsidiary.
#[derive(Clone, Debug)]
pub(super) struct Single(FileCache);

impl Single {
    /// The collection of one cache.
    pub(super) const fn new(cache: FileCache) -> Self {
        Self(cache)
    }
}

impl CacheCollection for Single {
    fn name(&self) -> String {
        self.0.name.clone()
    }

    fn caches(&self) -> Result<CacheCursor, Error> {
        let present = self.0.path.try_exists()?;
        Ok(CacheCursor::new(if present {
            vec![Box::new(self.0.clone())]
        } else {
            Vec::new()
        }))
    }

    fn primary(&self) -> Result<Box<dyn CacheHandle>, Error> {
        Ok(Box::new(self.0.clone()))
    }

    /// Switching to the one cache changes nothing (MIT has no `switch_to` for
    /// `FILE`, `ccfns.c:295-300`); any other cache is refused.
    fn switch(&self, cache: &dyn CacheHandle) -> Result<(), Error> {
        if cache.name() == self.0.name {
            Ok(())
        } else {
            Err(Error::OutsideCollection {
                name: cache.name(),
                collection: self.name(),
            })
        }
    }

    /// A new `tkt*` cache next to the one cache.
    fn new_unique(&self) -> Result<Box<dyn CacheHandle>, Error> {
        let directory = self
            .0
            .path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let path = create_unique(directory)?;
        let prefix = self.0.name.split_once(':').map_or("FILE", |(kind, _)| kind);
        let name = if prefix.eq_ignore_ascii_case("DIR") {
            format!("DIR::{}", path.display())
        } else {
            format!("FILE:{}", path.display())
        };
        Ok(Box::new(FileCache {
            name,
            path,
            version: self.0.version,
        }))
    }
}
