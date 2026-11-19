//! The keytab-store abstraction (MIT 1.22.2 `krb5_kt_ops`) with the file and
//! `MEMORY` keytab types (`src/lib/krb5/keytab/kt_file.c`, `kt_memory.c`).
//!
//! # Cancel safety
//!
//! The methods are synchronous: each finishes or fails before it returns.
//! File keytabs block on file locks held by other writers.

use alloc::{collections::BTreeMap, sync::Arc};
use core::fmt;
use std::{
    io,
    path::PathBuf,
    sync::{Mutex, MutexGuard, PoisonError},
};

use super::{EncryptionKey, Entry, Error, Keytab, Principal};
use crate::{
    extensions,
    file_name::{
        SecretBytes,
        locked::{self, Change},
    },
};

/// A keytab of some type (MIT `krb5_keytab`): the client keytab and the
/// acceptor keytabs are read through it.
///
/// # Security
///
/// Removed entries are dropped into their zeroizing key owners. File keytabs
/// are written owner-only and replaced atomically, and refuse symlinks and
/// files others may write.
pub trait KeyStore: fmt::Debug + Send + Sync {
    /// The full name, `TYPE:residual`.
    fn name(&self) -> String;

    /// All entries (MIT `krb5_kt_start_seq_get` and `krb5_kt_next_entry`).
    ///
    /// # Errors
    ///
    /// Storage and parse errors; a file keytab that does not exist is `Io`.
    fn load(&self) -> Result<Keytab, Error>;

    /// Add an entry (MIT `krb5_kt_add_entry`); a file keytab is created when
    /// absent.
    ///
    /// # Errors
    ///
    /// Storage and serialization errors.
    fn add(&self, entry: Entry) -> Result<(), Error>;

    /// Remove the entries of `principal` with `kvno` (0: any) and `etype`
    /// (`None`: any) (MIT `krb5_kt_remove_entry`). Returns how many.
    ///
    /// # Errors
    ///
    /// Storage and parse errors.
    fn remove(&self, principal: &Principal, kvno: u32, etype: Option<i32>) -> Result<usize, Error>;

    /// The newest key of `principal` with `kvno` (0: any) and `etype`, and its
    /// kvno (MIT `krb5_kt_get_entry`; [`Keytab::find_key`]).
    ///
    /// # Errors
    ///
    /// The errors of [`Self::load`] and [`Error::NoMatchingKey`].
    #[inline]
    fn find(
        &self,
        principal: &Principal,
        kvno: u32,
        etype: i32,
    ) -> Result<(EncryptionKey, u32), Error> {
        let keytab = self.load()?;
        let components: Vec<&str> = principal.components.iter().map(String::as_str).collect();
        let (key, found) = keytab.find_key(&components, &principal.realm, kvno, etype)?;
        Ok((key.clone(), found))
    }
}

/// A keytab type (MIT `krb5_kt_ops`): it resolves residuals to keytabs.
///
/// A store provider registered through [`crate::extensions::Registry`] offers
/// one for its prefix.
pub trait KeytabType: fmt::Debug + Send + Sync {
    /// The keytab a residual names (MIT `krb5_kt_resolve`).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidKeytabName`] for a residual this type does not accept;
    /// storage errors.
    fn resolve(&self, residual: &str) -> Result<Box<dyn KeyStore>, Error>;
}

/// The keytab `name` names when a store provider installed with
/// [`crate::extensions::Registry::install_stores`] claims its prefix.
///
/// # Errors
///
/// The errors of the provider's [`KeytabType::resolve`].
pub(crate) fn installed_keytab(name: &str) -> Result<Option<Box<dyn KeyStore>>, Error> {
    let Some((provider, residual)) = extensions::stores::installed(name) else {
        return Ok(None);
    };
    provider
        .keytab_type()
        .map(|keytabs| keytabs.resolve(residual))
        .transpose()
}

/// Remove matching entries from `keytab`; their keys are erased as they drop.
fn remove_entries(
    keytab: &mut Keytab,
    principal: &Principal,
    kvno: u32,
    etype: Option<i32>,
) -> usize {
    let before = keytab.entries.len();
    keytab.entries.retain(|entry| {
        entry.principal.realm != principal.realm
            || entry.principal.components != principal.components
            || (kvno != 0 && entry.kvno != kvno)
            || etype.is_some_and(|wanted| entry.key().etype() != wanted)
    });
    before.saturating_sub(keytab.entries.len())
}

/// The keytab store of a file keytab name: a bare path, `FILE:` or `WRFILE:`,
/// after `%{uid}` and `%{euid}` expansion (MIT `krb5_kt_resolve`).
///
/// # Errors
///
/// The errors of [`Keytab::file_path_from_keytab_name`].
#[inline]
pub fn resolve(name: &str) -> Result<Box<dyn KeyStore>, Error> {
    let path = Keytab::file_path_from_keytab_name(name)?;
    Ok(Box::new(FileKeytab {
        name: format!("FILE:{}", path.display()),
        path,
    }))
}

/// A file keytab.
#[derive(Debug)]
struct FileKeytab {
    /// The full name.
    name: String,
    /// The file.
    path: PathBuf,
}

impl FileKeytab {
    /// Change the keytab under the exclusive lock; an absent or zero-length
    /// file starts empty (the zero-length file another writer has just
    /// created and not yet locked included).
    ///
    /// # Errors
    ///
    /// Storage, parse and serialization errors.
    fn update<T>(&self, change: impl FnOnce(&mut Keytab) -> T) -> Result<T, Error> {
        locked::rewrite(&self.path, |current| {
            let mut keytab = current
                .filter(|bytes| !bytes.is_empty())
                .map_or_else(|| Ok(Keytab::new()), Keytab::parse)?;
            let result = change(&mut keytab);
            Ok((Change::Write(SecretBytes::new(keytab.to_bytes()?)), result))
        })
    }
}

impl KeyStore for FileKeytab {
    fn name(&self) -> String {
        self.name.clone()
    }

    fn load(&self) -> Result<Keytab, Error> {
        let bytes = locked::read_shared(&self.path)?
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "keytab file does not exist"))?;
        Keytab::parse(&bytes)
    }

    fn add(&self, entry: Entry) -> Result<(), Error> {
        self.update(|keytab| keytab.entries.push(entry))
    }

    fn remove(&self, principal: &Principal, kvno: u32, etype: Option<i32>) -> Result<usize, Error> {
        self.update(|keytab| remove_entries(keytab, principal, kvno, etype))
    }
}

/// The `MEMORY` keytab type: a table of named in-memory keytabs (MIT
/// `MEMORY:` keytabs, `kt_memory.c`).
///
/// [`Self::resolve`] creates an empty keytab under a new name, as MIT does.
/// Clones share the table; separate tables never see each other's keytabs,
/// where MIT keeps one table per process.
///
/// # Security
///
/// Keys live only in this process's memory; removed and destroyed entries
/// are erased when they drop.
#[derive(Clone, Default)]
pub struct MemoryKeytab {
    /// The keytabs by name.
    table: Arc<Mutex<BTreeMap<String, Keytab>>>,
}

impl MemoryKeytab {
    /// An empty table.
    #[must_use]
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    /// The keytab `name` (without the `MEMORY:` prefix), created empty when
    /// absent (MIT `mkt_resolve`).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidKeytabName`] for an empty name.
    #[inline]
    pub fn resolve(&self, name: &str) -> Result<Box<dyn KeyStore>, Error> {
        if name.is_empty() {
            return Err(Error::InvalidKeytabName);
        }
        let mut table = self.lock();
        let _: &mut Keytab = table.entry(name.to_owned()).or_default();
        drop(table);
        Ok(Box::new(MemoryEntry {
            table: self.clone(),
            name: name.to_owned(),
        }))
    }

    /// Remove the keytab `name` and erase its keys (MIT `krb5_kt_destroy`).
    /// Returns whether it existed.
    #[must_use]
    #[inline]
    pub fn destroy(&self, name: &str) -> bool {
        let mut table = self.lock();
        let removed = table.remove(name).is_some();
        drop(table);
        removed
    }

    /// The table, also after a panic in another thread.
    fn lock(&self) -> MutexGuard<'_, BTreeMap<String, Keytab>> {
        self.table.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl fmt::Debug for MemoryKeytab {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let table = self.lock();
        f.debug_tuple("MemoryKeytab")
            .field(&table.keys().collect::<Vec<_>>())
            .finish()
    }
}

/// One keytab of a [`MemoryKeytab`] table.
#[derive(Debug)]
struct MemoryEntry {
    /// The table holding it.
    table: MemoryKeytab,
    /// Its name.
    name: String,
}

impl MemoryEntry {
    /// Run `change` on the keytab, recreating it when it was destroyed.
    fn update<T>(&self, change: impl FnOnce(&mut Keytab) -> T) -> T {
        let mut table = self.table.lock();
        let result = change(table.entry(self.name.clone()).or_default());
        drop(table);
        result
    }
}

impl KeyStore for MemoryEntry {
    fn name(&self) -> String {
        format!("MEMORY:{}", self.name)
    }

    fn load(&self) -> Result<Keytab, Error> {
        Ok(self.update(|keytab| keytab.clone()))
    }

    fn add(&self, entry: Entry) -> Result<(), Error> {
        self.update(|keytab| keytab.entries.push(entry));
        Ok(())
    }

    fn remove(&self, principal: &Principal, kvno: u32, etype: Option<i32>) -> Result<usize, Error> {
        Ok(self.update(|keytab| remove_entries(keytab, principal, kvno, etype)))
    }
}
