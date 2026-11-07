//! Kerberos keytab parsing and serialization.
//!
//! MIT keytabs support long-term key lookup, password-derived entry generation,
//! file-name resolution, private persistence and redacted metadata.

use alloc::fmt;
use core::{
    mem,
    str::{self, FromStr},
    time::Duration,
};
use std::{
    env, fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;

/// Password ownership retained through derivation and every early error.
mod password;

#[cfg(feature = "messages")]
use crate::config::{LibDefaults, credential_names, parameters::DefaultName};
use crate::{crypto::selection, file_name};

/// First byte of every keytab file.
const KEYTAB_FIRST_BYTE: u8 = 5;
/// Environment variable naming the default keytab.
const KRB5_KTNAME_ENV: &str = "KRB5_KTNAME";

/// Parsed MIT-style keytab name.
///
/// `rskrb5-ng` supports file-backed keytabs only. The explicit name
/// type gives callers a validation point before attempting filesystem access.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Name {
    /// A file-backed keytab.
    File(PathBuf),
}

impl Name {
    /// Parse a MIT-style keytab name.
    ///
    /// Bare paths, `FILE:path`, and `WRFILE:path` are supported. Collection
    /// and platform stores such as `DIR:`, `KEYRING:`, and `MEMORY:` are
    /// rejected explicitly.
    ///
    /// # Errors
    ///
    /// Returns any error of [`Keytab::file_path_from_keytab_name`].
    #[inline]
    pub fn parse<P>(name: P) -> Result<Self, Error>
    where
        P: AsRef<str>,
    {
        Keytab::file_path_from_keytab_name(name.as_ref()).map(Self::File)
    }

    #[must_use]
    /// File path for this keytab name.
    #[inline]
    pub fn file_path(&self) -> &Path {
        match self {
            Self::File(path) => path,
        }
    }

    #[must_use]
    /// Consume this keytab name and return its file path.
    #[inline]
    pub fn into_file_path(self) -> PathBuf {
        match self {
            Self::File(path) => path,
        }
    }
}

impl FromStr for Name {
    type Err = Error;

    #[inline]
    fn from_str(name: &str) -> Result<Self, Self::Err> {
        Self::parse(name)
    }
}

/// Parsed keytab file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Keytab {
    /// File format version, 1 or 2.
    version: u8,
    /// Entries in file order.
    entries: Vec<Entry>,
}

impl Keytab {
    #[must_use]
    /// Create an empty version 2 keytab.
    #[inline]
    pub const fn new() -> Self {
        Self {
            version: 2,
            entries: Vec::new(),
        }
    }

    /// Load and parse a keytab file.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] when the file cannot be read, and any error of
    /// [`Keytab::parse`] for its contents.
    #[inline]
    pub fn load<P>(path: P) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        let bytes = file_name::SecretBytes::new(fs::read(path.as_ref())?);
        Self::parse(&bytes)
    }

    /// Load and parse the file keytab named by `KRB5_KTNAME`.
    ///
    /// # Ambient input
    /// Reads `KRB5_KTNAME`; use [`Keytab::load_name`] for an explicit name.
    ///
    /// Only file-backed keytab names are supported: bare paths, `FILE:path`,
    /// and `WRFILE:path`. Collection and platform stores such as `DIR:`,
    /// `KEYRING:`, and `MEMORY:` are rejected explicitly.
    ///
    /// # Errors
    ///
    /// Returns [`Error::DefaultKeytabName`] when `KRB5_KTNAME` is unset or not
    /// valid Unicode, and any error of [`Keytab::load_name`].
    #[inline]
    pub fn load_from_env() -> Result<Self, Error> {
        let name = env::var(KRB5_KTNAME_ENV).map_err(Error::DefaultKeytabName)?;
        Self::load_name(name)
    }

    /// Load and parse a keytab by MIT-style keytab name.
    ///
    /// Bare paths, `FILE:path`, and `WRFILE:path` are supported.
    ///
    /// # Errors
    ///
    /// Returns any error of [`Name::parse`] and [`Keytab::load`].
    #[inline]
    pub fn load_name<P>(name: P) -> Result<Self, Error>
    where
        P: AsRef<str>,
    {
        Self::load(Name::parse(name)?.into_file_path())
    }

    /// Parse keytab bytes.
    ///
    /// The borrowed input remains the caller's erasure responsibility.
    ///
    /// Entries with a negative length are holes left by deleted entries and
    /// are skipped; a zero length ends the entry list.
    ///
    /// # Errors
    ///
    /// Returns [`Error::TooShort`] for input shorter than two bytes,
    /// [`Error::InvalidFirstByte`] and [`Error::InvalidVersion`] for a bad
    /// file prefix, [`Error::Truncated`], [`Error::NegativeLength`] and
    /// [`Error::LengthOverflow`] for lengths and counts that do not fit the
    /// input, and [`Error::InvalidString`] for a principal string that is not
    /// UTF-8.
    #[inline]
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let [first_byte, version, ..] = *bytes else {
            return Err(Error::TooShort {
                actual: bytes.len(),
            });
        };
        if first_byte != KEYTAB_FIRST_BYTE {
            return Err(Error::InvalidFirstByte(first_byte));
        }
        if version != 1 && version != 2 {
            return Err(Error::InvalidVersion(version));
        }

        let endian = Endian::for_version(version);
        let mut offset = 2_usize;
        let mut entries = Vec::new();

        while offset < bytes.len() {
            let entry_len = read_i32(bytes, &mut offset, endian)?;
            if entry_len == 0_i32 {
                break;
            }
            if entry_len < 0_i32 {
                let skip = entry_len
                    .checked_abs()
                    .ok_or(Error::LengthOverflow)?
                    .try_into()
                    .map_err(|_out_of_range| Error::LengthOverflow)?;
                checked_advance(bytes, &mut offset, skip)?;
                continue;
            }

            let body_len =
                usize::try_from(entry_len).map_err(|_out_of_range| Error::LengthOverflow)?;
            let entry_bytes = read_bytes(bytes, &mut offset, body_len)?;
            let mut entry_offset = 0_usize;

            let principal = Principal::parse(entry_bytes, &mut entry_offset, version, endian)?;
            let timestamp = read_u32(entry_bytes, &mut entry_offset, endian)?;
            let kvno8 = read_u8(entry_bytes, &mut entry_offset)?;
            let etype = i32::from(read_i16(entry_bytes, &mut entry_offset, endian)?);
            let raw_key_len = read_i16(entry_bytes, &mut entry_offset, endian)?;
            let Ok(key_len) = usize::try_from(raw_key_len) else {
                return Err(Error::NegativeLength(raw_key_len.into()));
            };
            let key = EncryptionKey {
                etype,
                value: read_bytes(entry_bytes, &mut entry_offset, key_len)?.to_vec(),
            };

            let mut kvno = if entry_bytes.len().saturating_sub(entry_offset) >= 4 {
                read_u32(entry_bytes, &mut entry_offset, endian)?
            } else {
                kvno8.into()
            };
            if kvno == 0 {
                kvno = kvno8.into();
            }

            entries.push(Entry {
                principal,
                timestamp,
                kvno8,
                key,
                kvno,
            });
        }

        Ok(Self { version, entries })
    }

    /// Save this keytab to a file.
    ///
    /// Unix creation uses owner-only mode 0600 and existing owner rights are
    /// never widened. On Windows, supply a directory with an owner-only ACL.
    ///
    /// # Errors
    ///
    /// Returns any error of [`Keytab::to_bytes`], and [`Error::Io`] when the
    /// file cannot be written.
    #[inline]
    pub fn save<P>(&self, path: P) -> Result<(), Error>
    where
        P: AsRef<Path>,
    {
        let bytes = file_name::SecretBytes::new(self.to_bytes()?);
        file_name::write_private(path.as_ref(), &bytes)?;
        Ok(())
    }

    /// Save this keytab to the file keytab named by `KRB5_KTNAME`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::DefaultKeytabName`] when `KRB5_KTNAME` is unset or not
    /// valid Unicode, and any error of [`Keytab::save_name`].
    #[inline]
    /// # Ambient input
    /// Reads `KRB5_KTNAME`; use [`Keytab::save_name`] for an explicit name.
    pub fn save_to_env(&self) -> Result<(), Error> {
        let name = env::var(KRB5_KTNAME_ENV).map_err(Error::DefaultKeytabName)?;
        self.save_name(name)
    }

    /// Save this keytab by MIT-style keytab name.
    ///
    /// Bare paths, `FILE:path`, and `WRFILE:path` are supported.
    ///
    /// # Errors
    ///
    /// Returns any error of [`Name::parse`] and [`Keytab::save`].
    #[inline]
    pub fn save_name<P>(&self, name: P) -> Result<(), Error>
    where
        P: AsRef<str>,
    {
        self.save(Name::parse(name)?.into_file_path())
    }

    /// Resolve a MIT-style keytab name to a file path.
    ///
    /// Identity tokens read Linux procfs; otherwise this only validates that the name
    /// denotes a keytab format backed by this module.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKeytabName`] when the name or its path is
    /// empty, and [`Error::UnsupportedKeytabType`] for a type prefix other
    /// than `FILE` or `WRFILE`. [`Error::IdentityUnavailable`] means identity
    /// token expansion cannot read Linux procfs or is unsupported on this platform.
    #[inline]
    pub fn file_path_from_keytab_name(name: &str) -> Result<PathBuf, Error> {
        file_name::file_path_from_name(name, &["FILE", "WRFILE"]).map_err(|error| match error {
            file_name::Error::Empty => Error::InvalidKeytabName,
            file_name::Error::IdentityUnavailable => Error::IdentityUnavailable,
            file_name::Error::UnsupportedType { name_type } => Error::UnsupportedKeytabType {
                keytab_type: name_type,
            },
        })
    }

    /// Serialize the keytab to bytes.
    ///
    /// Successful raw output is caller-owned secret material; erase it after use.
    ///
    /// # Errors
    ///
    /// Returns [`Error::LengthOverflow`] when a component count, string or key
    /// length exceeds `i16::MAX`, an encryption type does not fit an `i16`,
    /// or an entry does not fit an `i32` length.
    #[inline]
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        let endian = Endian::for_version(self.version);
        let mut out = file_name::SecretBytes::new(vec![KEYTAB_FIRST_BYTE, self.version]);
        for entry in &self.entries {
            if entry.kvno == 0 && entry.kvno8 != 0 {
                return Err(Error::LengthOverflow);
            }
            let mut body = file_name::SecretBytes::new(Vec::new());
            entry.principal.write_to(&mut body, self.version, endian)?;
            write_u32(&mut body, entry.timestamp, endian);
            body.push(entry.kvno8);
            let etype = i16::try_from(entry.key.etype).map_err(|_range| Error::LengthOverflow)?;
            body.extend_from_slice(&match endian {
                Endian::Big => etype.to_be_bytes(),
                Endian::Little => etype.to_le_bytes(),
            });
            write_u16_checked(&mut body, entry.key.value.len(), endian)?;
            body.extend_from_slice(&entry.key.value);
            write_u32(&mut body, entry.kvno, endian);

            let body_len: i32 = body
                .len()
                .try_into()
                .map_err(|_out_of_range| Error::LengthOverflow)?;
            write_i32(&mut out, body_len, endian);
            out.extend_from_slice(&body);
        }
        Ok(out.into_vec())
    }

    #[must_use]
    /// Keytab file format version.
    #[inline]
    pub const fn version(&self) -> u8 {
        self.version
    }

    #[must_use]
    /// Parsed entries.
    #[inline]
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// Mutable parsed entries, useful for tests and construction.
    #[inline]
    pub const fn entries_mut(&mut self) -> &mut Vec<Entry> {
        &mut self.entries
    }

    /// Redacted entry metadata, suitable for diagnostics and JSON rendering.
    #[cfg(feature = "serde")]
    #[inline]
    pub fn entry_metadata(&self) -> Vec<EntryMetadata> {
        self.entries.iter().map(EntryMetadata::from_entry).collect()
    }

    /// Return redacted entry metadata as pretty-printed JSON.
    ///
    /// Raw key bytes are intentionally omitted.
    ///
    /// # Errors
    ///
    /// Returns the [`serde_json::Error`] of a failed serialization.
    #[cfg(feature = "serde")]
    #[inline]
    pub fn entries_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(&self.entry_metadata())
    }

    /// Add an entry by deriving key material from a password.
    ///
    /// This mirrors gokrb5's keytab entry generation: the default Kerberos
    /// password salt is `realm + principal components`, and the selected
    /// encryption type's default string-to-key parameters are used.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnsupportedEtype`] for an encryption type this crate
    /// does not implement, [`Error::Crypto`] when key derivation fails, and
    /// [`Error::TimestampBeforeUnixEpoch`] or [`Error::TimestampOverflow`]
    /// when `timestamp` does not fit the file's unsigned 32-bit seconds.
    #[inline]
    pub fn add_entry_from_password(
        &mut self,
        principal: Principal,
        password: Zeroizing<Vec<u8>>,
        timestamp: SystemTime,
        kvno: u8,
        etype: i32,
    ) -> Result<(), Error> {
        let owned = password::Owner(password);
        let etype_impl = selection::enctype(etype)?.ok_or(Error::UnsupportedEtype(etype))?;
        let salt = principal.default_password_salt();
        let seconds = system_time_to_u32_seconds(timestamp)?;
        let key = EncryptionKey::new(
            etype,
            etype_impl.string_to_key(&owned.0, salt.as_bytes(), etype_impl.default_s2kparams())?,
        );
        self.entries.push(Entry {
            principal,
            timestamp: seconds,
            kvno8: kvno,
            key,
            kvno: kvno.into(),
        });
        Ok(())
    }

    /// Add an entry from an SPN-style principal name string.
    ///
    /// The name is split on `/` and stored with name type `1`
    /// (`KRB_NT_PRINCIPAL`), matching gokrb5's keytab `AddEntry` behavior.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidPrincipalName`] when the name is empty or has
    /// an empty component, and any error of
    /// [`Keytab::add_entry_from_password`].
    #[inline]
    pub fn add_entry_from_password_name<P, Q>(
        &mut self,
        principal_name: P,
        realm: Q,
        password: Zeroizing<Vec<u8>>,
        timestamp: SystemTime,
        kvno: u8,
        etype: i32,
    ) -> Result<(), Error>
    where
        P: AsRef<str>,
        Q: Into<String>,
    {
        let mut owned = password::Owner(password);
        let principal = Principal::from_name(realm, 1, principal_name)?;
        self.add_entry_from_password(principal, mem::take(&mut owned.0), timestamp, kvno, etype)
    }

    /// Derive an entry from borrowed password bytes without taking their ownership.
    /// # Security
    /// The caller must erase the borrowed input and copies; the temporary owner is erased here.
    /// # Errors
    /// Returns the derivation and timestamp errors of [`Self::add_entry_from_password`].
    #[inline]
    pub fn add_entry_from_password_ref(
        &mut self,
        principal: Principal,
        password: &[u8],
        timestamp: SystemTime,
        kvno: u8,
        etype: i32,
    ) -> Result<(), Error> {
        self.add_entry_from_password(
            principal,
            Zeroizing::new(password.to_vec()),
            timestamp,
            kvno,
            etype,
        )
    }

    /// Find the newest key matching principal components, realm, kvno, and
    /// encryption type. A `kvno` of `0` matches any kvno, mirroring gokrb5.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NoMatchingKey`] when no entry matches.
    #[inline]
    pub fn find_key(
        &self,
        principal_components: &[&str],
        realm: &str,
        kvno: u32,
        etype: i32,
    ) -> Result<(&EncryptionKey, u32), Error> {
        let mut selected: Option<&Entry> = None;
        for entry in &self.entries {
            if entry.principal.realm == realm
                && entry.principal.components.len() == principal_components.len()
                && entry
                    .principal
                    .components
                    .iter()
                    .zip(principal_components)
                    .all(|(left, right)| left == right)
                && entry.key.etype == etype
                && (kvno == 0 || entry.kvno == kvno)
            {
                match selected {
                    Some(current) if current.timestamp >= entry.timestamp => {}
                    _ => selected = Some(entry),
                }
            }
        }

        selected
            .map(|entry| (&entry.key, entry.kvno))
            .ok_or_else(|| Error::NoMatchingKey {
                principal: principal_components.join("/"),
                realm: realm.to_owned(),
                kvno,
                etype,
            })
    }
}

/// The default keytab name: `KRB5_KTNAME` when it is set, otherwise
/// `configured_name`.
///
/// # Ambient input
/// Reads `KRB5_KTNAME` before the caller's configured fallback.
///
/// # Errors
///
/// Returns [`Error::DefaultKeytabName`] when `KRB5_KTNAME` is set but not
/// valid Unicode.
#[cfg(feature = "messages")]
pub(crate) fn default_keytab_name(defaults: &LibDefaults) -> Result<Keytab, Error> {
    match env::var(KRB5_KTNAME_ENV) {
        Ok(keytab_name) => Keytab::load_name(keytab_name),
        Err(env::VarError::NotPresent) => configured_keytab(defaults, DefaultName::Keytab),
        Err(error) => Err(Error::DefaultKeytabName(error)),
    }
}

/// Load a configured keytab after one explicit-context substitution.
///
/// # Ambient input
/// Reads `TMPDIR`, `TEMP`, `APPDATA` and process identity through the default
/// resolver. Use `Keytab::load` with an explicit path to avoid discovery.
///
/// # Errors
/// Returns typed expansion, store and file errors.
#[cfg(feature = "messages")]
pub(crate) fn configured_keytab(
    defaults: &LibDefaults,
    selection: DefaultName,
) -> Result<Keytab, Error> {
    let name = credential_names::resolve_credential_template(defaults, selection)
        .map_err(Error::Expansion)?;
    let path =
        file_name::literal_file_path(&name, &["FILE", "WRFILE"]).map_err(|error| match error {
            file_name::Error::Empty => Error::InvalidKeytabName,
            file_name::Error::IdentityUnavailable => Error::IdentityUnavailable,
            file_name::Error::UnsupportedType { name_type } => Error::UnsupportedKeytabType {
                keytab_type: name_type,
            },
        })?;
    Keytab::load(path)
}

impl Default for Keytab {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

/// A keytab entry.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Entry {
    /// Principal for the key.
    pub principal: Principal,
    /// POSIX timestamp in seconds.
    pub timestamp: u32,
    /// 8-bit key version number stored in the fixed entry fields.
    pub kvno8: u8,
    /// Long-term key material.
    pub key: EncryptionKey,
    /// 32-bit key version number, falling back to `kvno8` when absent or zero.
    pub kvno: u32,
}

impl Entry {
    /// Creates a `Entry` from its required fields.
    #[must_use]
    #[inline]
    pub fn new(
        principal: Principal,
        timestamp: u32,
        kvno8: u8,
        key: EncryptionKey,
        kvno: u32,
    ) -> Self {
        Self {
            principal,
            timestamp,
            kvno8,
            key,
            kvno: if kvno == 0 { u32::from(kvno8) } else { kvno },
        }
    }

    #[must_use]
    /// Entry timestamp as `SystemTime`.
    ///
    /// Every supported platform represents all unsigned 32-bit POSIX seconds;
    /// a platform that cannot gets the Unix epoch instead.
    #[inline]
    pub fn system_time(&self) -> SystemTime {
        UNIX_EPOCH
            .checked_add(Duration::from_secs(self.timestamp.into()))
            .unwrap_or(UNIX_EPOCH)
    }
}

/// Keytab principal.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Principal {
    /// Principal realm.
    pub realm: String,
    /// Principal name components.
    pub components: Vec<String>,
    /// Kerberos name type. Version 1 keytabs omit this and parse as `0`.
    pub name_type: i32,
}

impl Principal {
    /// Create a keytab principal.
    #[inline]
    pub fn new<I, S, P>(realm: P, name_type: i32, components: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
        P: Into<String>,
    {
        Self {
            realm: realm.into(),
            components: components.into_iter().map(Into::into).collect(),
            name_type,
        }
    }

    /// Create a keytab principal from components separated by `/`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidPrincipalName`] when the name is empty or has
    /// an empty component.
    #[inline]
    pub fn from_name<P, Q>(realm: P, name_type: i32, principal_name: Q) -> Result<Self, Error>
    where
        P: Into<String>,
        Q: AsRef<str>,
    {
        let name = principal_name.as_ref();
        if name.is_empty() {
            return Err(Error::InvalidPrincipalName);
        }
        let components = name.split('/');
        if components.clone().any(str::is_empty) {
            return Err(Error::InvalidPrincipalName);
        }
        Ok(Self::new(realm, name_type, components))
    }

    #[must_use]
    /// Return the default Kerberos password salt for this principal.
    #[inline]
    pub fn default_password_salt(&self) -> String {
        let mut salt = self.realm.clone();
        for component in &self.components {
            salt.push_str(component);
        }
        salt
    }

    #[must_use]
    /// Principal components joined by `/`.
    #[inline]
    pub fn name_string(&self) -> String {
        self.components.join("/")
    }

    #[must_use]
    /// Principal as `name@REALM`.
    #[inline]
    pub fn principal_string(&self) -> String {
        format!("{}@{}", self.name_string(), self.realm)
    }

    /// Parse a principal at `offset` in the encoding of `version`, advancing
    /// `offset` past it.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Truncated`], [`Error::NegativeLength`] or
    /// [`Error::LengthOverflow`] when a count or length does not fit the
    /// input, and [`Error::InvalidString`] for a string that is not UTF-8.
    fn parse(bytes: &[u8], offset: &mut usize, version: u8, endian: Endian) -> Result<Self, Error> {
        let mut raw_count = read_i16(bytes, offset, endian)?;
        if version == 1 {
            // Version 1 counts the realm as a component.
            raw_count = raw_count.checked_sub(1).ok_or(Error::LengthOverflow)?;
        }
        let Ok(component_count) = usize::try_from(raw_count) else {
            return Err(Error::NegativeLength(raw_count.into()));
        };

        let realm = read_counted_string(bytes, offset, endian)?;
        let mut components = Vec::with_capacity(component_count);
        for _ in 0..component_count {
            components.push(read_counted_string(bytes, offset, endian)?);
        }

        let name_type = if version == 1 {
            0_i32
        } else {
            read_i32(bytes, offset, endian)?
        };

        Ok(Self {
            realm,
            components,
            name_type,
        })
    }

    /// Append the principal to `out` in the encoding of `version`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::LengthOverflow`] when the component count or a string
    /// length exceeds `i16::MAX`.
    fn write_to(&self, out: &mut Vec<u8>, version: u8, endian: Endian) -> Result<(), Error> {
        let component_count = if version == 1 {
            self.components
                .len()
                .checked_add(1)
                .ok_or(Error::LengthOverflow)?
        } else {
            self.components.len()
        };
        write_u16_checked(out, component_count, endian)?;
        write_counted_string(out, &self.realm, endian)?;
        for component in &self.components {
            write_counted_string(out, component, endian)?;
        }
        if version != 1 {
            write_i32(out, self.name_type, endian);
        }
        Ok(())
    }
}

/// Kerberos encryption key as stored in a keytab.
#[derive(Clone, Eq, PartialEq, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
#[non_exhaustive]
pub struct EncryptionKey {
    /// Kerberos encryption type id.
    pub etype: i32,
    /// Raw key bytes.
    pub value: Vec<u8>,
}

impl EncryptionKey {
    /// Creates a `EncryptionKey` from its required fields.
    #[must_use]
    #[inline]
    pub const fn new(etype: i32, value: Vec<u8>) -> Self {
        Self { etype, value }
    }
}

impl fmt::Debug for EncryptionKey {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self { etype, value } = self;
        f.debug_struct("EncryptionKey")
            .field("etype", etype)
            .field("value_len", &value.len())
            .finish()
    }
}

/// Redacted keytab entry metadata.
#[cfg(feature = "serde")]
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "PascalCase")]
#[non_exhaustive]
pub struct EntryMetadata {
    /// Principal as `name@REALM`.
    pub principal: String,
    /// Principal realm.
    pub realm: String,
    /// Principal name components.
    pub components: Vec<String>,
    /// Kerberos name type.
    pub name_type: i32,
    /// Entry timestamp as POSIX seconds.
    pub timestamp: u32,
    /// 8-bit key version number.
    #[serde(rename = "KVNO8")]
    pub kvno8: u8,
    /// 32-bit key version number.
    #[serde(rename = "KVNO")]
    pub kvno: u32,
    /// Kerberos encryption type id.
    #[serde(rename = "EType")]
    pub etype: i32,
    /// Length of the key value in bytes.
    pub key_length: usize,
}

#[cfg(feature = "serde")]
impl EntryMetadata {
    /// Redacted metadata of one entry.
    fn from_entry(entry: &Entry) -> Self {
        Self {
            principal: entry.principal.principal_string(),
            realm: entry.principal.realm.clone(),
            components: entry.principal.components.clone(),
            name_type: entry.principal.name_type,
            timestamp: entry.timestamp,
            kvno8: entry.kvno8,
            kvno: entry.kvno,
            etype: entry.key.etype,
            key_length: entry.key.value.len(),
        }
    }
}

use crate::error::Keytab as Error;

/// Byte order of the integers in a keytab file.
#[derive(Clone, Copy, Debug)]
enum Endian {
    /// Network byte order, used by version 2.
    Big,
    /// Little-endian host order, used by version 1 on such hosts.
    Little,
}

impl Endian {
    /// Byte order of a file of `version`: version 1 uses host order.
    const fn for_version(version: u8) -> Self {
        if version == 1 && cfg!(target_endian = "little") {
            Self::Little
        } else {
            Self::Big
        }
    }
}

/// The error for a read of `needed` bytes at `offset` past the input end.
const fn truncated(bytes: &[u8], offset: usize, needed: usize) -> Error {
    Error::Truncated {
        offset,
        needed,
        remaining: bytes.len().saturating_sub(offset),
    }
}

/// The end offset of a read of `len` bytes at `offset`.
///
/// # Errors
///
/// Returns [`Error::LengthOverflow`] when the end does not fit `usize`, and
/// [`Error::Truncated`] when it lies past the input end.
fn checked_end(bytes: &[u8], offset: usize, len: usize) -> Result<usize, Error> {
    let end = offset.checked_add(len).ok_or(Error::LengthOverflow)?;
    if end > bytes.len() {
        return Err(truncated(bytes, offset, len));
    }
    Ok(end)
}

/// Whole POSIX seconds of `value`, as stored in a keytab entry.
///
/// # Errors
///
/// Returns [`Error::TimestampBeforeUnixEpoch`] for a time before the epoch and
/// [`Error::TimestampOverflow`] when the seconds do not fit a `u32`.
fn system_time_to_u32_seconds(value: SystemTime) -> Result<u32, Error> {
    value
        .duration_since(UNIX_EPOCH)?
        .as_secs()
        .try_into()
        .map_err(|_out_of_range| Error::TimestampOverflow)
}

/// Advance `offset` past `len` bytes without reading them.
///
/// # Errors
///
/// Returns the [`checked_end`] error when the bytes do not fit the input.
fn checked_advance(bytes: &[u8], offset: &mut usize, len: usize) -> Result<(), Error> {
    *offset = checked_end(bytes, *offset, len)?;
    Ok(())
}

/// Read `len` bytes at `offset`, advancing it past them.
///
/// # Errors
///
/// Returns the [`checked_end`] error when the bytes do not fit the input.
fn read_bytes<'input>(
    bytes: &'input [u8],
    offset: &mut usize,
    len: usize,
) -> Result<&'input [u8], Error> {
    let start = *offset;
    let end = checked_end(bytes, start, len)?;
    let raw = bytes
        .get(start..end)
        .ok_or_else(|| truncated(bytes, start, len))?;
    *offset = end;
    Ok(raw)
}

/// Read `N` bytes at `offset` into an array, advancing it past them.
///
/// # Errors
///
/// Returns the [`checked_end`] error when the bytes do not fit the input.
fn read_array<const N: usize>(bytes: &[u8], offset: &mut usize) -> Result<[u8; N], Error> {
    let start = *offset;
    read_bytes(bytes, offset, N)?
        .first_chunk::<N>()
        .copied()
        .ok_or_else(|| truncated(bytes, start, N))
}

/// Read one byte at `offset`, advancing it.
///
/// # Errors
///
/// Returns [`Error::Truncated`] at the input end.
fn read_u8(bytes: &[u8], offset: &mut usize) -> Result<u8, Error> {
    let [byte] = read_array::<1>(bytes, offset)?;
    Ok(byte)
}

/// Read an `i16` at `offset`, advancing it.
///
/// # Errors
///
/// Returns [`Error::Truncated`] when fewer than two bytes remain.
fn read_i16(bytes: &[u8], offset: &mut usize, endian: Endian) -> Result<i16, Error> {
    let raw = read_array::<2>(bytes, offset)?;
    Ok(match endian {
        Endian::Big => i16::from_be_bytes(raw),
        Endian::Little => i16::from_le_bytes(raw),
    })
}

/// Read an `i32` at `offset`, advancing it.
///
/// # Errors
///
/// Returns [`Error::Truncated`] when fewer than four bytes remain.
fn read_i32(bytes: &[u8], offset: &mut usize, endian: Endian) -> Result<i32, Error> {
    let raw = read_array::<4>(bytes, offset)?;
    Ok(match endian {
        Endian::Big => i32::from_be_bytes(raw),
        Endian::Little => i32::from_le_bytes(raw),
    })
}

/// Read a `u32` at `offset`, advancing it.
///
/// # Errors
///
/// Returns [`Error::Truncated`] when fewer than four bytes remain.
fn read_u32(bytes: &[u8], offset: &mut usize, endian: Endian) -> Result<u32, Error> {
    let raw = read_array::<4>(bytes, offset)?;
    Ok(match endian {
        Endian::Big => u32::from_be_bytes(raw),
        Endian::Little => u32::from_le_bytes(raw),
    })
}

/// Read an `i16`-length-prefixed UTF-8 string at `offset`, advancing it.
///
/// # Errors
///
/// Returns [`Error::NegativeLength`] for a negative length,
/// [`Error::Truncated`] or [`Error::LengthOverflow`] when the string does not
/// fit the input, and [`Error::InvalidString`] when it is not UTF-8.
fn read_counted_string(bytes: &[u8], offset: &mut usize, endian: Endian) -> Result<String, Error> {
    let raw_len = read_i16(bytes, offset, endian)?;
    let Ok(len) = usize::try_from(raw_len) else {
        return Err(Error::NegativeLength(raw_len.into()));
    };
    let raw = read_bytes(bytes, offset, len)?;
    Ok(str::from_utf8(raw)?.to_owned())
}

/// Append an `i32` to `out`.
fn write_i32(out: &mut Vec<u8>, value: i32, endian: Endian) {
    out.extend_from_slice(&match endian {
        Endian::Big => value.to_be_bytes(),
        Endian::Little => value.to_le_bytes(),
    });
}

/// Append a `u32` to `out`.
fn write_u32(out: &mut Vec<u8>, value: u32, endian: Endian) {
    out.extend_from_slice(&match endian {
        Endian::Big => value.to_be_bytes(),
        Endian::Little => value.to_le_bytes(),
    });
}

/// Append `value` to `out` as a `u16`.
///
/// # Errors
///
/// Returns [`Error::LengthOverflow`] when `value` exceeds `i16::MAX`.
fn write_u16_checked<T>(out: &mut Vec<u8>, value: T, endian: Endian) -> Result<(), Error>
where
    T: TryInto<u16>,
{
    let narrowed: u16 = value
        .try_into()
        .map_err(|_out_of_range| Error::LengthOverflow)?;
    if narrowed > 0x7fff {
        return Err(Error::LengthOverflow);
    }
    out.extend_from_slice(&match endian {
        Endian::Big => narrowed.to_be_bytes(),
        Endian::Little => narrowed.to_le_bytes(),
    });
    Ok(())
}

/// Append `value` to `out` as a `u16`-length-prefixed string.
///
/// # Errors
///
/// Returns [`Error::LengthOverflow`] when the length exceeds `i16::MAX`.
fn write_counted_string(out: &mut Vec<u8>, value: &str, endian: Endian) -> Result<(), Error> {
    write_u16_checked(out, value.len(), endian)?;
    out.extend_from_slice(value.as_bytes());
    Ok(())
}
