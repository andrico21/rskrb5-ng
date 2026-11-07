//! MIT credential cache parsing and serialization.
//!
//! FILE/WRFILE and DIR caches support credential lookup, metadata, persistence
//! and X-CACHECONF entries. Ticket bytes are preserved without interpretation;
//! the client and message modules handle their cryptographic contents.

use alloc::fmt;
use core::{
    mem,
    str::{self, FromStr},
};
use std::{
    env, fs, io,
    path::{Path, PathBuf},
};

#[cfg(feature = "serde")]
use serde::de::Error as _;
use zeroize::Zeroizing;

use crate::file_name;

/// First byte of every MIT credential cache file.
const CCACHE_FIRST_BYTE: u8 = 5;
/// Version 4 header field tag carrying the KDC clock offset.
const HEADER_FIELD_TAG_KDC_OFFSET: u16 = 1;
/// Environment variable naming the default credential cache.
const KRB5CCNAME_ENV: &str = "KRB5CCNAME";
/// File in a `DIR:` collection that names the primary cache.
const DIR_PRIMARY_FILE: &str = "primary";
/// Primary cache file name created in a `DIR:` collection without one; also
/// the prefix every cache file name in a collection must start with.
const DIR_DEFAULT_PRIMARY_CACHE: &str = "tkt";
/// Realm of the synthetic credentials that carry cache configuration.
const X_CACHECONF_REALM: &str = "X-CACHECONF:";
/// First server name component of a cache configuration credential.
const X_CACHECONF_COMPONENT: &str = "krb5_ccache_conf_data";

/// Parsed MIT-style credential cache name.
///
/// `rskrb5-ng` supports direct file-backed cache names, including
/// subsidiary `DIR::path` cache names which point directly at a FILE-format
/// cache in a DIR collection. Keeping the parsed name explicit gives callers a
/// stable validation point and leaves room for platform stores to grow into
/// separate variants.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum CacheName {
    /// A file-backed credential cache.
    File(PathBuf),
}

/// Redaction of credential-bearing diagnostics.
mod credential_debug;

/// Erasure of retained credential payloads.
mod payload;

/// Credential payload lifetime regressions.
#[cfg(test)]
mod payload_tests;

/// Credential cache configuration entry.
///
/// MIT stores cache metadata as synthetic credentials with realm
/// `X-CACHECONF:`. The configuration value is the credential's ticket field.
#[derive(Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub struct ConfigEntry<'cache> {
    /// Configuration key.
    pub key: &'cache str,
    /// Optional associated principal string.
    pub principal: Option<&'cache str>,
    /// Raw configuration value bytes.
    pub value: &'cache [u8],
}

impl CacheName {
    /// Parse a MIT-style credential cache name.
    ///
    /// Bare paths, `FILE:path`, `WRFILE:path`, and subsidiary `DIR::path`
    /// cache names are supported. `DIR:directory` primary collections are
    /// resolved by `CCache::file_path_from_cache_name`, which may touch the
    /// filesystem. Platform stores such as `KCM:`, `KEYRING:`, and `API:` are
    /// rejected explicitly.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidCacheName`] when the name or its path is empty
    /// or a `DIR::path` name is not a `tkt*` file inside a directory, and
    /// [`Error::UnsupportedCacheType`] for any other type prefix, `DIR:`
    /// collections included. [`Error::IdentityUnavailable`] means process identity
    /// token expansion cannot read Linux procfs or is unsupported on this platform.
    #[inline]
    pub fn parse<P>(name: P) -> Result<Self, Error>
    where
        P: AsRef<str>,
    {
        let expanded = file_name::expand_path_tokens(name.as_ref()).map_err(file_name_error)?;
        direct_file_path_from_cache_name(&expanded).map(Self::File)
    }

    #[must_use]
    /// File path for this cache name.
    #[inline]
    pub fn file_path(&self) -> &Path {
        match self {
            Self::File(path) => path,
        }
    }

    #[must_use]
    /// Consume this cache name and return its file path.
    #[inline]
    pub fn into_file_path(self) -> PathBuf {
        match self {
            Self::File(path) => path,
        }
    }
}

impl FromStr for CacheName {
    type Err = Error;

    #[inline]
    fn from_str(name: &str) -> Result<Self, Self::Err> {
        Self::parse(name)
    }
}

/// Parsed MIT credential cache file.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct CCache {
    /// File format version, 1 to 4.
    #[cfg_attr(feature = "serde", serde(deserialize_with = "deserialize_version"))]
    version: u8,
    /// Version 4 header; empty for older versions.
    header: Header,
    /// Default client principal.
    default_principal: Principal,
    /// Credentials in file order, configuration entries included.
    credentials: Vec<Credential>,
}

impl CCache {
    #[must_use]
    /// Create an empty version 4 credential cache.
    #[inline]
    pub fn new(default_principal: Principal) -> Self {
        Self {
            version: 4,
            header: Header::default(),
            default_principal,
            credentials: Vec::new(),
        }
    }

    /// Load and parse a credential cache file.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] when the file cannot be read, and any error of
    /// [`CCache::parse`] for its contents.
    #[inline]
    pub fn load<P>(path: P) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        let bytes = file_name::SecretBytes::new(fs::read(path.as_ref())?);
        Self::parse(&bytes)
    }

    /// Load and parse the file credential cache named by `KRB5CCNAME`.
    ///
    /// # Ambient input
    /// Reads `KRB5CCNAME`; use [`CCache::load_name`] for an explicit name.
    ///
    /// Only file-backed cache names are supported: bare paths, `FILE:path`,
    /// `WRFILE:path`, `DIR:directory`, and subsidiary `DIR::path` cache
    /// names. Platform stores such as `KCM:`, `KEYRING:`, and `API:` are
    /// rejected explicitly.
    ///
    /// # Errors
    ///
    /// Returns [`Error::DefaultCacheName`] when `KRB5CCNAME` is unset or not
    /// valid Unicode, and any error of [`CCache::load_name`].
    #[inline]
    pub fn load_from_env() -> Result<Self, Error> {
        let name = env::var(KRB5CCNAME_ENV).map_err(Error::DefaultCacheName)?;
        Self::load_name(name)
    }

    /// Load and parse a credential cache by MIT-style cache name.
    ///
    /// Bare paths, `FILE:path`, `WRFILE:path`, `DIR:directory`, and
    /// subsidiary `DIR::path` cache names are supported.
    ///
    /// # Errors
    ///
    /// Returns any error of [`CCache::file_path_from_cache_name`] and
    /// [`CCache::load`].
    #[inline]
    pub fn load_name<P>(name: P) -> Result<Self, Error>
    where
        P: AsRef<str>,
    {
        Self::load(Self::file_path_from_cache_name(name.as_ref())?)
    }

    /// Save this credential cache to a file.
    ///
    /// Unix creation uses owner-only mode 0600 and existing owner rights are
    /// never widened. On Windows, supply a directory with an owner-only ACL.
    ///
    /// # Errors
    ///
    /// Returns any error of [`CCache::to_bytes`], and [`Error::Io`] when the
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

    /// Save this credential cache to the file cache named by `KRB5CCNAME`.
    ///
    /// # Ambient input
    /// Reads `KRB5CCNAME`; use [`CCache::save_name`] for an explicit name.
    ///
    /// # Errors
    ///
    /// Returns [`Error::DefaultCacheName`] when `KRB5CCNAME` is unset or not
    /// valid Unicode, and any error of [`CCache::save_name`].
    #[inline]
    pub fn save_to_env(&self) -> Result<(), Error> {
        let name = env::var(KRB5CCNAME_ENV).map_err(Error::DefaultCacheName)?;
        self.save_name(name)
    }

    /// Save this credential cache by MIT-style cache name.
    ///
    /// Bare paths, `FILE:path`, `WRFILE:path`, `DIR:directory`, and
    /// subsidiary `DIR::path` cache names are supported.
    ///
    /// # Errors
    ///
    /// Returns any error of [`CCache::file_path_from_cache_name`] and
    /// [`CCache::save`].
    #[inline]
    pub fn save_name<P>(&self, name: P) -> Result<(), Error>
    where
        P: AsRef<str>,
    {
        let cache_name = file_name::expand_path_tokens(name.as_ref()).map_err(file_name_error)?;
        self.save_resolved_name(&cache_name)
    }

    /// Save a resolved name and publish a new collection primary without rescanning.
    ///
    /// # Errors
    /// Returns serialization, path and filesystem failures.
    pub(crate) fn save_resolved_name(&self, cache_name: &str) -> Result<(), Error> {
        self.save(Self::resolved_file_path(cache_name)?)?;
        if dir_collection_path(cache_name).is_some() {
            let _published = Self::resolved_file_path(cache_name)?;
        }
        Ok(())
    }

    /// Resolve a MIT-style cache name to a file path.
    ///
    /// `DIR:directory` names read the directory's `primary` file and create it
    /// with the default `tkt` primary name when it is absent, matching MIT
    /// Kerberos collection resolution.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidCacheName`] when the name or its path is empty,
    /// a `DIR::path` name is not a `tkt*` file inside a directory, or a
    /// collection's `primary` file does not name a `tkt*` cache on its first
    /// line; [`Error::UnsupportedCacheType`] for a type prefix other than
    /// `FILE`, `WRFILE` or `DIR`; and [`Error::Io`] when the `primary` file
    /// cannot be read or created. [`Error::IdentityUnavailable`] means identity
    /// token expansion cannot read Linux procfs or is unsupported on this platform.
    #[inline]
    pub fn file_path_from_cache_name(name: &str) -> Result<PathBuf, Error> {
        Self::resolved_file_path(&file_name::expand_path_tokens(name).map_err(file_name_error)?)
    }

    /// Resolve already-expanded data without interpreting inserted percent signs.
    ///
    /// # Errors
    /// Returns store, path and collection I/O errors, but performs no token expansion.
    pub(crate) fn resolved_file_path(name: &str) -> Result<PathBuf, Error> {
        if let Some(directory) = dir_collection_path(name) {
            return dir_collection_primary_path(directory);
        }
        direct_file_path_from_cache_name(name)
    }

    /// Parse credential cache bytes.
    ///
    /// The borrowed input remains the caller's erasure responsibility.
    ///
    /// # Errors
    ///
    /// Returns [`Error::TooShort`] for input shorter than two bytes,
    /// [`Error::InvalidFirstByte`] and [`Error::InvalidVersion`] for a bad
    /// file prefix, [`Error::Truncated`], [`Error::NegativeLength`] and
    /// [`Error::LengthOverflow`] for lengths and counts that do not fit the
    /// input, [`Error::InvalidString`] for a principal string that is not
    /// UTF-8, and [`Error::InvalidHeaderField`] or
    /// [`Error::InvalidHeaderLength`] for a malformed version 4 header.
    #[inline]
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let [first_byte, version, ..] = *bytes else {
            return Err(Error::TooShort {
                actual: bytes.len(),
            });
        };
        if first_byte != CCACHE_FIRST_BYTE {
            return Err(Error::InvalidFirstByte(first_byte));
        }

        validate_version(version)?;

        let endian = Endian::for_version(version);
        let mut offset = 2_usize;
        let header = if version == 4 {
            Header::parse(bytes, &mut offset, endian)?
        } else {
            Header::default()
        };
        let default_principal = Principal::parse(bytes, &mut offset, version, endian)?;
        let mut credentials = Vec::new();

        while offset < bytes.len() {
            credentials.push(Credential::parse(bytes, &mut offset, version, endian)?);
        }

        Ok(Self {
            version,
            header,
            default_principal,
            credentials,
        })
    }

    /// Serialize the credential cache to bytes.
    ///
    /// Successful raw output is caller-owned secret material; erase it after use.
    ///
    /// # Errors
    ///
    /// Returns [`Error::LengthOverflow`] when a length, count or encryption
    /// type does not fit its on-disk field, [`Error::InvalidVersion`] for an
    /// unsupported version, and [`Error::InvalidHeaderField`]
    /// when a KDC offset header field is not eight bytes long.
    #[inline]
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        validate_version(self.version)?;
        if self.version < 4 && !self.header.fields.is_empty() {
            return Err(Error::InvalidHeaderLength);
        }
        let endian = Endian::for_version(self.version);
        let mut out = file_name::SecretBytes::new(vec![CCACHE_FIRST_BYTE, self.version]);
        if self.version == 4 {
            self.header.write_to(&mut out, endian)?;
        }
        self.default_principal
            .write_to(&mut out, self.version, endian)?;
        for credential in &self.credentials {
            credential.write_to(&mut out, self.version, endian)?;
        }
        Ok(out.into_vec())
    }

    #[must_use]
    /// Credential cache file format version.
    #[inline]
    pub const fn version(&self) -> u8 {
        self.version
    }

    #[must_use]
    /// Version 4 header.
    #[inline]
    pub const fn header(&self) -> &Header {
        &self.header
    }

    /// Mutable version 4 header, useful for construction.
    #[inline]
    pub const fn header_mut(&mut self) -> &mut Header {
        &mut self.header
    }

    #[must_use]
    /// Default client principal.
    #[inline]
    pub const fn default_principal(&self) -> &Principal {
        &self.default_principal
    }

    /// Mutable default client principal, useful for construction.
    #[inline]
    pub const fn default_principal_mut(&mut self) -> &mut Principal {
        &mut self.default_principal
    }

    #[must_use]
    /// Default client realm.
    #[inline]
    pub fn client_realm(&self) -> &str {
        &self.default_principal.realm
    }

    #[must_use]
    /// Default client principal components joined by `/`.
    #[inline]
    pub fn client_name(&self) -> String {
        self.default_principal.name_string()
    }

    #[must_use]
    /// Parsed credentials, including configuration entries.
    #[inline]
    pub fn credentials(&self) -> &[Credential] {
        &self.credentials
    }

    /// Mutable parsed credentials, useful for tests and construction.
    #[inline]
    pub const fn credentials_mut(&mut self) -> &mut Vec<Credential> {
        &mut self.credentials
    }

    /// Insert a credential, replacing the same client and server identities.
    ///
    /// Realm and name components define identity; name-type hints do not
    /// (RFC 4120 §6.2). Replacement preserves the new credential's hints.
    #[inline]
    pub fn upsert_credential(&mut self, credential: Credential) -> Option<Credential> {
        if let Some(existing) = self.credentials.iter_mut().find(|existing| {
            same_principal_identity(&existing.client, &credential.client)
                && same_principal_identity(&existing.server, &credential.server)
        }) {
            Some(mem::replace(existing, credential))
        } else {
            self.credentials.push(credential);
            None
        }
    }

    /// Insert or replace a cache configuration entry for the default client.
    #[inline]
    pub fn upsert_config_entry<P>(
        &mut self,
        key: P,
        principal: Option<String>,
        value: Zeroizing<Vec<u8>>,
    ) -> Option<Credential>
    where
        P: Into<String>,
    {
        self.upsert_credential(Credential::config_entry(
            self.default_principal.clone(),
            key,
            principal,
            value,
        ))
    }

    /// Remove non-configuration credentials for a client principal.
    ///
    /// X-CACHECONF entries are preserved because they carry cache metadata
    /// rather than Kerberos tickets.
    #[inline]
    pub fn remove_entries_for_client(&mut self, client: &Principal) -> Vec<Credential> {
        let (removed, kept): (Vec<Credential>, Vec<Credential>) = mem::take(&mut self.credentials)
            .into_iter()
            .partition(|credential| {
                same_principal_identity(&credential.client, client)
                    && !is_config_credential(credential)
            });
        self.credentials = kept;
        removed
    }

    #[must_use]
    /// Return credentials excluding X-CACHECONF configuration entries.
    #[inline]
    pub fn entries(&self) -> Vec<&Credential> {
        self.credentials
            .iter()
            .filter(|credential| !is_config_credential(credential))
            .collect()
    }

    /// Return parsed cache configuration entries.
    #[inline]
    pub fn config_entries(&self) -> Vec<ConfigEntry<'_>> {
        self.credentials
            .iter()
            .filter_map(parse_config_entry)
            .collect()
    }

    #[must_use]
    /// Return a cache configuration value by key and optional associated principal.
    #[inline]
    pub fn config_entry_value(&self, key: &str, principal: Option<&str>) -> Option<&[u8]> {
        self.config_entries()
            .into_iter()
            .find(|entry| entry.key == key && entry.principal == principal)
            .map(|entry| entry.value)
    }

    /// Redacted credential metadata, suitable for diagnostics and JSON rendering.
    #[cfg(feature = "serde")]
    #[inline]
    pub fn credential_metadata(&self) -> Vec<CredentialMetadata> {
        self.credentials
            .iter()
            .map(CredentialMetadata::from_credential)
            .collect()
    }

    /// Return redacted credential metadata as pretty-printed JSON.
    ///
    /// Raw key bytes and ticket DER are intentionally omitted.
    ///
    /// # Errors
    ///
    /// Returns the [`serde_json::Error`] of a failed serialization.
    #[cfg(feature = "serde")]
    #[inline]
    pub fn credentials_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(&self.credential_metadata())
    }

    #[must_use]
    /// Test whether the cache contains a server principal by name components.
    ///
    /// Like gokrb5, name type and realm are not significant for this check.
    #[inline]
    pub fn contains_server(&self, components: &[&str]) -> bool {
        self.get_entry(components).is_some()
    }

    #[must_use]
    /// Return the first credential matching a server principal by components.
    #[inline]
    pub fn get_entry(&self, components: &[&str]) -> Option<&Credential> {
        self.credentials
            .iter()
            .find(|credential| credential.server.matches_components(components))
    }
}

/// Admit only the versions supported by both binary and serde entry points.
///
/// # Errors
///
/// Returns [`Error::InvalidVersion`] outside versions 1 through 4.
fn validate_version(version: u8) -> Result<(), Error> {
    if (1..=4).contains(&version) {
        Ok(())
    } else {
        Err(Error::InvalidVersion(version))
    }
}

/// Deserialize a version through the same admission rule as the binary parser.
///
/// # Errors
///
/// Returns the deserializer error for a non-byte or unsupported version.
#[cfg(feature = "serde")]
fn deserialize_version<'de, D>(deserializer: D) -> Result<u8, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let version = <u8 as serde::Deserialize>::deserialize(deserializer)?;
    validate_version(version).map_err(D::Error::custom)?;
    Ok(version)
}

/// Whether two principals share realm and name components; the name type is
/// not significant.
fn same_principal_identity(left: &Principal, right: &Principal) -> bool {
    left.realm == right.realm && left.components == right.components
}

/// Resolve a cache name that names a file directly, without reading a `DIR:`
/// collection's `primary` file.
///
/// # Errors
///
/// Returns [`Error::InvalidCacheName`] for an empty name or path or an invalid
/// `DIR::path` name, and [`Error::UnsupportedCacheType`] for a type prefix
/// other than `FILE` or `WRFILE`.
fn direct_file_path_from_cache_name(name: &str) -> Result<PathBuf, Error> {
    if let Some(path) = dir_subsidiary_path(name) {
        return validate_dir_subsidiary_path(path);
    }
    file_name::literal_file_path(name, &["FILE", "WRFILE"]).map_err(file_name_error)
}

/// Map the shared filename boundary into the credential-cache error domain.
fn file_name_error(error: file_name::Error) -> Error {
    match error {
        file_name::Error::Empty => Error::InvalidCacheName,
        file_name::Error::IdentityUnavailable => Error::IdentityUnavailable,
        file_name::Error::UnsupportedType { name_type } => Error::UnsupportedCacheType {
            cache_type: name_type,
        },
    }
}

/// The path of a subsidiary `DIR::path` cache name, or `None` for any other
/// name.
fn dir_subsidiary_path(name: &str) -> Option<&str> {
    let (prefix, residual) = name.split_once(':')?;
    if prefix.eq_ignore_ascii_case("DIR") {
        residual.strip_prefix(':')
    } else {
        None
    }
}

/// The directory of a `DIR:directory` collection name, or `None` for any
/// other name, subsidiary `DIR::path` names included.
fn dir_collection_path(name: &str) -> Option<&str> {
    let (prefix, residual) = name.split_once(':')?;
    (prefix.eq_ignore_ascii_case("DIR") && !residual.starts_with(':')).then_some(residual)
}

/// Expand and check the path of a subsidiary `DIR::path` cache name.
///
/// # Errors
///
/// Returns [`Error::InvalidCacheName`] when the path is empty, has no parent
/// directory, or its file name is not valid Unicode or does not start with
/// `tkt`.
fn validate_dir_subsidiary_path(path: &str) -> Result<PathBuf, Error> {
    if path.is_empty() {
        return Err(Error::InvalidCacheName);
    }
    let expanded = PathBuf::from(path);
    let has_parent = expanded
        .parent()
        .is_some_and(|parent| !parent.as_os_str().is_empty());
    let Some(filename) = expanded.file_name().and_then(|filename| filename.to_str()) else {
        return Err(Error::InvalidCacheName);
    };
    if !has_parent || !filename.starts_with(DIR_DEFAULT_PRIMARY_CACHE) {
        return Err(Error::InvalidCacheName);
    }
    Ok(expanded)
}

/// Resolve the primary cache of a `DIR:directory` collection, creating the
/// `primary` file with the default `tkt` name when it is absent.
///
/// # Errors
///
/// Returns [`Error::InvalidCacheName`] for an empty directory or a malformed
/// `primary` file, and [`Error::Io`] when the `primary` file cannot be read
/// or created.
fn dir_collection_primary_path(directory: &str) -> Result<PathBuf, Error> {
    if directory.is_empty() {
        return Err(Error::InvalidCacheName);
    }
    let collection = PathBuf::from(directory);
    let primary_path = collection.join(DIR_PRIMARY_FILE);
    file_name::reject_symlink(&primary_path)?;
    let primary = match fs::read_to_string(&primary_path) {
        Ok(contents) => parse_dir_primary_name(&contents)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let cache = collection.join(DIR_DEFAULT_PRIMARY_CACHE);
            if !cache.try_exists()? {
                return Ok(cache);
            }
            file_name::create_primary(
                &primary_path,
                format!("{DIR_DEFAULT_PRIMARY_CACHE}\n").as_bytes(),
            )?;
            parse_dir_primary_name(&fs::read_to_string(&primary_path)?)?
        }
        Err(error) => return Err(Error::Io(error)),
    };
    Ok(collection.join(primary))
}

/// Read the primary cache name from the contents of a collection's `primary`
/// file.
///
/// # Errors
///
/// Returns [`Error::InvalidCacheName`] when the contents have no complete
/// first line, or that line does not start with `tkt` or contains a path
/// separator.
fn parse_dir_primary_name(contents: &str) -> Result<String, Error> {
    let Some((line, _)) = contents.split_once('\n') else {
        return Err(Error::InvalidCacheName);
    };
    if !line.starts_with(DIR_DEFAULT_PRIMARY_CACHE) || line.contains('/') || line.contains('\\') {
        return Err(Error::InvalidCacheName);
    }
    Ok(line.to_owned())
}

/// Whether a credential is an X-CACHECONF configuration entry.
fn is_config_credential(credential: &Credential) -> bool {
    parse_config_entry(credential).is_some()
}

/// The configuration entry a credential carries, or `None` when it is not an
/// X-CACHECONF entry with a key and at most one principal.
fn parse_config_entry(credential: &Credential) -> Option<ConfigEntry<'_>> {
    if credential.server.realm != X_CACHECONF_REALM {
        return None;
    }
    let [marker, key, principal @ ..] = credential.server.components.as_slice() else {
        return None;
    };
    if marker != X_CACHECONF_COMPONENT || principal.len() > 1 {
        return None;
    }
    Some(ConfigEntry {
        key: key.as_str(),
        principal: principal.first().map(String::as_str),
        value: &credential.ticket,
    })
}

/// Version 4 ccache header.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[non_exhaustive]
pub struct Header {
    /// Header fields in file order.
    pub fields: Vec<HeaderField>,
}

impl Header {
    /// Parse a version 4 header at `offset`, advancing it past the header.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Truncated`] or [`Error::LengthOverflow`] when the
    /// header does not fit the input, [`Error::InvalidHeaderField`] for a
    /// malformed field, and [`Error::InvalidHeaderLength`] when the fields
    /// overrun the declared header length.
    fn parse(bytes: &[u8], offset: &mut usize, endian: Endian) -> Result<Self, Error> {
        let length = usize::from(read_u16(bytes, offset, endian)?);
        let end = checked_end(bytes, *offset, length)?;
        let mut fields = Vec::new();

        while *offset < end {
            let tag = read_u16(bytes, offset, endian)?;
            let field_length = usize::from(read_u16(bytes, offset, endian)?);
            let value = read_bytes(bytes, offset, field_length)?.to_vec();
            let field = HeaderField { tag, value };
            field.validate()?;
            fields.push(field);
        }

        if *offset != end {
            return Err(Error::InvalidHeaderLength);
        }

        Ok(Self { fields })
    }

    /// Append the encoded header to `out`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidHeaderField`] for a malformed field and
    /// [`Error::LengthOverflow`] when a field or the header is longer than
    /// `u16::MAX` bytes.
    fn write_to(&self, out: &mut Vec<u8>, endian: Endian) -> Result<(), Error> {
        let mut body = Vec::new();
        for field in &self.fields {
            field.validate()?;
            write_u16(&mut body, field.tag, endian);
            write_u16_checked(&mut body, field.value.len(), endian)?;
            body.extend_from_slice(&field.value);
        }

        write_u16_checked(out, body.len(), endian)?;
        out.extend_from_slice(&body);
        Ok(())
    }
}

/// One version 4 ccache header field.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[non_exhaustive]
pub struct HeaderField {
    /// Field tag.
    pub tag: u16,
    /// Raw field value.
    pub value: Vec<u8>,
}

impl HeaderField {
    /// Construct a header field with a representable, tag-valid value.
    ///
    /// # Errors
    /// Returns [`Error::LengthOverflow`] for values larger than `u16::MAX`,
    /// or [`Error::InvalidHeaderField`] for a malformed KDC offset.
    #[inline]
    pub fn new(tag: u16, value: Vec<u8>) -> Result<Self, Error> {
        let _length = u16::try_from(value.len()).map_err(|_range| Error::LengthOverflow)?;
        let field = Self { tag, value };
        field.validate()?;
        Ok(field)
    }

    /// Check the field value length that its tag requires.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidHeaderField`] when a KDC offset field is not
    /// eight bytes long.
    const fn validate(&self) -> Result<(), Error> {
        if self.tag == HEADER_FIELD_TAG_KDC_OFFSET && self.value.len() != 8 {
            return Err(Error::InvalidHeaderField {
                tag: self.tag,
                length: self.value.len(),
            });
        }
        Ok(())
    }
}

/// Principal stored in a credential cache.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[non_exhaustive]
pub struct Principal {
    /// Principal realm.
    pub realm: String,
    /// Principal name type.
    pub name_type: i32,
    /// Principal components.
    pub components: Vec<String>,
}

impl Principal {
    /// Create a principal.
    #[inline]
    pub fn new<P>(realm: P, name_type: i32, components: Vec<String>) -> Self
    where
        P: Into<String>,
    {
        Self {
            realm: realm.into(),
            name_type,
            components,
        }
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

    #[must_use]
    /// Compare principal components, ignoring name type and realm like gokrb5's
    /// `PrincipalName.Equal`.
    #[inline]
    pub fn matches_components(&self, components: &[&str]) -> bool {
        self.components.len() == components.len()
            && self
                .components
                .iter()
                .zip(components)
                .all(|(left, right)| left == right)
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
        let name_type = if version == 1 {
            0_i32
        } else {
            read_i32(bytes, offset, endian)?
        };

        // Each component is at least a four-byte counted string; bound the
        // count against the remaining input before reserving capacity.
        let mut component_count = read_count(bytes, offset, endian, 4)?;
        if version == 1 {
            component_count = component_count
                .checked_sub(1)
                .ok_or(Error::LengthOverflow)?;
        }

        let realm = read_counted_string(bytes, offset, endian)?;
        let mut components = Vec::with_capacity(component_count);
        for _ in 0..component_count {
            components.push(read_counted_string(bytes, offset, endian)?);
        }

        Ok(Self {
            realm,
            name_type,
            components,
        })
    }

    /// Append the principal to `out` in the encoding of `version`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::LengthOverflow`] when the component count or a string
    /// length does not fit an `i32`.
    fn write_to(&self, out: &mut Vec<u8>, version: u8, endian: Endian) -> Result<(), Error> {
        if version == 1 && self.name_type != 0_i32 {
            return Err(Error::LengthOverflow);
        }
        if version != 1 {
            write_i32(out, self.name_type, endian);
        }

        let component_count = if version == 1 {
            self.components
                .len()
                .checked_add(1)
                .ok_or(Error::LengthOverflow)?
        } else {
            self.components.len()
        };
        write_i32_len_checked(out, component_count, endian)?;
        write_counted_string(out, &self.realm, endian)?;
        for component in &self.components {
            write_counted_string(out, component, endian)?;
        }
        Ok(())
    }
}

/// Credential cache entry.
#[derive(Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[non_exhaustive]
pub struct Credential {
    /// Client principal.
    pub client: Principal,
    /// Server principal.
    pub server: Principal,
    /// Session key.
    pub key: EncryptionKey,
    /// Credential timestamps as POSIX seconds.
    pub times: CredentialTimes,
    /// Whether the ticket is encrypted in the session key.
    pub is_skey: bool,
    /// Kerberos ticket flags as the raw four bytes stored in ccache.
    pub ticket_flags: [u8; 4],
    /// Client addresses.
    pub addresses: Vec<HostAddress>,
    /// Authorization data entries.
    pub auth_data: Vec<AuthorizationDataEntry>,
    /// Primary ticket DER bytes.
    #[cfg_attr(feature = "serde", serde(with = "payload"))]
    pub ticket: Zeroizing<Vec<u8>>,
    /// Second ticket DER bytes.
    #[cfg_attr(feature = "serde", serde(with = "payload"))]
    pub second_ticket: Zeroizing<Vec<u8>>,
}

impl Credential {
    /// Creates a `Credential` from its required fields.
    #[must_use]
    #[inline]
    pub fn new(
        client: Principal,
        server: Principal,
        key: EncryptionKey,
        times: CredentialTimes,
        ticket_flags: [u8; 4],
        ticket: Zeroizing<Vec<u8>>,
    ) -> Self {
        Self {
            client,
            server,
            key,
            times,
            is_skey: false,
            ticket_flags,
            addresses: Vec::new(),
            auth_data: Vec::new(),
            ticket,
            second_ticket: Zeroizing::default(),
        }
    }
    /// Sets `is_skey`, preserving the other fields.
    #[must_use]
    #[inline]
    pub const fn with_is_skey(mut self, value: bool) -> Self {
        self.is_skey = value;
        self
    }
    /// Sets `addresses`, preserving the other fields.
    #[must_use]
    #[inline]
    pub fn with_addresses(mut self, value: Vec<HostAddress>) -> Self {
        self.addresses = value;
        self
    }
    /// Sets `auth_data`, preserving the other fields.
    #[must_use]
    #[inline]
    pub fn with_auth_data(mut self, value: Vec<AuthorizationDataEntry>) -> Self {
        self.auth_data = value;
        self
    }
    /// Sets `second_ticket`, preserving the other fields.
    #[must_use]
    #[inline]
    pub fn with_second_ticket(mut self, value: Zeroizing<Vec<u8>>) -> Self {
        self.second_ticket = value;
        self
    }

    /// Build a cache configuration credential.
    ///
    /// The `value` is stored in the ticket field, matching MIT's X-CACHECONF
    /// convention.
    #[inline]
    pub fn config_entry<P>(
        client: Principal,
        key: P,
        principal: Option<String>,
        value: Zeroizing<Vec<u8>>,
    ) -> Self
    where
        P: Into<String>,
    {
        let mut components = vec![X_CACHECONF_COMPONENT.to_owned(), key.into()];
        if let Some(associated) = principal {
            components.push(associated);
        }
        Self {
            client,
            server: Principal::new(X_CACHECONF_REALM, 0, components),
            key: EncryptionKey {
                etype: 0,
                value: Vec::new(),
            },
            times: CredentialTimes::default(),
            is_skey: false,
            ticket_flags: [0; 4],
            addresses: Vec::new(),
            auth_data: Vec::new(),
            ticket: value,
            second_ticket: Zeroizing::default(),
        }
    }

    /// Parse a credential at `offset` in the encoding of `version`, advancing
    /// `offset` past it.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Truncated`], [`Error::NegativeLength`] or
    /// [`Error::LengthOverflow`] when a field does not fit the input, and
    /// [`Error::InvalidString`] for a principal string that is not UTF-8.
    fn parse(bytes: &[u8], offset: &mut usize, version: u8, endian: Endian) -> Result<Self, Error> {
        let client = Principal::parse(bytes, offset, version, endian)?;
        let server = Principal::parse(bytes, offset, version, endian)?;

        // Version 3 stores the encryption type twice; the second copy wins.
        let first_etype = read_i16(bytes, offset, endian)?;
        let etype = if version == 3 {
            read_i16(bytes, offset, endian)?
        } else {
            first_etype
        };
        let key = EncryptionKey {
            etype: i32::from(etype),
            value: read_data(bytes, offset, endian)?,
        };

        let times = CredentialTimes {
            auth_time: read_u32(bytes, offset, endian)?,
            start_time: read_u32(bytes, offset, endian)?,
            end_time: read_u32(bytes, offset, endian)?,
            renew_till: read_u32(bytes, offset, endian)?,
        };
        let is_skey = read_u8(bytes, offset)? != 0;
        let ticket_flags = read_array::<4>(bytes, offset)?;

        // Every address entry is at least a six-byte counted record.
        let address_count = read_count(bytes, offset, endian, 6)?;
        let mut addresses = Vec::with_capacity(address_count);
        for _ in 0..address_count {
            addresses.push(HostAddress::parse(bytes, offset, endian)?);
        }

        // Every authorization-data entry is at least a six-byte counted record.
        let auth_data_count = read_count(bytes, offset, endian, 6)?;
        let mut auth_data = Vec::with_capacity(auth_data_count);
        for _ in 0..auth_data_count {
            auth_data.push(AuthorizationDataEntry::parse(bytes, offset, endian)?);
        }

        let ticket = Zeroizing::new(read_data(bytes, offset, endian)?);

        let mut credential = Self {
            client,
            server,
            key,
            times,
            is_skey,
            ticket_flags,
            addresses,
            auth_data,
            ticket,
            second_ticket: Zeroizing::default(),
        };
        credential.second_ticket = Zeroizing::new(read_data(bytes, offset, endian)?);
        Ok(credential)
    }

    /// Append the credential to `out` in the encoding of `version`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::LengthOverflow`] when the encryption type or an
    /// address or authorization-data type does not fit an `i16`, or a count
    /// or length does not fit an `i32`.
    fn write_to(&self, out: &mut Vec<u8>, version: u8, endian: Endian) -> Result<(), Error> {
        self.client.write_to(out, version, endian)?;
        self.server.write_to(out, version, endian)?;
        write_i16_checked(out, self.key.etype, endian)?;
        if version == 3 {
            write_i16_checked(out, self.key.etype, endian)?;
        }
        write_data(out, &self.key.value, endian)?;
        write_u32(out, self.times.auth_time, endian);
        write_u32(out, self.times.start_time, endian);
        write_u32(out, self.times.end_time, endian);
        write_u32(out, self.times.renew_till, endian);
        out.push(u8::from(self.is_skey));
        out.extend_from_slice(&self.ticket_flags);

        write_i32_len_checked(out, self.addresses.len(), endian)?;
        for address in &self.addresses {
            address.write_to(out, endian)?;
        }

        write_i32_len_checked(out, self.auth_data.len(), endian)?;
        for entry in &self.auth_data {
            entry.write_to(out, endian)?;
        }

        write_data(out, &self.ticket, endian)?;
        write_data(out, &self.second_ticket, endian)?;
        Ok(())
    }
}

/// Redacted credential cache entry metadata.
#[cfg(feature = "serde")]
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "PascalCase")]
#[non_exhaustive]
pub struct CredentialMetadata {
    /// Client principal as `name@REALM`.
    pub client: String,
    /// Server principal as `name@REALM`.
    pub server: String,
    /// Client realm.
    pub client_realm: String,
    /// Server realm.
    pub server_realm: String,
    /// Client principal components.
    pub client_components: Vec<String>,
    /// Server principal components.
    pub server_components: Vec<String>,
    /// Kerberos encryption type id.
    #[serde(rename = "EType")]
    pub etype: i32,
    /// Length of the session key in bytes.
    pub key_length: usize,
    /// Credential timestamps as POSIX seconds.
    pub times: CredentialTimes,
    /// Whether the ticket is encrypted in the session key.
    pub is_skey: bool,
    /// Kerberos ticket flags as raw bytes.
    pub ticket_flags: [u8; 4],
    /// Number of client addresses.
    pub address_count: usize,
    /// Number of authorization-data entries.
    pub auth_data_count: usize,
    /// Primary ticket length in bytes.
    pub ticket_length: usize,
    /// Second ticket length in bytes.
    pub second_ticket_length: usize,
    /// Whether this is an X-CACHECONF metadata entry.
    pub is_config_entry: bool,
}

#[cfg(feature = "serde")]
impl CredentialMetadata {
    /// Redacted metadata of one credential.
    fn from_credential(credential: &Credential) -> Self {
        Self {
            client: credential.client.principal_string(),
            server: credential.server.principal_string(),
            client_realm: credential.client.realm.clone(),
            server_realm: credential.server.realm.clone(),
            client_components: credential.client.components.clone(),
            server_components: credential.server.components.clone(),
            etype: credential.key.etype,
            key_length: credential.key.value.len(),
            times: credential.times,
            is_skey: credential.is_skey,
            ticket_flags: credential.ticket_flags,
            address_count: credential.addresses.len(),
            auth_data_count: credential.auth_data.len(),
            ticket_length: credential.ticket.len(),
            second_ticket_length: credential.second_ticket.len(),
            is_config_entry: is_config_credential(credential),
        }
    }
}

/// Kerberos encryption key stored in a ccache credential.
#[derive(Clone, Eq, PartialEq, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
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

/// Credential timestamp fields as POSIX seconds.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[non_exhaustive]
pub struct CredentialTimes {
    /// Initial authentication time.
    pub auth_time: u32,
    /// Ticket start time.
    pub start_time: u32,
    /// Ticket expiration time.
    pub end_time: u32,
    /// Renewable-until time.
    pub renew_till: u32,
}

/// Host address stored in a ccache credential.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[non_exhaustive]
pub struct HostAddress {
    /// Kerberos address type id.
    pub addr_type: i32,
    /// Raw address bytes.
    pub address: Vec<u8>,
}

impl HostAddress {
    /// Construct an opaque address, preserving its signed wire type.
    #[must_use]
    #[inline]
    pub fn new(addr_type: i16, address: Vec<u8>) -> Self {
        Self {
            addr_type: i32::from(addr_type),
            address,
        }
    }

    /// Construct an IPv4 address (Kerberos address type 2).
    #[must_use]
    #[inline]
    pub fn ipv4(address: [u8; 4]) -> Self {
        Self::new(2, address.to_vec())
    }

    /// Construct an IPv6 address (Kerberos address type 24).
    #[must_use]
    #[inline]
    pub fn ipv6(address: [u8; 16]) -> Self {
        Self::new(24, address.to_vec())
    }

    /// Parse a host address at `offset`, advancing it past the address.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Truncated`], [`Error::NegativeLength`] or
    /// [`Error::LengthOverflow`] when the address does not fit the input.
    fn parse(bytes: &[u8], offset: &mut usize, endian: Endian) -> Result<Self, Error> {
        Ok(Self {
            addr_type: i32::from(read_i16(bytes, offset, endian)?),
            address: read_data(bytes, offset, endian)?,
        })
    }

    /// Append the host address to `out`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::LengthOverflow`] when the address type does not fit
    /// an `i16` or the address length does not fit an `i32`.
    fn write_to(&self, out: &mut Vec<u8>, endian: Endian) -> Result<(), Error> {
        write_i16_checked(out, self.addr_type, endian)?;
        write_data(out, &self.address, endian)
    }
}

/// Authorization data entry stored in a ccache credential.
#[derive(Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[non_exhaustive]
pub struct AuthorizationDataEntry {
    /// Authorization data type id.
    pub ad_type: i32,
    /// Raw authorization data bytes.
    #[cfg_attr(feature = "serde", serde(with = "payload"))]
    pub data: Zeroizing<Vec<u8>>,
}

impl AuthorizationDataEntry {
    /// Creates a `AuthorizationDataEntry` from its required fields.
    #[must_use]
    #[inline]
    pub const fn new(ad_type: i32, data: Zeroizing<Vec<u8>>) -> Self {
        Self { ad_type, data }
    }

    /// Parse an authorization-data entry at `offset`, advancing it past the
    /// entry.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Truncated`], [`Error::NegativeLength`] or
    /// [`Error::LengthOverflow`] when the entry does not fit the input.
    fn parse(bytes: &[u8], offset: &mut usize, endian: Endian) -> Result<Self, Error> {
        Ok(Self {
            ad_type: i32::from(read_i16(bytes, offset, endian)?),
            data: Zeroizing::new(read_data(bytes, offset, endian)?),
        })
    }

    /// Append the authorization-data entry to `out`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::LengthOverflow`] when the data type does not fit an
    /// `i16` or the data length does not fit an `i32`.
    fn write_to(&self, out: &mut Vec<u8>, endian: Endian) -> Result<(), Error> {
        write_i16_checked(out, self.ad_type, endian)?;
        write_data(out, &self.data, endian)
    }
}

use crate::error::Ccache as Error;

/// Byte order of the integers in a credential cache file.
#[derive(Clone, Copy, Debug)]
enum Endian {
    /// Network byte order, used by versions 3 and 4.
    Big,
    /// Little-endian host order, used by versions 1 and 2 on such hosts.
    Little,
}

impl Endian {
    /// Byte order of a file of `version`: versions 1 and 2 use host order.
    const fn for_version(version: u8) -> Self {
        if (version == 1 || version == 2) && cfg!(target_endian = "little") {
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

/// Read a `u16` at `offset`, advancing it.
///
/// # Errors
///
/// Returns [`Error::Truncated`] when fewer than two bytes remain.
fn read_u16(bytes: &[u8], offset: &mut usize, endian: Endian) -> Result<u16, Error> {
    let raw = read_array::<2>(bytes, offset)?;
    Ok(match endian {
        Endian::Big => u16::from_be_bytes(raw),
        Endian::Little => u16::from_le_bytes(raw),
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

/// Read a non-negative i32 element count and require the remaining input to be
/// able to hold that many elements of at least `min_item_len` bytes each.
///
/// Counts come from the credential-cache bytes themselves, so an unbounded
/// reservation would let a short malformed input ask the allocator for tens of
/// gigabytes; every reservation below is gated on this check.
///
/// # Errors
///
/// Returns the [`read_i32`] error when the count itself is truncated,
/// [`Error::NegativeLength`] for a negative count, [`Error::LengthOverflow`]
/// when the count or its byte size does not fit `usize`, and
/// [`Error::Truncated`] when the remaining input cannot hold that many
/// elements.
fn read_count(
    bytes: &[u8],
    offset: &mut usize,
    endian: Endian,
    min_item_len: usize,
) -> Result<usize, Error> {
    let count = read_i32(bytes, offset, endian)?;
    if count < 0_i32 {
        return Err(Error::NegativeLength(count));
    }
    let Ok(items) = usize::try_from(count) else {
        return Err(Error::LengthOverflow);
    };
    let remaining = bytes.len().saturating_sub(*offset);
    let needed = items
        .checked_mul(min_item_len)
        .ok_or(Error::LengthOverflow)?;
    if needed > remaining {
        return Err(Error::Truncated {
            offset: *offset,
            needed,
            remaining,
        });
    }
    Ok(items)
}

/// Read an `i32`-length-prefixed byte string at `offset`, advancing it.
///
/// # Errors
///
/// Returns [`Error::Truncated`], [`Error::NegativeLength`] or
/// [`Error::LengthOverflow`] when the length or the data does not fit the
/// input.
fn read_data(bytes: &[u8], offset: &mut usize, endian: Endian) -> Result<Vec<u8>, Error> {
    let len = read_count(bytes, offset, endian, 1)?;
    Ok(read_bytes(bytes, offset, len)?.to_vec())
}

/// Read an `i32`-length-prefixed UTF-8 string at `offset`, advancing it.
///
/// # Errors
///
/// Returns the [`read_data`] errors, and [`Error::InvalidString`] when the
/// bytes are not UTF-8.
fn read_counted_string(bytes: &[u8], offset: &mut usize, endian: Endian) -> Result<String, Error> {
    let raw = read_data(bytes, offset, endian)?;
    Ok(str::from_utf8(&raw)?.to_owned())
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

/// Append a `u16` to `out`.
fn write_u16(out: &mut Vec<u8>, value: u16, endian: Endian) {
    out.extend_from_slice(&match endian {
        Endian::Big => value.to_be_bytes(),
        Endian::Little => value.to_le_bytes(),
    });
}

/// Append `value` to `out` as an `i16`.
///
/// # Errors
///
/// Returns [`Error::LengthOverflow`] when `value` does not fit an `i16`.
fn write_i16_checked<T>(out: &mut Vec<u8>, value: T, endian: Endian) -> Result<(), Error>
where
    T: TryInto<i16>,
{
    let narrowed: i16 = value
        .try_into()
        .map_err(|_out_of_range| Error::LengthOverflow)?;
    out.extend_from_slice(&match endian {
        Endian::Big => narrowed.to_be_bytes(),
        Endian::Little => narrowed.to_le_bytes(),
    });
    Ok(())
}

/// Append `value` to `out` as a `u16`.
///
/// # Errors
///
/// Returns [`Error::LengthOverflow`] when `value` does not fit a `u16`.
fn write_u16_checked<T>(out: &mut Vec<u8>, value: T, endian: Endian) -> Result<(), Error>
where
    T: TryInto<u16>,
{
    let narrowed: u16 = value
        .try_into()
        .map_err(|_out_of_range| Error::LengthOverflow)?;
    write_u16(out, narrowed, endian);
    Ok(())
}

/// Append the length or count `value` to `out` as an `i32`.
///
/// # Errors
///
/// Returns [`Error::LengthOverflow`] when `value` does not fit an `i32`.
fn write_i32_len_checked<T>(out: &mut Vec<u8>, value: T, endian: Endian) -> Result<(), Error>
where
    T: TryInto<i32>,
{
    let narrowed: i32 = value
        .try_into()
        .map_err(|_out_of_range| Error::LengthOverflow)?;
    write_i32(out, narrowed, endian);
    Ok(())
}

/// Append `value` to `out` with an `i32` length prefix.
///
/// # Errors
///
/// Returns [`Error::LengthOverflow`] when the length does not fit an `i32`.
fn write_data(out: &mut Vec<u8>, value: &[u8], endian: Endian) -> Result<(), Error> {
    write_i32_len_checked(out, value.len(), endian)?;
    out.extend_from_slice(value);
    Ok(())
}

/// Append `value` to `out` as an `i32`-length-prefixed string.
///
/// # Errors
///
/// Returns [`Error::LengthOverflow`] when the length does not fit an `i32`.
fn write_counted_string(out: &mut Vec<u8>, value: &str, endian: Endian) -> Result<(), Error> {
    write_data(out, value.as_bytes(), endian)
}
