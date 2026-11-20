//! Configuration source selection: explicit paths, `KRB5_CONFIG`, platform defaults and text.

use std::{
    fs, io,
    io::Read as _,
    path::{Path, PathBuf},
};

use super::{Config, IncludeExpansion, MAX_INCLUDE_BYTES, ParseMode, compose::compose};
use crate::error::Config as Error;

/// The configuration files tried, in order, when `KRB5_CONFIG` is unset.
#[cfg(target_family = "unix")]
pub(super) const PLATFORM_DEFAULT_CONFIG_PATHS: &[&str] = &["/etc/krb5.conf"];

/// The configuration files tried, in order, when `KRB5_CONFIG` is unset.
#[cfg(target_family = "windows")]
pub(super) const PLATFORM_DEFAULT_CONFIG_PATHS: &[&str] =
    &["C:\\ProgramData\\MIT\\Kerberos5\\krb5.ini"];

/// The configuration files tried, in order, when `KRB5_CONFIG` is unset.
#[cfg(not(any(target_family = "unix", target_family = "windows")))]
pub(super) const PLATFORM_DEFAULT_CONFIG_PATHS: &[&str] = &[];

/// Load and parse a `krb5.conf` file.
///
/// # Errors
/// Returns [`Error::File`] when the file cannot be resolved or read, and the
/// [`Config::parse`] errors for its contents.
pub(super) fn load<P>(path: P) -> Result<Config, Error>
where
    P: AsRef<Path>,
{
    Config::load_paths([path])
}

/// Load and parse one or more `krb5.conf` files.
///
/// # Errors
/// Returns [`Error::EmptyConfigPathList`] when the list names no non-empty
/// path, [`Error::File`] when a named file cannot be resolved or read,
/// [`Error::IncludeDir`] when a named directory cannot be listed, and the
/// [`Config::parse`] errors for each independent source.
pub(super) fn load_paths<I, P>(paths: I) -> Result<Config, Error>
where
    I: IntoIterator<Item = P>,
    P: AsRef<Path>,
{
    let mut loader = IncludeExpansion::default();
    let mut found = false;
    for entry in paths {
        let path = entry.as_ref();
        if path.as_os_str().is_empty() {
            continue;
        }
        found = true;
        let metadata = fs::metadata(path).map_err(|source| Error::File {
            path: path.to_path_buf(),
            source,
        })?;
        if metadata.is_dir() {
            loader.include_dir(path, 0)?;
        } else {
            loader.include_file(path, 0)?;
        }
    }
    if !found {
        return Err(Error::EmptyConfigPathList);
    }
    loader.profile.finish(ParseMode::Compatible)
}

/// Load the platform default files of `paths` that exist.
///
/// # Errors
/// Returns [`Error::NoDefault`] when none of them exists, and the
/// [`Config::load_paths`] errors for those that do.
pub(super) fn load_default_paths<I, P>(paths: I) -> Result<Config, Error>
where
    I: IntoIterator<Item = P>,
    P: AsRef<Path>,
{
    let existing = existing_default_config_paths(paths);
    if existing.is_empty() {
        return Err(Error::NoDefault);
    }
    Config::load_paths(existing)
}

/// Load the platform default files of `paths` that exist, or parse
/// `embedded_krb5_conf` when none does.
///
/// # Errors
/// Returns the [`Config::load_paths`] errors for existing files, and the
/// [`Config::parse`] errors for the embedded text.
pub(super) fn load_default_or_parse_paths<I, P>(
    embedded_krb5_conf: &str,
    paths: I,
) -> Result<Config, Error>
where
    I: IntoIterator<Item = P>,
    P: AsRef<Path>,
{
    match Config::load_default_paths(paths) {
        Ok(config) => Ok(config),
        Err(Error::NoDefault) => Config::parse(embedded_krb5_conf),
        Err(error) => Err(error),
    }
}

/// Parse a `krb5.conf` string.
///
/// # Errors
/// Returns the include-expansion errors ([`Error::IncludeFile`],
/// [`Error::IncludeDir`], [`Error::IncludeCycle`], [`Error::IncludeTooDeep`],
/// [`Error::IncludeTooMany`], [`Error::IncludeTooLarge`]), the error of any
/// line or value a section parser refuses, and the enctype policy
/// errors above.
pub(super) fn parse(input: &str) -> Result<Config, Error> {
    Config::parse_with_roots(input, [])
}

/// Parse caller text, equivalent to gokrb5's `NewFromString`.
///
/// # Errors
/// Returns the bounded profile-composition errors of [`Self::parse`].
pub(super) fn from_string(input: &str) -> Result<Config, Error> {
    Config::parse(input)
}

/// Load an explicit path, equivalent to gokrb5's `Load`.
///
/// # Errors
/// Returns the pathful I/O and composition errors of [`Self::load`].
pub(super) fn from_path<P>(path: P) -> Result<Config, Error>
where
    P: AsRef<Path>,
{
    Config::load(path)
}

/// Parse a reader, including buffered readers, through profile composition.
///
/// # Errors
/// Returns typed I/O, UTF-8, size and include-composition failures.
pub(super) fn from_reader<R>(reader: R) -> Result<Config, Error>
where
    R: io::Read,
{
    let mut bytes = Vec::new();
    let limit = u64::try_from(MAX_INCLUDE_BYTES)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    let _: usize = reader.take(limit).read_to_end(&mut bytes)?;
    if bytes.len() > MAX_INCLUDE_BYTES {
        return Err(Error::IncludeTooLarge {
            bytes: bytes.len(),
            limit: MAX_INCLUDE_BYTES,
        });
    }
    let text = String::from_utf8(bytes)
        .map_err(|source| io::Error::new(io::ErrorKind::InvalidData, source))?;
    Config::parse(&text)
}

/// Parse a profile with explicit secure-unsupported handling.
///
/// # Errors
/// Returns the errors of [`Self::parse`], including Camellia errors in strict mode.
pub(super) fn parse_with_mode(input: &str, mode: ParseMode) -> Result<Config, Error> {
    Config::parse_with_roots_mode(input, [], mode)
}

/// Parse caller-provided text with an optional active source chain.
///
/// # Errors
/// Returns the [`IncludeExpansion::expand`] error of an `include` or
/// `includedir` the text names, and the error of any line or section the
/// parser refuses.
pub(super) fn parse_with_roots<I>(text: &str, roots: I) -> Result<Config, Error>
where
    I: IntoIterator<Item = PathBuf>,
{
    Config::parse_with_roots_mode(text, roots, ParseMode::Compatible)
}

/// Expand sources and apply the requested enctype parsing mode.
///
/// # Errors
/// Returns include, profile and expression-policy errors without fallback.
pub(super) fn parse_with_roots_mode<I>(
    text: &str,
    roots: I,
    mode: ParseMode,
) -> Result<Config, Error>
where
    I: IntoIterator<Item = PathBuf>,
{
    compose(IncludeExpansion::default().with_roots(roots), text, mode)
}

/// The paths of `paths` that name an existing regular file, in order.
pub(super) fn existing_default_config_paths<I, P>(paths: I) -> Vec<PathBuf>
where
    I: IntoIterator<Item = P>,
    P: AsRef<Path>,
{
    paths
        .into_iter()
        .map(|path| path.as_ref().to_path_buf())
        .filter(|path| path.is_file())
        .collect()
}
