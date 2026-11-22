//! The `.k5login` module (`localauth_k5login.c`).
//!
//! MIT 1.22.2 reads the file with `fopen` and compares each line with the
//! unparsed principal (`localauth_k5login.c:119-149`); it requires the owner
//! to be the account's user or root (`:126-135`) and follows symlinks. This
//! module also refuses a symbolic link, a file that is not regular, one that
//! its group or others can write, one that is replaced between the check and
//! the open, and one past the bounds below.

use std::io;

use crate::ccache::Principal;

#[cfg(unix)]
use std::{
    fs::{self, File},
    io::Read as _,
    os::unix::fs::MetadataExt as _,
    path::{Path, PathBuf},
};

#[cfg(unix)]
use super::{Account, LocalAuthorizer};

/// The largest `.k5login` file read, in bytes.
pub const MAX_FILE_BYTES: usize = 1_048_576;
/// The most lines in a `.k5login` file.
pub const MAX_LINES: usize = 16_384;
/// The longest line of a `.k5login` file, newline excluded: MIT reads with a
/// `BUFSIZ` (8192) buffer and cannot match a longer line.
pub const MAX_LINE_BYTES: usize = 8191;

/// Why the `.k5login` module refused.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Fault {
    /// The resolver does not know the account.
    UnknownAccount,
    /// The account name cannot be a file name under `k5login_directory`.
    UnsafeLocalName,
    /// The home directory or `k5login_directory` is not absolute.
    RelativePath,
    /// The file or its metadata could not be read.
    Unreadable(io::ErrorKind),
    /// The path is a symbolic link.
    Symlink,
    /// The path is not a regular file.
    NotRegular,
    /// The file is not the one that was inspected (it was replaced).
    Changed,
    /// The file belongs to neither the account's user nor root.
    WrongOwner,
    /// The file is writable by its group or by others.
    WritableByOthers,
    /// The file is larger than [`MAX_FILE_BYTES`].
    TooLarge,
    /// The file has more than [`MAX_LINES`] lines.
    TooManyLines,
    /// A line is longer than [`MAX_LINE_BYTES`].
    LineTooLong,
    /// The file does not list the principal.
    NotListed,
}

/// Whether `contents`, the bytes of a `.k5login` file, list `principal`.
///
/// A line is the whole unparsed principal name (`krb5_unparse_name`: realm
/// included, `\\`, `/` and `@` escaped); the comparison is byte for byte, the
/// only line ending removed is one `\n`, and the scan stops at the first
/// match.
///
/// # Errors
///
/// [`Fault::TooLarge`], [`Fault::TooManyLines`] or [`Fault::LineTooLong`]
/// when the bytes exceed a bound before a match is found.
#[inline]
pub fn lists(contents: &[u8], principal: &Principal) -> Result<bool, Fault> {
    if contents.len() > MAX_FILE_BYTES {
        return Err(Fault::TooLarge);
    }
    let wanted = super::unparse::with_realm(principal).into_bytes();
    for (index, raw) in contents.split_inclusive(|byte| *byte == b'\n').enumerate() {
        if index >= MAX_LINES {
            return Err(Fault::TooManyLines);
        }
        let line = raw.strip_suffix(b"\n").unwrap_or(raw);
        if line.len() > MAX_LINE_BYTES {
            return Err(Fault::LineTooLong);
        }
        if line == wanted.as_slice() {
            return Ok(true);
        }
    }
    Ok(false)
}

/// What the module says.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum Verdict {
    /// The file lists the principal.
    Listed,
    /// No file, or a refusal that is not authoritative: no opinion.
    Silent,
    /// The module refuses.
    Refused(Fault),
}

/// What a lookup of the file found.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Found {
    /// The file lists the principal.
    Listed,
    /// There is no file.
    Missing,
}

/// The verdict on the bytes of a file (`None`: there is none).
fn judge(contents: Option<&[u8]>, principal: &Principal) -> Result<Found, Fault> {
    let Some(bytes) = contents else {
        return Ok(Found::Missing);
    };
    if lists(bytes, principal)? {
        Ok(Found::Listed)
    } else {
        Err(Fault::NotListed)
    }
}

/// A refusal is final only while `k5login_authoritative` holds
/// (`localauth_k5login.c:159-160`).
fn classify(outcome: Result<Found, Fault>, authoritative: bool) -> Verdict {
    match outcome {
        Ok(Found::Listed) => Verdict::Listed,
        Ok(Found::Missing) => Verdict::Silent,
        Err(fault) if authoritative => Verdict::Refused(fault),
        Err(_) => Verdict::Silent,
    }
}

/// The file of `account` for the local name `name`.
#[cfg(unix)]
fn path_of(directory: Option<&Path>, account: &Account, name: &str) -> Result<PathBuf, Fault> {
    let path = match directory {
        Some(dir) => {
            if matches!(name, "." | "..") || name.contains(['/', '\\']) {
                return Err(Fault::UnsafeLocalName);
            }
            dir.join(name)
        }
        None => account.home.join(".k5login"),
    };
    if path.is_absolute() {
        Ok(path)
    } else {
        Err(Fault::RelativePath)
    }
}

/// Inspect, open and read the file at `path`.
#[cfg(unix)]
fn read_listing(path: &Path, account: &Account, principal: &Principal) -> Result<Found, Fault> {
    let unreadable = |error: io::Error| Fault::Unreadable(error.kind());
    let before = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
            ) =>
        {
            return judge(None, principal);
        }
        Err(error) => return Err(unreadable(error)),
    };
    if before.file_type().is_symlink() {
        return Err(Fault::Symlink);
    }
    if !before.is_file() {
        return Err(Fault::NotRegular);
    }
    let file = File::open(path).map_err(unreadable)?;
    let opened = file.metadata().map_err(unreadable)?;
    if !opened.is_file() || opened.dev() != before.dev() || opened.ino() != before.ino() {
        return Err(Fault::Changed);
    }
    if opened.uid() != account.uid && opened.uid() != 0 {
        return Err(Fault::WrongOwner);
    }
    if opened.mode() & 0o022 != 0 {
        return Err(Fault::WritableByOthers);
    }
    let limit = u64::try_from(MAX_FILE_BYTES).map_or(u64::MAX, |bytes| bytes.saturating_add(1));
    if opened.len() >= limit {
        return Err(Fault::TooLarge);
    }
    let mut contents = Vec::new();
    let _: usize = file.take(limit).read_to_end(&mut contents).map_err(unreadable)?;
    judge(Some(&contents), principal)
}

/// The module's answer for `principal` acting as `name`
/// (`userok_k5login`, `localauth_k5login.c:83-161`).
#[cfg(unix)]
pub(super) fn check(authorizer: &LocalAuthorizer, principal: &Principal, name: &str) -> Verdict {
    let outcome = authorizer
        .resolver
        .lookup(name)
        .ok_or(Fault::UnknownAccount)
        .and_then(|account| {
            let path = path_of(authorizer.directory.as_deref(), &account, name)?;
            read_listing(&path, &account, principal)
        });
    classify(outcome, authorizer.authoritative)
}

/// Off Unix there are no file owners or modes to check and the module has no
/// opinion (MIT `localauth_k5login.c:164-170`).
#[cfg(not(unix))]
pub(super) fn check(authorizer: &LocalAuthorizer, principal: &Principal, _name: &str) -> Verdict {
    let _unused = (&authorizer.resolver, &authorizer.directory);
    classify(judge(None, principal), authorizer.authoritative)
}
