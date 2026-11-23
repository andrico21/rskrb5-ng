//! MIT's `dfl` file name (MIT 1.22.2 `rc_dfl.c:open_file`).

use std::{env, path::PathBuf};

use super::Error;
use crate::{file_name::process_identity, secure_env};

/// The effective user id the `dfl` file name and owner check use.
///
/// # Errors
///
/// Returns [`Error::IdentityUnavailable`] when this platform cannot report it.
#[cfg(target_os = "linux")]
pub(super) fn effective_uid() -> Result<u32, Error> {
    process_identity()
        .map(|(_real, effective)| effective)
        .map_err(|_unavailable| Error::IdentityUnavailable)
}

/// The effective user id (`rustix`, the one dependency of this crate on these
/// platforms).
///
/// # Errors
///
/// Returns [`Error::IdentityUnavailable`] for the invalid id `-1`.
#[cfg(all(unix, not(target_os = "linux")))]
pub(super) fn effective_uid() -> Result<u32, Error> {
    let raw = rustix::process::geteuid().as_raw();
    if raw == u32::MAX {
        Err(Error::IdentityUnavailable)
    } else {
        Ok(raw)
    }
}

/// Windows has no user id: the `dfl` name is per-profile instead.
///
/// # Errors
///
/// Always returns [`Error::IdentityUnavailable`].
#[cfg(not(unix))]
pub(super) const fn effective_uid() -> Result<u32, Error> {
    Err(Error::IdentityUnavailable)
}

/// The `dfl` cache file: `<dir>/krb5_<euid>.rcache2` with `dir` from
/// `KRB5RCACHEDIR`, else `TMPDIR`, else `/var/tmp` (`rc_dfl.c:80-91`; the
/// variables are ignored in a set-uid process like MIT's `secure_getenv`).
///
/// # Errors
///
/// Returns [`Error::IdentityUnavailable`] when the user id cannot be read.
#[cfg(unix)]
pub(super) fn default_path() -> Result<PathBuf, Error> {
    let directory = secure_env::ambient(|| env::var_os("KRB5RCACHEDIR"))
        .or_else(|| secure_env::ambient(|| env::var_os("TMPDIR")))
        .map_or_else(|| PathBuf::from("/var/tmp"), PathBuf::from);
    Ok(directory.join(format!("krb5_{}.rcache2", effective_uid()?)))
}

/// The `dfl` cache file: `<KRB5RCACHEDIR>\krb5.rcache2`, else
/// `%LOCALAPPDATA%\krb5.rcache2` (`rc_dfl.c:35-60`).
///
/// # Errors
///
/// Returns [`Error::IdentityUnavailable`] when no directory is known.
#[cfg(not(unix))]
pub(super) fn default_path() -> Result<PathBuf, Error> {
    secure_env::ambient(|| env::var_os("KRB5RCACHEDIR"))
        .or_else(|| secure_env::ambient(|| env::var_os("LOCALAPPDATA")))
        .map(|directory| PathBuf::from(directory).join("krb5.rcache2"))
        .ok_or(Error::IdentityUnavailable)
}
