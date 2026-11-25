//! Cache-name routes that read the configuration they are given.
//!
//! [`CCache::load_name`], [`CCache::save_name`] and their environment twins
//! are the configuration-free routes: a built-in `KCM:` name reaches its
//! daemon with the default settings (the default socket, or the installed
//! [`KcmTransport`](super::kcm::seam::KcmTransport)). The functions here do
//! the same for a [`Config`]: a `KCM:` name reaches the daemon the
//! `kcm_socket` and `kcm_mach_service` of its `[libdefaults]` name
//! ([`kcm::Store::from_libdefaults`](super::kcm::Store::from_libdefaults)).
//! Every other cache type resolves exactly as in the configuration-free
//! routes, and the name expansion, the installed stores and the built-in
//! dispatch are the same code
//! ([`file_store::resolve_configured`](super::file_store::resolve_configured)
//! is the handle-level route).
//!
//! # Security
//!
//! A disabled socket (`kcm_socket = -`) is never replaced by the default
//! socket, and a request that may have been delivered is never sent a second
//! time through another route ([`Kcm::OutcomeUnknown`](crate::error::Kcm::OutcomeUnknown)).

use std::env;

use super::{CCache, Error, KRB5CCNAME_ENV};
use crate::{config::Config, file_name, secure_env};

/// The value of `KRB5CCNAME`.
///
/// # Errors
///
/// [`Error::DefaultCacheName`] when it is unset or not valid Unicode.
fn env_name() -> Result<String, Error> {
    secure_env::ambient(|| env::var(KRB5CCNAME_ENV)).map_err(Error::DefaultCacheName)
}

/// Load a cache by MIT-style name, as [`CCache::load_name`] does, with the
/// daemon settings of `config` for a `KCM:` name.
///
/// # Errors
///
/// The errors of [`CCache::load_name`], and those of
/// [`kcm::Store::from_libdefaults`](super::kcm::Store::from_libdefaults) for a
/// `KCM:` name.
#[inline]
pub fn load_name(config: &Config, name: &str) -> Result<CCache, Error> {
    CCache::load_resolved_name_with(
        &file_name::expand_path_tokens(name).map_err(super::file_name_error)?,
        Some(&config.libdefaults),
    )
}

/// Load the cache `KRB5CCNAME` names, as [`CCache::load_from_env`] does, with
/// the daemon settings of `config` for a `KCM:` name.
///
/// # Ambient input
///
/// Reads `KRB5CCNAME`; use [`load_name`] for an explicit name. In a set-uid or
/// set-gid process the variable is ignored, as MIT 1.22.2 ignores it
/// (`secure_getenv`).
///
/// # Errors
///
/// [`Error::DefaultCacheName`] when `KRB5CCNAME` is unset or not valid
/// Unicode, and the errors of [`load_name`].
#[inline]
pub fn load_ccache_env(config: &Config) -> Result<CCache, Error> {
    load_name(config, &env_name()?)
}

/// Save `cache` by MIT-style name, as [`CCache::save_name`] does, with the
/// daemon settings of `config` for a `KCM:` name.
///
/// # Errors
///
/// The errors of [`CCache::save_name`], and those of
/// [`kcm::Store::from_libdefaults`](super::kcm::Store::from_libdefaults) for a
/// `KCM:` name.
#[inline]
pub fn save_name(config: &Config, cache: &CCache, name: &str) -> Result<(), Error> {
    cache.save_resolved_name_with(
        &file_name::expand_path_tokens(name).map_err(super::file_name_error)?,
        Some(&config.libdefaults),
    )
}
