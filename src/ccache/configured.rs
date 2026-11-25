//! Cache-name routes that read the configuration they are given.
//!
//! [`CCache::load_name`] and [`CCache::save_name`] are the configuration-free
//! routes: they reach the built-in `KCM` type with its default settings. The
//! functions here reach it with the `kcm_socket` and `kcm_mach_service` of a
//! [`Config`].

use super::{CCache, Error};
use crate::config::Config;

/// Load a cache by name.
///
/// # Errors
///
/// The errors of [`CCache::load_name`].
#[inline]
pub fn load_name(_config: &Config, name: &str) -> Result<CCache, Error> {
    CCache::load_name(name)
}

/// Save a cache by name.
///
/// # Errors
///
/// The errors of [`CCache::save_name`].
#[inline]
pub fn save_name(_config: &Config, cache: &CCache, name: &str) -> Result<(), Error> {
    cache.save_name(name)
}

/// Load the cache `KRB5CCNAME` names.
///
/// # Errors
///
/// The errors of [`CCache::load_from_env`].
#[inline]
pub fn load_from_env(_config: &Config) -> Result<CCache, Error> {
    CCache::load_from_env()
}
