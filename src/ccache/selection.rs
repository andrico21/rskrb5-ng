//! Credential-cache selection over a collection (MIT 1.22.2 `krb5_cc_select`,
//! `src/lib/krb5/ccache/ccselect.c:121-190`) and the default `.k5identity`.

use std::{env, path::Path};

use super::{
    Error, Principal,
    stores::{CacheCollection, CacheHandle},
};
use crate::{
    config::Config,
    extensions::{CacheCandidate, K5Identity, RealmQuery, Registry, Selection},
    secure_env,
};

/// MIT's host-based service name type, `KRB5_NT_SRV_HST`.
const NT_SRV_HST: i32 = 3;

/// What [`select_cache`] chose.
#[derive(Debug)]
#[non_exhaustive]
pub enum Selected {
    /// Use this cache.
    Cache(Box<dyn CacheHandle>),
    /// The server needs this client principal, but no cache holds it (MIT
    /// `KRB5_CC_NOTFOUND` with a principal).
    Principal(Principal),
    /// No selector chose (MIT `KRB5_CC_NOTFOUND`).
    NotFound,
}

/// Choose a cache of `collection` for `server` with the selectors of
/// `registry` (MIT `krb5_cc_select`).
///
/// The candidates are the caches of the collection whose default principal
/// can be read, primary first. A server in the referral (empty) realm with a
/// two-component host-based name is matched in its fallback realm: the first
/// realm the registry's host-realm mappers give for the host
/// ([`RealmQuery::Fallback`]), else the default realm, else none (MIT
/// `krb5_get_fallback_host_realm`, `src/lib/krb5/os/hostrealm.c:401-446`).
///
/// # Errors
///
/// The errors of [`CacheCollection::caches`]; [`Error::Selection`] for a
/// selector or mapper failure and a refused answer.
#[inline]
pub fn select_cache(
    registry: &Registry,
    config: &Config,
    collection: &dyn CacheCollection,
    server: &Principal,
) -> Result<Selected, Error> {
    let mut handles = Vec::new();
    let mut candidates = Vec::new();
    for cache in collection.caches()? {
        if let Ok(loaded) = cache.load() {
            candidates.push(CacheCandidate::new(
                cache.name(),
                loaded.default_principal().clone(),
            ));
            handles.push(cache);
        }
    }
    let target = fallback_server(registry, config, server)?;
    let choice = registry.select_cache(config, target.as_ref().unwrap_or(server), &candidates)?;
    Ok(match choice {
        Selection::Cache(index) if index < handles.len() => {
            Selected::Cache(handles.swap_remove(index))
        }
        Selection::Principal(principal) => Selected::Principal(principal),
        Selection::Cache(_) | Selection::NoHandle => Selected::NotFound,
    })
}

/// The server in its fallback realm, when it is a host-based name in the
/// referral realm and a realm is known.
///
/// # Errors
///
/// [`Error::Selection`] for a mapper failure.
fn fallback_server(
    registry: &Registry,
    config: &Config,
    server: &Principal,
) -> Result<Option<Principal>, Error> {
    let [_, named] = server.components.as_slice() else {
        return Ok(None);
    };
    if !server.realm.is_empty() || server.name_type != NT_SRV_HST {
        return Ok(None);
    }
    let host = named.trim_end_matches('.').to_ascii_lowercase();
    let mapped = registry
        .realms(config, &RealmQuery::Fallback(&host))?
        .and_then(|realms| realms.into_iter().next());
    let fallback = mapped.or_else(|| {
        Some(config.libdefaults.default_realm.clone()).filter(|default| !default.is_empty())
    });
    Ok(fallback.map(|realm| Principal {
        realm,
        ..server.clone()
    }))
}

/// The `k5identity` selector over `$HOME/.k5identity`.
///
/// MIT reads the same file (`get_homedir`,
/// `src/lib/krb5/ccache/ccselect_k5identity.c:128-150`). Without a home
/// directory, and on Windows, where MIT has no `k5identity` module
/// (`ccselect.c:61-66`), there is no selector.
///
/// # Ambient input
/// Reads `HOME`; use [`K5Identity::new`] with an explicit path to avoid
/// discovery. MIT falls back to the passwd home directory of the effective
/// user; this crate reads no passwd database and returns `None`.
///
/// In a set-uid or set-gid process the variables named here are ignored, as MIT 1.22.2
/// ignores them (`secure_getenv`); see the secure-environment decision of
/// `docs/security-policy.md`.
#[must_use]
#[inline]
pub fn default_k5identity() -> Option<K5Identity> {
    if cfg!(windows) {
        return None;
    }
    let home = secure_env::ambient(|| env::var_os("HOME"))?;
    Some(K5Identity::new(Path::new(&home).join(".k5identity")))
}
