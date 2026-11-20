//! Store-provider admission and the process-wide installed prefixes.
//!
//! MIT 1.22.2 `krb5_cc_register` (`src/lib/krb5/ccache/ccbase.c:161-186`) and
//! `krb5_kt_register` (`src/lib/krb5/keytab/ktbase.c:117-136`).

use alloc::sync::Arc;
use std::sync::{PoisonError, RwLock};

use super::{Error, Interface, MAX_EXTENSIONS, MAX_ID_BYTES, StoreProvider};

/// The built-in name types, which no provider may claim in any letter case.
const BUILT_IN: [&str; 4] = ["FILE", "WRFILE", "DIR", "MEMORY"];

/// One installed provider and the prefix it held when it was installed.
type Installed = (String, Arc<dyn StoreProvider>);

/// The installed providers, in installation order.
static INSTALLED: RwLock<Vec<Installed>> = RwLock::new(Vec::new());

/// Admit `provider` into a registry that holds `registered`.
/// # Errors
/// Returns `InvalidRegistration` for a malformed claim and `PrefixTaken` for
/// a built-in prefix or one a registered provider holds.
pub(super) fn admit(
    registered: &[Arc<dyn StoreProvider>],
    provider: &dyn StoreProvider,
) -> Result<(), Error> {
    let prefix = claim(provider)?;
    if registered
        .iter()
        .any(|entry| entry.prefix().eq_ignore_ascii_case(prefix))
    {
        return Err(taken(provider, prefix));
    }
    Ok(())
}

/// Install `providers` all at once; a provider installed already is skipped.
/// # Errors
/// Returns the errors of [`claim`], `PrefixTaken` for a prefix another
/// provider holds and `TooManyProviders` beyond [`MAX_EXTENSIONS`].
pub(super) fn install(providers: &[Arc<dyn StoreProvider>]) -> Result<(), Error> {
    let mut installed = INSTALLED.write().unwrap_or_else(PoisonError::into_inner);
    let mut added: Vec<Installed> = Vec::new();
    for provider in providers {
        let prefix = claim(&**provider)?;
        match installed
            .iter()
            .chain(&added)
            .find(|(held, _)| held.eq_ignore_ascii_case(prefix))
        {
            Some((_, holder)) if Arc::ptr_eq(holder, provider) => {}
            Some(_) => return Err(taken(&**provider, prefix)),
            None => added.push((prefix.to_owned(), Arc::clone(provider))),
        }
    }
    if installed.len().saturating_add(added.len()) > MAX_EXTENSIONS {
        return Err(Error::TooManyProviders {
            interface: Interface::StoreProvider,
            limit: MAX_EXTENSIONS,
        });
    }
    installed.extend(added);
    drop(installed);
    Ok(())
}

/// The installed provider whose prefix is exactly the type prefix of `name`
/// (MIT `strcmp`, `ccbase.c:268-274`), and the residual after the colon.
pub(crate) fn installed(name: &str) -> Option<(Arc<dyn StoreProvider>, &str)> {
    let (prefix, residual) = name.split_once(':')?;
    let table = INSTALLED.read().unwrap_or_else(PoisonError::into_inner);
    let provider = table
        .iter()
        .find(|(held, _)| held == prefix)
        .map(|(_, provider)| Arc::clone(provider));
    drop(table);
    provider.map(|found| (found, residual))
}

/// The prefix `provider` may claim: well formed, not built in, and the cache
/// type of its credential store, which it must offer unless it offers a
/// keytab type.
/// # Errors
/// Returns `InvalidRegistration` or `PrefixTaken`.
fn claim(provider: &dyn StoreProvider) -> Result<&str, Error> {
    let refusal = |reason: &'static str| Error::InvalidRegistration {
        interface: Interface::StoreProvider,
        id: provider.id().to_owned(),
        reason,
    };
    let prefix = provider.prefix();
    let well_formed = (2..=MAX_ID_BYTES).contains(&prefix.len())
        && prefix
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'));
    if !well_formed {
        return Err(refusal("store prefix is malformed"));
    }
    let caches = provider.credential_store();
    if caches.is_none() && provider.keytab_type().is_none() {
        return Err(refusal(
            "store offers neither a cache type nor a keytab type",
        ));
    }
    if caches.is_some_and(|store| store.cache_type() != prefix) {
        return Err(refusal("cache type differs from the claimed prefix"));
    }
    if BUILT_IN
        .iter()
        .any(|built_in| built_in.eq_ignore_ascii_case(prefix))
    {
        return Err(taken(provider, prefix));
    }
    Ok(prefix)
}

/// The error of a prefix that is built in or held by another provider.
fn taken(provider: &dyn StoreProvider, prefix: &str) -> Error {
    Error::PrefixTaken {
        id: provider.id().to_owned(),
        prefix: prefix.to_owned(),
    }
}
