//! Credential-cache selection: the built-in selectors and the driver.

use alloc::sync::Arc;
use std::{
    fs,
    io::{self, Read as _},
    path::Path,
};

use super::{
    CacheCandidate, CacheSelector, Error, Event, HostnameSelector, IdentitySource, Interface,
    K5Identity, MAX_K5IDENTITY_BYTES, Priority, ProviderError, RealmSelector, Refusal, Registry,
    Selection, SelectionRequest, checks, k5identity, order,
};
use crate::{ccache::Principal, config::Config};

/// MIT's host-based service name type, `KRB5_NT_SRV_HST`.
const NT_SRV_HST: i32 = 3;

/// A registry holding the built-in selectors in MIT's registration order
/// (`ccselect.c:69-84`).
pub(super) fn builtins(k5identity: Option<K5Identity>) -> Registry {
    let mut selectors: Vec<Arc<dyn CacheSelector>> = Vec::new();
    if let Some(selector) = k5identity {
        selectors.push(Arc::new(selector));
    }
    selectors.push(Arc::new(RealmSelector));
    selectors.push(Arc::new(HostnameSelector));
    Registry {
        selectors,
        ..Registry::default()
    }
}

/// MIT `krb5_cc_select` (`ccselect.c:162-185`): authoritative selectors, then
/// heuristic ones, each in enabled order; the first answer other than
/// `NoHandle` ends the selection.
/// # Errors
/// Returns a selector's failure or the refusal of its answer.
pub(super) fn select(
    registry: &Registry,
    config: &Config,
    server: &Principal,
    caches: &[CacheCandidate],
) -> Result<Selection, Error> {
    let interface = Interface::CacheSelector;
    let request = SelectionRequest {
        server,
        caches,
        default_realm: Some(config.libdefaults.default_realm.as_str())
            .filter(|realm| !realm.is_empty()),
    };
    let enabled = order::enabled(&registry.selectors, interface, Some(config), |item| {
        item.id()
    });
    for priority in [Priority::Authoritative, Priority::Heuristic] {
        for selector in enabled.iter().filter(|item| item.priority() == priority) {
            let id = selector.id();
            order::notify(&registry.observers, &Event::Consulted { interface, id });
            let refused = |reason: Refusal| {
                order::notify(
                    &registry.observers,
                    &Event::Refused {
                        interface,
                        id,
                        reason,
                    },
                );
            };
            let selection = selector.choose(&request).map_err(|source| {
                refused(Refusal::Failed);
                Error::CallFailed {
                    interface,
                    id: id.to_owned(),
                    source,
                }
            })?;
            let valid = match &selection {
                Selection::NoHandle => {
                    order::notify(&registry.observers, &Event::Declined { interface, id });
                    continue;
                }
                Selection::Cache(index) => *index < caches.len(),
                Selection::Principal(principal) => checks::principal(principal),
            };
            if !valid {
                refused(Refusal::Malformed);
                return Err(checks::malformed(interface, id, "cache index or principal"));
            }
            order::notify(&registry.observers, &Event::Chosen { interface, id });
            return Ok(selection);
        }
    }
    Ok(Selection::NoHandle)
}

/// The `k5identity` choice (MIT `ccselect_k5identity.c:156-197`).
/// # Errors
/// Returns a read error other than an absent or unreadable file, and an
/// oversized file.
pub(super) fn k5identity(
    source: &IdentitySource,
    request: &SelectionRequest<'_>,
) -> Result<Selection, ProviderError> {
    let bytes = match source {
        IdentitySource::Bytes(bytes) => bytes.clone(),
        IdentitySource::File(path) => match bounded_read(path) {
            Ok(bytes) => bytes,
            // MIT answers nothing for a file it cannot open or read
            // (`fopen` == NULL, `fgets` == NULL; `ccselect_k5identity.c:171-181`).
            Err(_) => return Ok(Selection::NoHandle),
        },
    };
    if bytes.len() > MAX_K5IDENTITY_BYTES {
        return Err(Box::new(io::Error::new(
            io::ErrorKind::InvalidData,
            ".k5identity exceeds its size bound",
        )));
    }
    let Some(principal) = k5identity::choose(&bytes, request.server, request.default_realm) else {
        return Ok(Selection::NoHandle);
    };
    Ok(request
        .caches
        .iter()
        .position(|cache| same_principal(&cache.principal, &principal))
        .map_or(Selection::Principal(principal), Selection::Cache))
}

/// Read at most one byte more than the bound, so an oversized file is detected
/// without reading it whole.
/// # Errors
/// Returns the open or read error.
fn bounded_read(path: &Path) -> io::Result<Vec<u8>> {
    let limit = u64::try_from(MAX_K5IDENTITY_BYTES)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    let mut bytes = Vec::new();
    let _: usize = fs::File::open(path)?.take(limit).read_to_end(&mut bytes)?;
    Ok(bytes)
}

/// MIT `krb5_principal_compare`: realm and components, name type ignored.
fn same_principal(left: &Principal, right: &Principal) -> bool {
    left.realm == right.realm && left.components == right.components
}

/// The `realm` choice (MIT `ccselect_realm.c:48-79`).
pub(super) fn realm(request: &SelectionRequest<'_>) -> Selection {
    if request.server.realm.is_empty() {
        return Selection::NoHandle;
    }
    request
        .caches
        .iter()
        .position(|cache| cache.principal.realm == request.server.realm)
        .map_or(Selection::NoHandle, Selection::Cache)
}

/// The `hostname` choice (MIT `ccselect_hostname.c:58-122`): the cache whose
/// realm is the longest domain tail of the upper-cased host; an earlier cache
/// keeps an equal match.
pub(super) fn hostname(request: &SelectionRequest<'_>) -> Selection {
    let server = request.server;
    let Some(host) = server
        .components
        .get(1)
        .filter(|_| server.name_type == NT_SRV_HST)
        .map(|name| name.to_ascii_uppercase())
    else {
        return Selection::NoHandle;
    };
    let mut best: Option<(usize, usize)> = None;
    for (index, cache) in request.caches.iter().enumerate() {
        let realm = cache.principal.realm.as_str();
        let longer = best.is_none_or(|(_, length)| length < realm.len());
        if longer && domain_tail(&host, realm) {
            best = Some((index, realm.len()));
        }
    }
    best.map_or(Selection::NoHandle, |(index, _)| Selection::Cache(index))
}

/// Whether `realm` is `host` or a suffix of it that starts after a `.`.
fn domain_tail(host: &str, realm: &str) -> bool {
    host == realm
        || host
            .strip_suffix(realm)
            .is_some_and(|prefix| !realm.is_empty() && prefix.ends_with('.'))
}
