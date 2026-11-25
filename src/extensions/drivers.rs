//! Host-realm, local-authorization and server-location drivers.

use super::{
    Decision, Error, Event, HostRealm, Interface, LocateRequest, MAX_NAMES, RealmQuery, Refusal,
    Registry, ServerAddress, checks, order,
};
use crate::{ccache::Principal, config::Config};

/// Report a refusal to the observers.
fn refuse(registry: &Registry, interface: Interface, id: &str, reason: Refusal) {
    order::notify(
        &registry.observers,
        &Event::Refused {
            interface,
            id,
            reason,
        },
    );
}

/// The refusal reason of an output error.
const fn refusal_of(error: &Error) -> Refusal {
    if matches!(
        error,
        Error::OutputTooLarge {
            interface: _,
            id: _,
            limit: _
        }
    ) {
        Refusal::TooLarge
    } else {
        Refusal::Malformed
    }
}

/// The failure of a provider call, reported to the observers.
fn failed(
    registry: &Registry,
    interface: Interface,
    id: &str,
    source: super::ProviderError,
) -> Error {
    refuse(registry, interface, id, Refusal::Failed);
    Error::CallFailed {
        interface,
        id: id.to_owned(),
        source,
    }
}

/// Validate a non-empty, bounded list.
/// # Errors
/// Returns `MalformedOutput` for an empty list or a bad entry, and
/// `OutputTooLarge` beyond `MAX_NAMES` entries.
fn bounded<T, F>(interface: Interface, id: &str, values: &[T], valid: F) -> Result<(), Error>
where
    F: Fn(&T) -> bool,
{
    if values.is_empty() {
        return Err(checks::malformed(interface, id, "empty answer"));
    }
    if values.len() > MAX_NAMES {
        return Err(Error::OutputTooLarge {
            interface,
            id: id.to_owned(),
            limit: MAX_NAMES,
        });
    }
    if values.iter().all(valid) {
        Ok(())
    } else {
        Err(checks::malformed(interface, id, "invalid entry"))
    }
}

/// The first enabled host-realm mapper's answer (MIT `hostrealm.c:380-397`).
/// # Errors
/// Returns the mapper's failure or the refusal of its answer.
pub(super) fn realms(
    registry: &Registry,
    config: &Config,
    query: &RealmQuery<'_>,
) -> Result<Option<Vec<String>>, Error> {
    for mapper in order::enabled(
        &registry.realms,
        Interface::HostRealm,
        Some(config),
        |item| item.id(),
    ) {
        if let Some(realms) = realms_of(registry, mapper.as_ref(), query)? {
            return Ok(Some(realms));
        }
    }
    Ok(None)
}

/// The answer of the registered mapper `id`, `None` when it declines or no
/// mapper has that id.
/// # Errors
/// Returns the mapper's failure or the refusal of its answer.
#[cfg(feature = "tokio")]
pub(super) fn realms_from(
    registry: &Registry,
    id: &str,
    query: &RealmQuery<'_>,
) -> Result<Option<Vec<String>>, Error> {
    registry
        .realms
        .iter()
        .find(|mapper| mapper.id() == id)
        .map_or(Ok(None), |mapper| {
            realms_of(registry, mapper.as_ref(), query)
        })
}

/// Ask one mapper, validate its answer and report to the observers.
/// # Errors
/// Returns the mapper's failure or the refusal of its answer.
fn realms_of(
    registry: &Registry,
    mapper: &dyn HostRealm,
    query: &RealmQuery<'_>,
) -> Result<Option<Vec<String>>, Error> {
    let interface = Interface::HostRealm;
    let id = mapper.id();
    order::notify(&registry.observers, &Event::Consulted { interface, id });
    let answer = mapper
        .realms(query)
        .map_err(|source| failed(registry, interface, id, source))?;
    let Some(realms) = answer else {
        order::notify(&registry.observers, &Event::Declined { interface, id });
        return Ok(None);
    };
    bounded(interface, id, &realms, |realm| checks::name(realm))
        .inspect_err(|error| refuse(registry, interface, id, refusal_of(error)))?;
    order::notify(&registry.observers, &Event::Chosen { interface, id });
    Ok(Some(realms))
}

/// MIT `krb5_kuserok` (`localauth.c:386-406`): a denial or a failure denies,
/// otherwise at least one authorizer must allow.
pub(super) fn authorize(
    registry: &Registry,
    config: &Config,
    principal: &Principal,
    local_name: &str,
) -> bool {
    let interface = Interface::LocalAuth;
    let mut allowed = false;
    for authorizer in order::enabled(&registry.local, interface, Some(config), |item| item.id()) {
        let id = authorizer.id();
        order::notify(&registry.observers, &Event::Consulted { interface, id });
        match authorizer.userok(principal, local_name) {
            Ok(Decision::Allow) => {
                order::notify(&registry.observers, &Event::Chosen { interface, id });
                allowed = true;
            }
            Ok(Decision::Pass) => {
                order::notify(&registry.observers, &Event::Declined { interface, id });
            }
            Ok(Decision::Deny) => {
                order::notify(&registry.observers, &Event::Chosen { interface, id });
                return false;
            }
            Err(source) => {
                drop(source);
                order::notify(
                    &registry.observers,
                    &Event::Refused {
                        interface,
                        id,
                        reason: Refusal::Failed,
                    },
                );
                return false;
            }
        }
    }
    allowed
}

/// The first enabled name mapper's answer (MIT `localauth.c:409-436`).
/// # Errors
/// Returns the mapper's failure or the refusal of its answer.
pub(super) fn local_name(
    registry: &Registry,
    config: &Config,
    principal: &Principal,
) -> Result<Option<String>, Error> {
    let interface = Interface::LocalAuth;
    for mapper in order::enabled(&registry.local, interface, Some(config), |item| item.id()) {
        let id = mapper.id();
        order::notify(&registry.observers, &Event::Consulted { interface, id });
        let answer = mapper
            .local_name(principal)
            .map_err(|source| failed(registry, interface, id, source))?;
        let Some(name) = answer else {
            order::notify(&registry.observers, &Event::Declined { interface, id });
            continue;
        };
        if !checks::local_name(&name) {
            refuse(registry, interface, id, Refusal::Malformed);
            return Err(checks::malformed(interface, id, "invalid local name"));
        }
        order::notify(&registry.observers, &Event::Chosen { interface, id });
        return Ok(Some(name));
    }
    Ok(None)
}

/// The first server locator's answer.
/// # Errors
/// Returns the locator's failure or the refusal of its answer.
pub(super) fn locate(
    registry: &Registry,
    request: &LocateRequest<'_>,
) -> Result<Option<Vec<ServerAddress>>, Error> {
    let interface = Interface::ServerLocator;
    for locator in &registry.locators {
        let id = locator.id();
        order::notify(&registry.observers, &Event::Consulted { interface, id });
        let answer = locator
            .locate(request)
            .map_err(|source| failed(registry, interface, id, source))?;
        let Some(addresses) = answer else {
            order::notify(&registry.observers, &Event::Declined { interface, id });
            continue;
        };
        bounded(interface, id, &addresses, |address| {
            address.port != 0 && checks::host(&address.host)
        })
        .inspect_err(|error| refuse(registry, interface, id, refusal_of(error)))?;
        order::notify(&registry.observers, &Event::Chosen { interface, id });
        return Ok(Some(addresses));
    }
    Ok(None)
}
