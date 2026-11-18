//! Registration, deterministic order and `[plugins]` filtering.

use alloc::sync::Arc;

use super::{
    Error, Event, Extension, Interface, LibraryObserver, MAX_EXTENSIONS, Registry, checks,
};
use crate::config::Config;

/// Every interface, in the order `Registry`'s `Debug` lists them.
pub(super) const INTERFACES: [Interface; 8] = [
    Interface::ClientPreauth,
    Interface::CacheSelector,
    Interface::HostRealm,
    Interface::LocalAuth,
    Interface::ProfileProvider,
    Interface::ServerLocator,
    Interface::GssMechanism,
    Interface::LibraryObserver,
];

/// Validate and append one provider.
/// # Errors
/// Returns the id, duplicate, count or interface-specific registration error.
pub(super) fn register(registry: &mut Registry, extension: Extension) -> Result<(), Error> {
    match extension {
        #[cfg(feature = "messages")]
        Extension::ClientPreauth(item) => {
            checks::preauth_types(item.id(), item.pa_types())?;
            push(
                &mut registry.preauth,
                item,
                Interface::ClientPreauth,
                |entry| entry.id(),
            )
        }
        Extension::CacheSelector(item) => push(
            &mut registry.selectors,
            item,
            Interface::CacheSelector,
            |entry| entry.id(),
        ),
        Extension::HostRealm(item) => {
            push(&mut registry.realms, item, Interface::HostRealm, |entry| {
                entry.id()
            })
        }
        Extension::LocalAuth(item) => {
            push(&mut registry.local, item, Interface::LocalAuth, |entry| {
                entry.id()
            })
        }
        Extension::ProfileProvider(item) => push(
            &mut registry.profiles,
            item,
            Interface::ProfileProvider,
            |entry| entry.id(),
        ),
        Extension::ServerLocator(item) => push(
            &mut registry.locators,
            item,
            Interface::ServerLocator,
            |entry| entry.id(),
        ),
        Extension::GssMechanism(item) => {
            checks::mechanism(&registry.mechanisms, item.id(), item.oid())?;
            push(
                &mut registry.mechanisms,
                item,
                Interface::GssMechanism,
                |entry| entry.id(),
            )
        }
        Extension::LibraryObserver(item) => push(
            &mut registry.observers,
            item,
            Interface::LibraryObserver,
            |entry| entry.id(),
        ),
    }
}

/// Append `item` after checking its id against the interface's providers.
/// # Errors
/// Returns `InvalidId`, `DuplicateId` or `TooManyExtensions`.
fn push<T>(
    items: &mut Vec<Arc<T>>,
    item: Arc<T>,
    interface: Interface,
    id: fn(&T) -> &str,
) -> Result<(), Error>
where
    T: ?Sized,
{
    let name = id(&item);
    checks::id(interface, name)?;
    if items.iter().any(|entry| id(entry) == name) {
        return Err(Error::DuplicateId {
            interface,
            id: name.to_owned(),
        });
    }
    if items.len() >= MAX_EXTENSIONS {
        return Err(Error::TooManyProviders {
            interface,
            limit: MAX_EXTENSIONS,
        });
    }
    items.push(item);
    Ok(())
}

/// The providers of `items` in consultation order: `disable` removes, then a
/// non-empty `enable_only` keeps and reorders (MIT `plugin.c:255-299`).
pub(super) fn enabled<'item, T>(
    items: &'item [Arc<T>],
    interface: Interface,
    config: Option<&Config>,
    id: fn(&T) -> &str,
) -> Vec<&'item Arc<T>>
where
    T: ?Sized,
{
    let restrictions = config
        .filter(|_| interface.configurable())
        .and_then(|value| value.plugins.get(interface.name()));
    let Some(plugins) = restrictions else {
        return items.iter().collect();
    };
    let kept: Vec<&Arc<T>> = items
        .iter()
        .filter(|item| !plugins.disable.iter().any(|name| name == id(item)))
        .collect();
    if plugins.enable_only.is_empty() {
        return kept;
    }
    let mut ordered = Vec::new();
    for name in &plugins.enable_only {
        if let Some(item) = kept.iter().find(|item| id(item) == name)
            && !ordered
                .iter()
                .any(|chosen: &&Arc<T>| Arc::ptr_eq(chosen, item))
        {
            ordered.push(*item);
        }
    }
    ordered
}

/// Provider ids of one interface, filtered by `config` when given.
pub(super) fn ids<'registry>(
    registry: &'registry Registry,
    interface: Interface,
    config: Option<&Config>,
) -> Vec<&'registry str> {
    match interface {
        #[cfg(feature = "messages")]
        Interface::ClientPreauth => enabled(&registry.preauth, interface, config, |item| item.id())
            .into_iter()
            .map(|item| item.id())
            .collect(),
        #[cfg(not(feature = "messages"))]
        Interface::ClientPreauth => Vec::new(),
        Interface::CacheSelector => {
            enabled(&registry.selectors, interface, config, |item| item.id())
                .into_iter()
                .map(|item| item.id())
                .collect()
        }
        Interface::HostRealm => enabled(&registry.realms, interface, config, |item| item.id())
            .into_iter()
            .map(|item| item.id())
            .collect(),
        Interface::LocalAuth => enabled(&registry.local, interface, config, |item| item.id())
            .into_iter()
            .map(|item| item.id())
            .collect(),
        Interface::ProfileProvider => registry.profiles.iter().map(|item| item.id()).collect(),
        Interface::ServerLocator => registry.locators.iter().map(|item| item.id()).collect(),
        Interface::GssMechanism => registry.mechanisms.iter().map(|item| item.id()).collect(),
        Interface::LibraryObserver => registry.observers.iter().map(|item| item.id()).collect(),
    }
}

/// Every `[plugins]` module name the registry resolves, as `(interface, id)`.
pub(super) fn module_names(registry: &Registry) -> Arc<[(&'static str, String)]> {
    INTERFACES
        .iter()
        .filter(|interface| interface.configurable())
        .flat_map(|interface| {
            ids(registry, *interface, None)
                .into_iter()
                .map(|id| (interface.name(), id.to_owned()))
        })
        .collect()
}

/// Hand one redacted event to every observer.
pub(super) fn notify(observers: &[Arc<dyn LibraryObserver>], event: &Event<'_>) {
    for observer in observers {
        observer.observe(event);
    }
}
