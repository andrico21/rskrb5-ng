//! Registration, deterministic order and `[plugins]` filtering.

use alloc::sync::Arc;

use super::{
    Error, Event, Extension, Interface, LibraryObserver, MAX_EXTENSIONS, Registry, checks, stores,
};
use crate::config::Config;

/// Every interface, in the order `Registry`'s `Debug` lists them.
pub(super) const INTERFACES: [Interface; 9] = [
    Interface::ClientPreauth,
    Interface::CacheSelector,
    Interface::HostRealm,
    Interface::LocalAuth,
    Interface::ProfileProvider,
    Interface::ServerLocator,
    Interface::GssMechanism,
    Interface::LibraryObserver,
    Interface::StoreProvider,
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
        Extension::StoreProvider(item) => {
            stores::admit(&registry.stores, &*item)?;
            push(
                &mut registry.stores,
                item,
                Interface::StoreProvider,
                |entry| entry.id(),
            )
        }
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

/// The providers of `items` in consultation order (MIT `plugin.c:302-347`):
/// [`arrange`] over their ids.
pub(super) fn enabled<'item, T>(
    items: &'item [Arc<T>],
    interface: Interface,
    config: Option<&Config>,
    id: fn(&T) -> &str,
) -> Vec<&'item Arc<T>>
where
    T: ?Sized,
{
    let Some(profile) = config else {
        return items.iter().collect();
    };
    arrange(interface, profile, items.iter().map(|item| id(item)))
        .into_iter()
        .filter_map(|name| items.iter().find(|item| id(item) == name))
        .collect()
}

/// The module names of `interface` in consultation order (MIT
/// `configure_interface`, `plugin.c:302-347`).
///
/// `names` are the registered providers in registration order followed by the
/// built-in modules in MIT's registration order. Configured `module` names come
/// first, a repeated name keeps its first place, `disable` removes, then a
/// non-empty `enable_only` keeps and reorders. Names match exactly
/// (`strcmp`). An interface without `[plugins]` controls keeps `names`.
pub(crate) fn arrange<'name, I>(interface: Interface, config: &Config, names: I) -> Vec<&'name str>
where
    I: IntoIterator<Item = &'name str>,
{
    let listed: Vec<&str> = names.into_iter().collect();
    let restrictions = interface
        .configurable()
        .then(|| config.plugins.get(interface.name()))
        .flatten();
    let Some(plugins) = restrictions else {
        let mut unique: Vec<&str> = Vec::new();
        for name in listed {
            if !unique.contains(&name) {
                unique.push(name);
            }
        }
        return unique;
    };
    let configured = plugins
        .module
        .iter()
        .filter_map(|name| listed.iter().copied().find(|item| item == name));
    let mut full: Vec<&str> = Vec::new();
    for name in configured.chain(listed.iter().copied()) {
        if !full.contains(&name) && !plugins.disable.iter().any(|item| item == name) {
            full.push(name);
        }
    }
    if plugins.enable_only.is_empty() {
        return full;
    }
    plugins
        .enable_only
        .iter()
        .filter_map(|name| full.iter().copied().find(|item| item == name))
        .fold(Vec::new(), |mut ordered, name| {
            if !ordered.contains(&name) {
                ordered.push(name);
            }
            ordered
        })
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
        Interface::StoreProvider => registry.stores.iter().map(|item| item.id()).collect(),
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
