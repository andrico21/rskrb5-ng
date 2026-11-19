//! Profile providers and `module` resolution.

use super::{Error, Event, Interface, Refusal, Registry, order};
use crate::{
    config::{self, Config, MAX_INCLUDE_BYTES, ParseMode},
    error::Config as ConfigError,
};

/// Parse `text` with `module` resolved against `registry`.
/// # Errors
/// Returns the parser error, `UnsupportedDynamicModule` for an unregistered
/// profile provider, or the provider's failure or oversized output.
pub(super) fn compose(registry: &Registry, text: &str, mode: ParseMode) -> Result<Config, Error> {
    let names = order::module_names(registry);
    let Some((name, residual)) = config::profile_module_directive(text) else {
        return Ok(config::compose_with_modules(text, mode, names)?);
    };
    let provider = registry
        .profiles
        .iter()
        .find(|provider| provider.id() == name)
        .ok_or(Error::Config(ConfigError::UnsupportedDynamicModule))?;
    let interface = Interface::ProfileProvider;
    let id = provider.id();
    order::notify(&registry.observers, &Event::Consulted { interface, id });
    let produced = provider.profile(residual).map_err(|source| {
        order::notify(
            &registry.observers,
            &Event::Refused {
                interface,
                id,
                reason: Refusal::Failed,
            },
        );
        Error::CallFailed {
            interface,
            id: id.to_owned(),
            source,
        }
    })?;
    if produced.len() > MAX_INCLUDE_BYTES {
        order::notify(
            &registry.observers,
            &Event::Refused {
                interface,
                id,
                reason: Refusal::TooLarge,
            },
        );
        return Err(Error::OutputTooLarge {
            interface,
            id: id.to_owned(),
            limit: MAX_INCLUDE_BYTES,
        });
    }
    let parsed = config::compose_with_modules(&produced, mode, names).map_err(|error| {
        order::notify(
            &registry.observers,
            &Event::Refused {
                interface,
                id,
                reason: Refusal::Malformed,
            },
        );
        Error::Config(error)
    })?;
    order::notify(&registry.observers, &Event::Chosen { interface, id });
    Ok(parsed)
}
