//! Effective restrictive policy validation independent of configuration origin.

use alloc::collections::BTreeMap;

use super::{Config, Error, LibDefaults, Realm, Toggle, section_values::Value};
#[cfg(feature = "messages")]
use crate::error::Policy;
use crate::replay::RcacheName;

/// Preserve permanent policy causes when admitting configured acceptors.
#[cfg(feature = "messages")]
pub(crate) const fn configuration_policy(error: &Error) -> Policy {
    if let Error::Policy(policy)
    | Error::RejectedEnctype {
        source: policy,
        token: _,
    } = error
    {
        *policy
    } else {
        Policy::InvalidConfiguration
    }
}

/// Refuse a `default_rcache_name` that no replay store can open: it must be
/// empty (unset) or a MIT `type:residual` name of a known type.
/// # Errors
/// Returns [`Error::InvalidReplayCacheName`] naming the value.
pub(crate) fn rcache_name(value: &str) -> Result<(), Error> {
    if value.is_empty() || RcacheName::parse(value).is_ok() {
        Ok(())
    } else {
        Err(Error::InvalidReplayCacheName(value.to_owned()))
    }
}

/// Validate the library defaults at every construction boundary.
/// # Errors
/// Returns the malformed replay-cache name before any authentication effect.
pub(crate) fn defaults(value: &LibDefaults) -> Result<(), Error> {
    rcache_name(&value.default_rcache_name)
}

/// Validate whole configuration, including realm restrictions.
/// # Errors
/// Returns the malformed replay-cache name or the named realm restriction error.
pub(crate) fn config(value: &Config) -> Result<(), Error> {
    defaults(&value.libdefaults)?;
    for entry in &value.realms {
        realm(entry)?;
    }
    Ok(())
}

/// Validate a realm timestamp prohibition regardless of construction path.
/// # Errors
/// Returns permanent protocol rejection or the named malformed restriction.
pub(super) fn realm(value: &Realm) -> Result<(), Error> {
    #[cfg(feature = "serde")]
    for (name, selection) in &value.protocol_relations {
        super::protocol::relation(name, selection)?;
    }
    realm_relations(&value.relations)
}

/// Admit typed realm selectors using the same permanent policy as profile text.
/// # Errors
/// Returns permanent protocol rejection or malformed/unsupported restriction errors.
pub(super) fn realm_relations(values: &BTreeMap<String, Value>) -> Result<(), Error> {
    timestamp(values.get("disable_encrypted_timestamp"))?;
    for (name, value) in values {
        if super::protocol::recognized(&name.trim_end_matches('*').to_ascii_lowercase()) {
            let scalar = match value {
                Value::Boolean(Toggle::Enabled) => "true",
                Value::Boolean(Toggle::Disabled) => "false",
                Value::Text(text) | Value::Choice(text) => text,
                Value::List(_) | Value::Locations(_) => {
                    return Err(Error::InvalidBoolean(name.clone()));
                }
            };
            super::protocol::relation(name, scalar)?;
        }
    }
    Ok(())
}

/// Admit only the typed Boolean timestamp policy at every construction boundary;
/// both values are effective (`client::stepwise` honours `true`).
/// # Errors
/// Returns a named invalid Boolean.
pub(super) fn timestamp(value: Option<&Value>) -> Result<(), Error> {
    match value {
        None | Some(Value::Boolean(Toggle::Disabled | Toggle::Enabled)) => Ok(()),
        Some(Value::Text(_) | Value::List(_) | Value::Choice(_) | Value::Locations(_)) => Err(
            Error::InvalidBoolean("disable_encrypted_timestamp".to_owned()),
        ),
    }
}
