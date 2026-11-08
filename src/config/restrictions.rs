//! Effective restrictive policy validation independent of configuration origin.

use alloc::collections::BTreeMap;

use super::{
    Config, Error, LibDefaults, Realm, Toggle,
    section_values::{Plugins, Value},
};

/// Reject restrictions whose consumers have not been implemented.
/// # Errors
/// Returns the named deferred relation before any authentication effect.
pub(crate) fn defaults(value: &LibDefaults) -> Result<(), Error> {
    for (name, restricted) in [
        ("noaddresses", !value.no_addresses.is_enabled()),
        ("request_timeout", !value.request_timeout.is_zero()),
        (
            "verify_ap_req_nofail",
            value.verify_ap_req_nofail.is_enabled(),
        ),
        (
            "client_aware_channel_bindings",
            value.client_aware_channel_bindings.is_enabled(),
        ),
        (
            "default_rcache_name",
            !value.default_rcache_name.is_empty() && value.default_rcache_name != "none:",
        ),
    ] {
        reject(name, restricted)?;
    }
    Ok(())
}

/// Validate whole configuration, including realm and client-plugin restrictions.
/// # Errors
/// Returns the named unsupported restriction.
pub(crate) fn config(value: &Config) -> Result<(), Error> {
    defaults(&value.libdefaults)?;
    for entry in &value.realms {
        realm(entry)?;
    }
    if let Some(entry) = value.plugins.get("clpreauth") {
        plugins(entry)?;
    }
    Ok(())
}

/// Validate a realm timestamp prohibition regardless of construction path.
/// # Errors
/// Returns the named unsupported restriction.
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

/// Admit only the typed Boolean timestamp policy at every construction boundary.
/// # Errors
/// Returns a named invalid Boolean or unsupported restriction.
pub(super) fn timestamp(value: Option<&Value>) -> Result<(), Error> {
    match value {
        None | Some(Value::Boolean(Toggle::Disabled)) => Ok(()),
        Some(Value::Boolean(Toggle::Enabled)) => reject("disable_encrypted_timestamp", true),
        Some(Value::Text(_) | Value::List(_) | Value::Choice(_) | Value::Locations(_)) => Err(
            Error::InvalidBoolean("disable_encrypted_timestamp".to_owned()),
        ),
    }
}

/// Validate restrictions on the currently implemented client preauthentication method.
/// # Errors
/// Returns the named unsupported restriction.
pub(super) fn plugins(value: &Plugins) -> Result<(), Error> {
    reject(
        "disable",
        value
            .disable
            .iter()
            .any(|name| name == "encrypted_timestamp"),
    )?;
    reject(
        "enable_only",
        !value.enable_only.is_empty()
            && !value
                .enable_only
                .iter()
                .any(|name| name == "encrypted_timestamp"),
    )
}

/// Central named refusal used by runtime and serde boundaries.
/// # Errors
/// Returns [`Error::NotYetEffective`] when the selected restriction cannot be honored.
pub(super) fn reject(relation: &'static str, restricted: bool) -> Result<(), Error> {
    if restricted {
        let package = match relation {
            "disable" | "enable_only" => "plan 2 WP-16",
            "disable_encrypted_timestamp" => "plan 2 WP-07",
            "default_rcache_name" => "plan 2 WP-20",
            _ => super::libdefaults::relations::RELATIONS
                .iter()
                .find(|row| row.0 == relation)
                .map_or("plan 2 WP-04", |row| row.3),
        };
        return Err(Error::NotYetEffective { relation, package });
    }
    Ok(())
}
