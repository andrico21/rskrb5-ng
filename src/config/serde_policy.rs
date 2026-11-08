//! Serde selection guards; opaque cache/key records are not selecting configuration.
use alloc::collections::BTreeMap;
use core::time::Duration;

use serde::{Deserialize as _, Deserializer, de::Error as _};

use super::{EnctypeExpr, ParseMode, Toggle};

/// Refuse address-bearing requests until their consumer exists.
/// # Errors
/// Rejects malformed or unsupported restrictions through serde.
pub(super) fn addresses<'de, D>(deserializer: D) -> Result<Toggle, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Toggle::deserialize(deserializer)?;
    super::restrictions::reject("noaddresses", !value.is_enabled()).map_err(D::Error::custom)?;
    Ok(value)
}

/// Refuse unimplemented mandatory AP verification.
/// # Errors
/// Rejects malformed or unsupported restrictions through serde.
pub(super) fn verify<'de, D>(deserializer: D) -> Result<Toggle, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Toggle::deserialize(deserializer)?;
    super::restrictions::reject("verify_ap_req_nofail", value.is_enabled())
        .map_err(D::Error::custom)?;
    Ok(value)
}

/// Refuse unimplemented channel-binding-aware signaling.
/// # Errors
/// Rejects malformed or unsupported restrictions through serde.
pub(super) fn channel_binding<'de, D>(deserializer: D) -> Result<Toggle, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Toggle::deserialize(deserializer)?;
    super::restrictions::reject("client_aware_channel_bindings", value.is_enabled())
        .map_err(D::Error::custom)?;
    Ok(value)
}

/// Refuse unimplemented total request deadlines.
/// # Errors
/// Rejects malformed or unsupported restrictions through serde.
pub(super) fn deadline<'de, D>(deserializer: D) -> Result<Duration, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Duration::deserialize(deserializer)?;
    super::restrictions::reject("request_timeout", !value.is_zero()).map_err(D::Error::custom)?;
    Ok(value)
}

/// Refuse persistent replay stores while preserving unspecified and none selections.
/// # Errors
/// Rejects malformed or unsupported restrictions through serde.
pub(super) fn replay<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    super::restrictions::reject("default_rcache_name", !value.is_empty() && value != "none:")
        .map_err(D::Error::custom)?;
    Ok(value)
}

/// Validate typed realm policies during deserialization.
/// # Errors
/// Rejects malformed or unsupported restrictions through serde.
pub(super) fn realm_relations<'de, D>(
    deserializer: D,
) -> Result<BTreeMap<String, super::section_values::Value>, D::Error>
where
    D: Deserializer<'de>,
{
    let values = BTreeMap::<String, super::section_values::Value>::deserialize(deserializer)?;
    super::restrictions::realm_relations(&values).map_err(D::Error::custom)?;
    Ok(values)
}

/// Validate realm restrictions before returning a configuration.
/// # Errors
/// Rejects malformed or unsupported restrictions through serde.
pub(super) fn realms<'de, D>(deserializer: D) -> Result<Vec<super::Realm>, D::Error>
where
    D: Deserializer<'de>,
{
    let values = Vec::<super::Realm>::deserialize(deserializer)?;
    for realm in &values {
        super::restrictions::realm(realm).map_err(D::Error::custom)?;
    }
    Ok(values)
}

/// Apply client preauthentication restrictions to the named interface.
/// # Errors
/// Rejects malformed or unsupported restrictions through serde.
pub(super) fn plugins<'de, D>(
    deserializer: D,
) -> Result<BTreeMap<String, super::section_values::Plugins>, D::Error>
where
    D: Deserializer<'de>,
{
    let values = BTreeMap::<String, super::section_values::Plugins>::deserialize(deserializer)?;
    if let Some(value) = values.get("clpreauth") {
        super::restrictions::plugins(value).map_err(D::Error::custom)?;
    }
    Ok(values)
}
use crate::{
    crypto::selection,
    error::{Policy, RejectedFeature, RejectionReason},
};

/// Reject positive D2 names while preserving expressions for policy resolution.
/// # Errors
/// Returns serde's error envelope for a typed policy or expression rejection.
pub(super) fn enctypes<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let names = Vec::<String>::deserialize(deserializer)?;
    if !names.is_empty() {
        drop(
            EnctypeExpr::parse(&names.join(" "))
                .and_then(|expr| {
                    expr.resolve(Toggle::Enabled, Toggle::Enabled, ParseMode::Compatible)
                })
                .map_err(D::Error::custom)?,
        );
    }
    Ok(names)
}

/// Weak crypto is never a deserializable permission.
/// # Errors
/// Returns a serde error containing the permanent typed-policy explanation.
pub(super) fn weak<'de, D>(deserializer: D) -> Result<Toggle, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Toggle::deserialize(deserializer)?;
    if value.is_enabled() {
        return Err(D::Error::custom(Policy::RejectedFeature {
            feature: RejectedFeature::WeakCrypto,
            reason: RejectionReason::InsecureByDesign,
        }));
    }
    Ok(value)
}

/// Reject forbidden checksum selection at deserialization, not after use.
/// # Errors
/// Returns serde's error envelope for a permanent checksum-policy refusal.
pub(super) fn checksum<'de, D>(deserializer: D) -> Result<i32, D::Error>
where
    D: Deserializer<'de>,
{
    let id = i32::deserialize(deserializer)?;
    selection::reject_checksum(id).map_err(D::Error::custom)?;
    Ok(id)
}

/// Check unknown configuration relations at the serde boundary, then discard them.
/// # Errors
/// Returns serde's envelope for a prohibited protocol selection.
pub(super) fn relations<'de, D>(deserializer: D) -> Result<BTreeMap<String, String>, D::Error>
where
    D: Deserializer<'de>,
{
    let values = BTreeMap::<String, serde_json::Value>::deserialize(deserializer)?;
    for (key, value) in values {
        let text = match value {
            serde_json::Value::String(text) => text,
            serde_json::Value::Bool(enabled) => enabled.to_string(),
            serde_json::Value::Number(number) => number.to_string(),
            serde_json::Value::Null => String::new(),
            serde_json::Value::Array(_) | serde_json::Value::Object(_) => "{".to_owned(),
        };
        super::protocol::relation(&key, &text).map_err(D::Error::custom)?;
    }
    Ok(BTreeMap::new())
}

/// Preserve informational preference IDs so the diagnostic accessor can report them.
/// # Errors
/// Returns serde's error for malformed integer lists.
pub(super) fn preferences<'de, D>(deserializer: D) -> Result<Vec<i32>, D::Error>
where
    D: Deserializer<'de>,
{
    Vec::<i32>::deserialize(deserializer)
}
