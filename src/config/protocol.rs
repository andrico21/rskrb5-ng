//! Removed protocol selectors, shared by text configuration and serde admission.
use super::{ConfigDiagnostic, parse_boolean};
use crate::{
    crypto::selection,
    error::{Config as Error, Policy, RejectedFeature, RejectionReason},
};

/// Protocol selectors recognized even when disabled and therefore not rejected.
pub(super) fn recognized(key: &str) -> bool {
    key.starts_with("v4_")
        || key.starts_with("krb4_")
        || matches!(
            key,
            "pkinit_win2k"
                | "pkinit_draft9"
                | "flag_rsa_protocol"
                | "pkinit_rsa_only"
                | "pkinit_use_rsa"
                | "pkinit_rsa"
                | "pkinit_key_exchange"
                | "pkinit_kex"
                | "kpasswd_unprotected"
                | "kpasswd_cleartext"
                | "kpasswd_protocol"
                | "kpasswd_version"
        )
}

/// Parse a protocol relation without enabling an unsupported legacy mechanism.
/// Unrelated keys, including certificate identity/trust paths, are not mode selectors.
/// # Errors
/// Returns a typed permanent rejection for enabling removed protocol modes.
#[inline]
pub fn relation(raw_key: &str, raw_value: &str) -> Result<(), Error> {
    let key = raw_key.trim_end_matches('*').to_ascii_lowercase();
    let value = raw_value
        .trim_matches(super::profile_syntax::tag_whitespace)
        .trim_matches('"');
    let disabled = (value.is_empty() || parse_boolean(value).is_ok_and(|enabled| !enabled))
        && !matches!(key.as_str(), "kpasswd_version" | "kpasswd_protocol");
    if disabled {
        return Ok(());
    }
    let feature = match key.as_str() {
        "krb4_convert" | "v4_instance_convert" | "v4_name_convert" | "v4_realm" => {
            RejectedFeature::V4Conversion
        }
        "pkinit_win2k" | "pkinit_draft9" => RejectedFeature::Draft9Pkinit,
        "flag_rsa_protocol" | "pkinit_rsa_only" | "pkinit_use_rsa" | "pkinit_rsa" => {
            RejectedFeature::RsaPkinit
        }
        "pkinit_key_exchange" | "pkinit_kex"
            if matches!(
                value.to_ascii_lowercase().as_str(),
                "rsa" | "rsa-only" | "key-transport" | "dh-less"
            ) =>
        {
            RejectedFeature::RsaPkinit
        }
        "kpasswd_unprotected" | "kpasswd_cleartext" => RejectedFeature::UnprotectedPasswordChange,
        "kpasswd_protocol" | "kpasswd_version" => {
            if matches!(value.to_ascii_lowercase().as_str(), "protected" | "rfc3244") {
                return Ok(());
            }
            if let Ok(version) = value.parse::<u16>() {
                selection::password_change_version(version)?;
                return Ok(());
            }
            RejectedFeature::UnprotectedPasswordChange
        }
        _ if key.starts_with("v4_") => RejectedFeature::V4Conversion,
        _ if key.starts_with("krb4_") => RejectedFeature::KerberosV4,
        _ => return Ok(()),
    };
    Err(Policy::RejectedFeature {
        feature,
        reason: RejectionReason::RemovedAndInsecure,
    }
    .into())
}

/// Remove draft-9 preferences, preserving current preference order and diagnostics.
pub(super) fn preferences(ids: &mut Vec<i32>, diagnostics: &mut Vec<ConfigDiagnostic>) {
    ids.retain(|id| {
        if matches!(*id, 14_i32 | 15_i32) {
            diagnostics.push(ConfigDiagnostic::IgnoredPreauthType { id: *id });
            false
        } else {
            true
        }
    });
}
