//! C1 additions and relation classification at the profile boundary.

#[path = "libdefaults/c2.rs"]
pub(super) mod c2;
#[cfg(test)]
#[path = "libdefaults/completeness.rs"]
mod completeness;
#[path = "libdefaults/duration.rs"]
pub(super) mod duration;
#[path = "libdefaults/relations.rs"]
pub(crate) mod relations;

use super::{ConfigDiagnostic, Error, LibDefaults, ParseMode};

/// Apply the fail-closed rule after all selected fields have been decoded.
/// # Errors
/// Strict mode rejects every out-of-scope relation and every relation whose
/// consumer needs a leaf this build lacks; stricter unsupported policies are
/// rejected in both modes.
pub(super) fn classify(defaults: &mut LibDefaults, selected: &[String]) -> Result<(), Error> {
    for &(name, _kind, _mit_default, consumer, _rationale, _test) in &relations::RELATIONS {
        if !selected.iter().any(|key| key == name) {
            continue;
        }
        if let Some(feature) = missing_leaf(name).or_else(|| missing_localauth_leaf(name)) {
            let diagnostic = ConfigDiagnostic::FeatureUnavailable {
                relation: name,
                feature,
            };
            if defaults.parse_mode() == ParseMode::Strict {
                return Err(diagnostic.into_error());
            }
            defaults.enctype_diagnostics.push(diagnostic);
            continue;
        }
        if let Some(diagnostic) = super::diagnostic::out_of_scope(name, consumer) {
            if defaults.parse_mode() == ParseMode::Strict {
                return Err(diagnostic.into_error());
            }
            defaults.enctype_diagnostics.push(diagnostic);
        }
    }
    Ok(())
}

/// The leaf feature whose consumer `relation` needs, when this build lacks it
/// (plan 2 "Disabled leaves": `FeatureUnavailable`).
fn missing_leaf(relation: &str) -> Option<&'static str> {
    let spake = cfg!(feature = "spake");
    (relation == "spake_preauth_groups" && !spake).then_some("spake")
}

/// The `localauth` leaf, when `relation` is one of its consumers and this
/// build lacks it (plan 2 "Disabled leaves": `FeatureUnavailable`).
fn missing_localauth_leaf(relation: &str) -> Option<&'static str> {
    let localauth = cfg!(feature = "localauth");
    (matches!(relation, "k5login_authoritative" | "k5login_directory") && !localauth)
        .then_some("localauth")
}
