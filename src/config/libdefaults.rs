//! C1 additions and deferred-relation classification at the profile boundary.

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
/// Strict mode rejects every deferred relation; stricter unsupported policies
/// are rejected in both modes, with the owning plan-2 work package.
pub(super) fn classify(defaults: &mut LibDefaults, selected: &[String]) -> Result<(), Error> {
    for &(name, _kind, _mit_default, consumer, _rationale, _test) in &relations::RELATIONS {
        if !selected
            .iter()
            .any(|key| key == name || (name == "noaddresses" && key == "no_addresses"))
            || !consumer.starts_with("plan 2 ")
        {
            continue;
        }
        let stricter = match name {
            "default_rcache_name" => defaults.default_rcache_name != "none:",
            "extra_addresses" => {
                !defaults.no_addresses.is_enabled() && !defaults.extra_addresses.is_empty()
            }
            _ => c2::stricter(defaults, name),
        };
        if stricter || defaults.parse_mode() == ParseMode::Strict {
            return Err(Error::NotYetEffective {
                relation: name,
                package: consumer,
            });
        }
        defaults
            .enctype_diagnostics
            .push(ConfigDiagnostic::NotYetEffective {
                relation: name,
                package: consumer,
            });
    }
    Ok(())
}
