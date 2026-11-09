//! Unknown profile paths are reported without guessing their intended policy.

use alloc::collections::{BTreeMap, BTreeSet};

use super::{
    Config, ConfigDiagnostic, Error, Line, libdefaults::relations::RELATIONS,
    realm_relations::REALM_RELATIONS, realm_values,
};

/// Supported section names, including inert server-only configuration.
const SECTIONS: [&str; 8] = [
    "libdefaults",
    "realms",
    "domain_realm",
    "capaths",
    "appdefaults",
    "plugins",
    "kdcdefaults",
    "dbmodules",
];

/// Report unknown headers and leaf paths; recognized dynamic namespaces stay open.
/// # Errors
/// Strict mode rejects each unknown path rather than silently accepting typos.
pub(super) fn report(
    config: &mut Config,
    sections: &BTreeSet<String>,
    paths: &BTreeMap<Vec<String>, Vec<Line>>,
) -> Result<(), Error> {
    for section in sections {
        if !SECTIONS.contains(&section.as_str()) && section != "logging" {
            realm_values::report(
                ConfigDiagnostic::UnknownSection {
                    section: section.clone(),
                },
                config.libdefaults.parse_mode(),
                &mut config.libdefaults.enctype_diagnostics,
            )?;
        }
    }
    for path in paths.keys() {
        if !known(path) {
            realm_values::report(
                ConfigDiagnostic::UnknownRelation { path: path.clone() },
                config.libdefaults.parse_mode(),
                &mut config.libdefaults.enctype_diagnostics,
            )?;
        }
    }
    Ok(())
}

/// Whether a leaf is decoded or belongs to an intentionally application-defined scope.
fn known(path: &[String]) -> bool {
    match path {
        [section, rest @ ..]
            if !SECTIONS.contains(&section.as_str())
                || matches!(section.as_str(), "kdcdefaults" | "dbmodules") =>
        {
            !rest.is_empty()
        }
        [section, key] if section == "libdefaults" => {
            RELATIONS.iter().any(|row| row.0 == key)
                || matches!(key.as_str(), "no_addresses" | "safe_checksum_type")
                || super::protocol::recognized(key)
        }
        [section, _, key] if section == "realms" => {
            REALM_RELATIONS.iter().any(|row| row.0 == key) || super::protocol::recognized(key)
        }
        [section, _, map, _] if section == "realms" && map == "auth_to_local_names" => true,
        [section, _] if section == "domain_realm" => true,
        [section, _, _] if section == "capaths" => true,
        [section, rest @ ..] if section == "appdefaults" => (1..=3).contains(&rest.len()),
        [section, _, key] if section == "plugins" => {
            matches!(key.as_str(), "disable" | "enable_only" | "module")
        }
        _ => false,
    }
}

/// Report empty unknown subsections, which have no leaf relation to inspect.
/// # Errors
/// Strict mode refuses unrecognized subsection shapes.
pub(super) fn empty_scopes(
    config: &mut Config,
    scopes: &BTreeSet<Vec<String>>,
) -> Result<(), Error> {
    for path in scopes {
        if matches!(path.as_slice(), [section, _, key]
            if section == "realms" && key == "auth_to_local_names")
        {
            realm_values::report(
                ConfigDiagnostic::NotYetEffective {
                    relation: "auth_to_local_names",
                    package: "plan 2 WP-17",
                },
                config.libdefaults.parse_mode(),
                &mut config.libdefaults.enctype_diagnostics,
            )?;
        }
        let valid = match path.as_slice() {
            [section] => SECTIONS.contains(&section.as_str()) || section == "logging",
            [section, _] => matches!(
                section.as_str(),
                "realms" | "capaths" | "appdefaults" | "plugins"
            ),
            [section, _, key] => {
                section == "appdefaults" || (section == "realms" && key == "auth_to_local_names")
            }
            _ => false,
        };
        if !valid
            && path.first().is_some_and(|section| {
                SECTIONS.contains(&section.as_str())
                    && !matches!(section.as_str(), "kdcdefaults" | "dbmodules")
            })
        {
            realm_values::report(
                ConfigDiagnostic::UnknownRelation { path: path.clone() },
                config.libdefaults.parse_mode(),
                &mut config.libdefaults.enctype_diagnostics,
            )?;
        }
    }
    Ok(())
}
