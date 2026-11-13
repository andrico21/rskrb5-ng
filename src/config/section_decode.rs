//! Typed profile subtrees decoded after scalar libdefaults policy resolution.

use alloc::collections::BTreeMap;

use super::{
    Config, ConfigDiagnostic, Error, Line, ParseMode, parse_assignment, realm_values,
    section_values::Route,
};

/// Non-realm dynamic-relation catalogue, with the same six-column schema.
pub(crate) const SECTION_RELATIONS: [(&str, &str, &str, &str, &str, &str); 6] = [
    (
        "domain_realm",
        "DNS-name -> realm map",
        "unset",
        "Config::resolve_realm",
        "Exact then longest suffix; dotted suffix excludes apex",
        "domain_realm",
    ),
    (
        "capaths",
        "client -> server -> direct/via graph",
        "unset",
        "plan 2 WP-11",
        "No profile-driven routing/validation; current acceptor denies cross-realm without explicit policy; diagnostic",
        "capaths",
    ),
    (
        "appdefaults",
        "hierarchical string/boolean lookup",
        "application-defined",
        "Config::appdefault; Config::appdefault_boolean",
        "Caller chooses type and consumes result; no implicit behavior",
        "appdefaults",
    ),
    (
        "disable",
        "repeated module names",
        "empty",
        "plan 2 WP-16",
        "Restrictions affecting current timestamp preauth fail; nonexistent plugin behavior only diagnosed",
        "disable",
    ),
    (
        "enable_only",
        "repeated module names",
        "all built-ins",
        "plan 2 WP-16",
        "Excluding current timestamp preauth fails; nonexistent plugin behavior only diagnosed",
        "enable_only",
    ),
    (
        "module",
        "rejected module descriptor",
        "empty",
        "profile_syntax::State::line",
        "Dynamic modules always rejected before composition",
        "module",
    ),
];

/// Decode graph, applications, realm maps and plugin lists without executing them.
/// # Errors
/// Rejects malformed subtrees, mixed direct/intermediate routes, strict diagnostics
/// and restrictions on the client's existing encrypted-timestamp mechanism.
pub(super) fn finish(
    config: &mut Config,
    values: &BTreeMap<Vec<String>, Vec<Line>>,
) -> Result<(), Error> {
    for (path, lines) in values {
        let Some(first) = lines.first() else {
            continue;
        };
        let (_, text) = parse_assignment(first, "profile")?;
        match path.as_slice() {
            [section, rest @ ..] if section == "appdefaults" => {
                if !(1..=3).contains(&rest.len()) {
                    return Err(invalid(first));
                }
                config.applications.insert(rest.to_vec(), text.to_owned());
            }
            [section, client, server] if section == "capaths" => {
                let realms = strings(lines)?;
                if let Some(line) = unusable_name_line(lines, &realms) {
                    return Err(invalid(line));
                }
                let route = if realms.iter().all(|name| name == ".") {
                    Route::Direct
                } else {
                    if realms.iter().any(|name| name == ".") {
                        // The first value decides the route kind; the first value of the
                        // other kind is the one that mixes them.
                        let first_is_direct = realms.first().is_some_and(|name| name == ".");
                        let mixing = lines
                            .iter()
                            .zip(&realms)
                            .find(|&(_, name)| (name == ".") != first_is_direct);
                        return Err(invalid(mixing.map_or(first, |(line, _)| line)));
                    }
                    Route::Via(realms)
                };
                drop(
                    config
                        .capaths
                        .entry(client.clone())
                        .or_default()
                        .insert(server.clone(), route),
                );
                diagnostic(config, "capaths")?;
            }
            [section, realm, subsection, name]
                if section == "realms" && subsection == "auth_to_local_names" =>
            {
                if let Some(entry) = config.realms.iter_mut().find(|entry| entry.name == *realm) {
                    drop(
                        entry
                            .auth_to_local_names
                            .insert(name.clone(), text.to_owned()),
                    );
                }
            }
            [section, interface, key]
                if section == "plugins" && matches!(key.as_str(), "disable" | "enable_only") =>
            {
                let names = strings(lines)?;
                if let Some(line) = unusable_name_line(lines, &names) {
                    return Err(invalid(line));
                }
                if interface == "clpreauth"
                    && ((key == "disable"
                        && names.iter().any(|name| name == "encrypted_timestamp"))
                        || (key == "enable_only"
                            && !names.iter().any(|name| name == "encrypted_timestamp")))
                {
                    return Err(Error::NotYetEffective {
                        relation: if key == "disable" {
                            "disable"
                        } else {
                            "enable_only"
                        },
                        package: "plan 2 WP-16",
                    });
                }
                let entry = config.plugins.entry(interface.clone()).or_default();
                if key == "disable" {
                    entry.disable = names;
                } else {
                    entry.enable_only = names;
                }
                diagnostic(config, key)?;
            }
            _ => {}
        }
    }
    Ok(())
}

/// Report a catalogue-backed section relation after its typed admission.
/// # Errors
/// Strict mode rejects deferred section consumers.
fn diagnostic(config: &mut Config, key: &str) -> Result<(), Error> {
    if let Some(&(name, _kind, _default, package, _rationale, _test)) =
        SECTION_RELATIONS.iter().find(|row| row.0 == key)
    {
        realm_values::report(
            ConfigDiagnostic::NotYetEffective {
                relation: name,
                package,
            },
            config.libdefaults.parse_mode(),
            &mut config.libdefaults.enctype_diagnostics,
        )?;
    }
    Ok(())
}

/// Preserve the values of repeated relations in source order.
/// # Errors
/// Returns assignment syntax errors without silently dropping entries.
fn strings(lines: &[Line]) -> Result<Vec<String>, Error> {
    lines
        .iter()
        .map(|line| parse_assignment(line, "profile").map(|(_, value)| value.to_owned()))
        .collect()
}

/// The line of the first value that is empty or contains tag whitespace.
fn unusable_name_line<'source>(lines: &'source [Line], values: &[String]) -> Option<&'source Line> {
    lines
        .iter()
        .zip(values)
        .find(|&(_, name)| name.is_empty() || name.contains(super::profile_syntax::tag_whitespace))
        .map(|(line, _)| line)
}

/// Typed invalid profile shape, carrying the original source line.
fn invalid(line: &Line) -> Error {
    Error::InvalidLine {
        section: "profile",
        line: line.number,
        text: line.text.clone(),
    }
}

/// Report even empty server-only sections from explicit header inventory.
/// # Errors
/// Strict mode rejects these sections instead of accepting unused server policy.
pub(super) fn server(section: &'static str, config: &mut Config) -> Result<(), Error> {
    let mode: ParseMode = config.libdefaults.parse_mode();
    realm_values::report(
        ConfigDiagnostic::ServerOnly { section },
        mode,
        &mut config.libdefaults.enctype_diagnostics,
    )
}

/// Select scalar or repeated realm values using the catalogue's declared kind.
/// # Errors
/// Propagates typed value and deferred-policy failures for each selected relation.
pub(super) fn realms(
    config: &mut Config,
    values: &BTreeMap<Vec<String>, Vec<Line>>,
) -> Result<(), Error> {
    use super::realm_relations::REALM_RELATIONS;
    let mode = config.libdefaults.parse_mode();
    for (path, lines) in values {
        if let [section, name, key] = path.as_slice()
            && section == "realms"
            && let Some(realm) = config.realms.iter_mut().find(|realm| realm.name == *name)
        {
            let repeated = REALM_RELATIONS
                .iter()
                .find(|row| row.0 == key)
                .is_some_and(|row| row.1.ends_with("list"));
            let selected = if repeated {
                lines.as_slice()
            } else {
                lines.get(..1).unwrap_or_default()
            };
            if let Some(diagnostic) = realm_values::decode(realm, key, selected)? {
                realm_values::report(
                    diagnostic,
                    mode,
                    &mut config.libdefaults.enctype_diagnostics,
                )?;
            }
        }
    }
    Ok(())
}
