//! Typed realm admission and deferred-policy reporting.

use super::{
    ConfigDiagnostic, Error, Line, ParseMode, Realm, Toggle, parse_assignment, parse_boolean,
    realm_relations::REALM_RELATIONS,
    section_values::{Location, Value},
};

/// Decode selected values using the realm catalogue's type and classification.
/// # Errors
/// Rejects malformed values, strict-mode deferred features and timestamp prohibition.
pub(super) fn decode(
    realm: &mut Realm,
    key: &str,
    lines: &[Line],
) -> Result<Option<ConfigDiagnostic>, Error> {
    let Some(&(name, kind, _default, consumer, _rationale, _test)) =
        REALM_RELATIONS.iter().find(|row| row.0 == key)
    else {
        return Ok(None);
    };
    let values = lines
        .iter()
        .map(|line| parse_assignment(line, "realms").map(|(_, value)| value.to_owned()))
        .collect::<Result<Vec<_>, _>>()?;
    let first = values.first().map_or("", String::as_str);
    let value = match kind {
        "boolean" | "rejected boolean" => Value::Boolean(Toggle::from_bool(parse_boolean(first)?)),
        "kpKDC|kpServerAuth|none" => choice(first, &["kpKDC", "kpServerAuth", "none"])?,
        "1024|2048|4096|P-256|P-384|P-521" => {
            choice(first, &["1024", "2048", "4096", "P-256", "P-384", "P-521"])?
        }
        "location list" | "identity location list" | "identity location" => Value::Locations(
            values
                .iter()
                .map(|text| location(text, kind.starts_with("identity")))
                .collect::<Result<Vec<_>, _>>()?,
        ),
        "rule list" => {
            for text in &values {
                if text != "DEFAULT" && !text.starts_with("RULE:") {
                    return Err(invalid(text));
                }
            }
            Value::List(values)
        }
        "certificate rule list" => {
            for text in &values {
                let body = text
                    .strip_prefix("&&")
                    .or_else(|| text.strip_prefix("||"))
                    .unwrap_or(text);
                if !["<SUBJECT>", "<ISSUER>", "<SAN>", "<EKU>", "<KU>"]
                    .iter()
                    .any(|prefix| body.starts_with(prefix))
                {
                    return Err(invalid(text));
                }
            }
            Value::List(values)
        }
        "endpoint list" | "hostname list" | "string list" => Value::List(values),
        _ => Value::Text(first.to_owned()),
    };
    drop(realm.relations.insert(name.to_owned(), value));
    if let Some(feature) = missing_leaf(consumer) {
        return Ok(Some(ConfigDiagnostic::FeatureUnavailable {
            relation: name,
            feature,
        }));
    }
    if consumer.starts_with("plan 2 ") {
        Ok(Some(ConfigDiagnostic::NotYetEffective {
            relation: name,
            package: consumer,
        }))
    } else {
        Ok(None)
    }
}

/// The leaf feature a relation's consumer needs, when this build lacks it
/// (plan 2 "Disabled leaves": `FeatureUnavailable`).
fn missing_leaf(consumer: &str) -> Option<&'static str> {
    let pkinit = cfg!(feature = "pkinit");
    (consumer.ends_with("(leaf pkinit)") && !pkinit).then_some("pkinit")
}

/// Promote a deferred diagnostic without inventing a second classification system.
/// # Errors
/// Strict mode rejects all returned section diagnostics.
pub(super) fn report(
    diagnostic: ConfigDiagnostic,
    mode: ParseMode,
    output: &mut Vec<ConfigDiagnostic>,
) -> Result<(), Error> {
    if mode == ParseMode::Strict {
        return Err(diagnostic.into_error());
    }
    output.push(diagnostic);
    Ok(())
}

/// An exact MIT enum vocabulary, not an arbitrary string value.
/// # Errors
/// Rejects values outside the declared choice list.
fn choice(text: &str, choices: &[&str]) -> Result<Value, Error> {
    choices
        .iter()
        .find(|choice| choice.eq_ignore_ascii_case(text))
        .map(|choice| Value::Choice((*choice).to_owned()))
        .ok_or_else(|| invalid(text))
}

/// Parse an inert reference without opening paths, variables or native modules.
/// # Errors
/// Rejects missing prefixes/residuals and identity-only prefixes in trust locations.
fn location(text: &str, identity: bool) -> Result<Location, Error> {
    let (prefix, residual) = text.split_once(':').ok_or_else(|| invalid(text))?;
    if residual.is_empty() && prefix != "PKCS11" {
        return Err(invalid(text));
    }
    match prefix {
        "FILE" => Ok(Location::File(residual.to_owned())),
        "DIR" => Ok(Location::Directory(residual.to_owned())),
        "ENV" => Ok(Location::Environment(residual.to_owned())),
        "PKCS12" if identity => Ok(Location::Pkcs12(residual.to_owned())),
        "PKCS11" if identity => Ok(Location::Pkcs11(residual.to_owned())),
        _ => Err(invalid(text)),
    }
}

/// Reuse the existing typed realm syntax error for malformed relation payloads.
fn invalid(text: &str) -> Error {
    Error::InvalidRealmsSection(text.to_owned())
}
