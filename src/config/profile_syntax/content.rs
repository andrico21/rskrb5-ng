//! One profile line after any pending opening brace: headers, closers and relations.

use core::slice;

use super::{
    super::{Error, Line, MAX_INCLUDE_DEPTH, profile::Profile, protocol},
    Scope, State, invalid, local_mapping, marker, quoted, relation_tag, tag_whitespace,
};

/// Parse a line after resolving any pending opening brace.
/// # Errors
/// Returns the typed profile syntax or policy error.
pub(super) fn apply(state: &mut State, line: &Line, profile: &mut Profile) -> Result<(), Error> {
    let text = line.text.as_str();
    if let Some(header) = text.strip_prefix('[') {
        state.finish(profile)?;
        let (raw_name, suffix) = header.split_once(']').ok_or_else(|| invalid(line))?;
        let tail = suffix.strip_prefix('*').unwrap_or(suffix);
        (!raw_name.is_empty() && tail.chars().all(tag_whitespace)).ok_or_else(|| invalid(line))?;
        let name = raw_name.to_owned();
        let discarded = profile.closed(slice::from_ref(&name));
        if !discarded {
            profile.scope(slice::from_ref(&name));
        }
        if !discarded && suffix.starts_with('*') {
            profile.finalize(vec![name.clone()]);
        }
        state.scopes.push(Scope {
            name,
            final_marker: suffix.starts_with('*'),
            discarded,
        });
        return Ok(());
    }
    if matches!(text, "}" | "}*") {
        (state.scopes.len() > 1).ok_or_else(|| invalid(line))?;
        state.close(profile, text == "}*");
        return Ok(());
    }
    let (raw_tag, raw) = text.split_once('=').ok_or_else(|| invalid(line))?;
    (!state.scopes.is_empty()).ok_or_else(|| invalid(line))?;
    let (tag, tag_final) = marker(relation_tag(raw_tag).ok_or_else(|| invalid(line))?);
    (!state.dynamic_module(tag)
        || state.local_mapping_assignment(text)
        || state.registered_module(text))
    .ok_or(Error::UnsupportedDynamicModule)?;
    (!tag.is_empty()).ok_or_else(|| invalid(line))?;
    let section = state.scopes.first().map_or("", |scope| scope.name.as_str());
    // MIT compares every name with `strcmp` (prof_tree.c:615); nothing is folded.
    let key = if section == "libdefaults" && tag == "no_addresses" {
        "noaddresses"
    } else {
        tag
    }
    .to_owned();
    let mut path: Vec<String> = state
        .scopes
        .iter()
        .map(|scope| scope.name.clone())
        .collect();
    path.push(key.clone());
    let discarded = state.scopes.iter().any(|scope| scope.discarded) || profile.child_closed(&path);
    let value = raw.trim_matches(tag_whitespace);
    if value == "{"
        || (value.is_empty() && matches!(section, "realms" | "appdefaults" | "plugins" | "capaths"))
    {
        state.pending_brace = value.is_empty();
        protocol::relation(&key, "{")?;
        if state.scopes.len() > MAX_INCLUDE_DEPTH {
            return Err(Error::IncludeTooDeep {
                depth: state.scopes.len(),
                limit: MAX_INCLUDE_DEPTH,
            });
        }
        if !discarded {
            profile.scope(&path);
            if tag_final {
                profile.finalize(path);
            }
        }
        state.scopes.push(Scope {
            name: key,
            final_marker: tag_final,
            discarded,
        });
        return Ok(());
    }
    let (body, value_final) = if matches!(key.as_str(), "auth_to_local" | "pkinit_cert_match") {
        (value, false)
    } else {
        marker(value)
    };
    let decoded = quoted(body, line)?;
    if section != "domain_realm" && !local_mapping(&path) {
        protocol::relation(&key, &decoded)?;
    }
    if !discarded {
        profile.relation(
            path.clone(),
            Line {
                number: line.number,
                text: format!("{key} = {decoded}"),
                value: Some(decoded),
            },
        );
        if tag_final || value_final {
            profile.finalize(path);
        }
    }
    Ok(())
}
