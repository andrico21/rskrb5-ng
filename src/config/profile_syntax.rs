//! Per-source grammar state and quote-aware comment boundaries.

use core::slice;

use super::{Error, Line, profile::Profile, protocol};

/// One open syntactic scope, including a final marker pending its close.
#[derive(Default)]
struct Scope {
    /// Path component.
    name: String,
    /// Close this scope to later definitions when leaving it.
    final_marker: bool,
    /// An earlier final marker suppresses this entire block.
    discarded: bool,
}

/// Parse state never shared between a parent and an included file.
#[derive(Default)]
pub(super) struct State {
    /// Section followed by open subsection scopes.
    scopes: Vec<Scope>,
    /// An empty assignment requires the next structural line to open its subsection.
    pending_brace: bool,
}

impl State {
    /// Process one non-directive line into the shared profile.
    ///
    /// # Errors
    /// Rejects malformed headers, assignments, quotes and unbalanced braces.
    pub(super) fn line(&mut self, line: &Line, profile: &mut Profile) -> Result<(), Error> {
        if self.pending_brace {
            self.pending_brace = false;
            return (line.text == "{").ok_or_else(|| invalid(line));
        }
        self.content(line, profile)
    }

    /// Parse a line after resolving any pending opening brace.
    /// # Errors
    /// Returns the typed profile syntax or policy error.
    fn content(&mut self, line: &Line, profile: &mut Profile) -> Result<(), Error> {
        let text = line.text.as_str();
        if let Some(header) = text.strip_prefix('[') {
            self.finish(profile)?;
            let (raw_name, suffix) = header.split_once(']').ok_or_else(|| invalid(line))?;
            if raw_name.trim().is_empty() || !matches!(suffix.trim(), "" | "*") {
                return Err(invalid(line));
            }
            let name = raw_name.trim().to_ascii_lowercase();
            let discarded = profile.closed(slice::from_ref(&name));
            if !discarded {
                profile.scope(slice::from_ref(&name));
            }
            if !discarded && suffix.trim() == "*" {
                profile.finalize(vec![name.clone()]);
            }
            self.scopes.push(Scope {
                name,
                final_marker: suffix.trim() == "*",
                discarded,
            });
            return Ok(());
        }
        if matches!(text, "}" | "}*") {
            (self.scopes.len() > 1).ok_or_else(|| invalid(line))?;
            self.close(profile, text == "}*");
            return Ok(());
        }
        let (raw_tag, raw) = text.split_once('=').ok_or_else(|| invalid(line))?;
        (!self.scopes.is_empty() && !raw_tag.trim().is_empty()).ok_or_else(|| invalid(line))?;
        let (tag, tag_final) = marker(raw_tag.trim());
        if tag.eq_ignore_ascii_case("module") {
            return Err(Error::UnsupportedDynamicModule);
        }
        (!tag.is_empty()).ok_or_else(|| invalid(line))?;
        let section = self.scopes.first().map_or("", |scope| scope.name.as_str());
        let key = if section == "libdefaults" && tag.eq_ignore_ascii_case("no_addresses") {
            "noaddresses".to_owned()
        } else if (self.scopes.len() == 1 && section == "realms")
            || matches!(section, "capaths" | "appdefaults")
            || self
                .scopes
                .last()
                .is_some_and(|scope| scope.name == "auth_to_local_names")
        {
            tag.to_owned()
        } else {
            tag.to_ascii_lowercase()
        };
        let mut path: Vec<String> = self.scopes.iter().map(|scope| scope.name.clone()).collect();
        path.push(key.clone());
        let discarded =
            self.scopes.iter().any(|scope| scope.discarded) || profile.child_closed(&path);
        let value = raw.trim();
        if value == "{"
            || (value.is_empty()
                && matches!(section, "realms" | "appdefaults" | "plugins" | "capaths"))
        {
            self.pending_brace = value.is_empty();
            if self.scopes.len() > super::MAX_INCLUDE_DEPTH {
                return Err(Error::IncludeTooDeep {
                    depth: self.scopes.len(),
                    limit: super::MAX_INCLUDE_DEPTH,
                });
            }
            if !discarded {
                profile.scope(&path);
                if tag_final {
                    profile.finalize(path);
                }
            }
            self.scopes.push(Scope {
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
        if section != "domain_realm" {
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

    /// Finish an independent source or section.
    ///
    /// # Errors
    /// An open subsection is always an error, even in an unknown section.
    pub(super) fn finish(&mut self, profile: &mut Profile) -> Result<(), Error> {
        if self.pending_brace || self.scopes.len() > 1 {
            return Err(Error::InvalidRealmsSection(
                "unclosed profile subsection".to_owned(),
            ));
        }
        self.close(profile, false);
        Ok(())
    }

    /// Close one scope, retaining its finality but never finalizing discarded input.
    fn close(&mut self, profile: &mut Profile, closing_final: bool) {
        let path = self.scopes.iter().map(|scope| scope.name.clone()).collect();
        if let Some(scope) = self.scopes.pop()
            && !scope.discarded
            && (scope.final_marker || closing_final)
        {
            profile.finalize(path);
        }
    }
}

/// Split a trailing final marker from a tag or unquoted extension value.
fn marker(text: &str) -> (&str, bool) {
    text.strip_suffix('*')
        .map_or((text, false), |body| (body.trim_end(), true))
}

/// Decode MIT quoted strings without treating their contents as structure.
///
/// # Errors
/// Rejects unterminated quotes, dangling escapes and text after a closing quote.
fn quoted(value: &str, line: &Line) -> Result<String, Error> {
    let Some(rest) = value.strip_prefix('"') else {
        return Ok(value.to_owned());
    };
    let mut result = String::new();
    let mut escaped = false;
    for (index, ch) in rest.char_indices() {
        if escaped {
            result.push(match ch {
                'n' => '\n',
                't' => '\t',
                'b' => '\u{8}',
                other => other,
            });
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else if ch == '"' {
            if rest
                .get(index.saturating_add(1)..)
                .is_some_and(|tail| tail.trim().is_empty())
            {
                return Ok(result);
            }
            return Err(invalid(line));
        } else {
            result.push(ch);
        }
    }
    Err(invalid(line))
}

/// Retain a line-numbered typed syntax failure.
fn invalid(line: &Line) -> Error {
    Error::InvalidLine {
        section: "profile",
        line: line.number,
        text: line.text.clone(),
    }
}

/// A comment starts outside quotes at line start or after whitespace.
pub(super) fn comments(line: &str) -> &str {
    let mut quoted = false;
    let mut escaped = false;
    let mut whitespace = true;
    for (index, ch) in line.char_indices() {
        if escaped {
            escaped = false;
        } else if quoted && ch == '\\' {
            escaped = true;
        } else if ch == '"' {
            quoted = !quoted;
        } else if !quoted && whitespace && matches!(ch, '#' | ';') {
            return line.get(..index).unwrap_or(line);
        } else {
            // Ordinary value characters do not change quote state.
        }
        whitespace = ch.is_whitespace();
    }
    line
}
