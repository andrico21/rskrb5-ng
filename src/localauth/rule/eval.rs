//! Applying a compiled `auth_to_local` rule (`localauth_rule.c:108-302`).

use super::{Compiled, Edit, Kind, Part};
use crate::{
    ccache::Principal,
    error::LocalAuth as Error,
    localauth::{MAX_MATCHES, MAX_SELECTION_BYTES, unparse},
};

/// Apply `kind` to `principal` of a configuration whose default realm is
/// `default_realm`.
///
/// # Errors
///
/// [`Error::NoTranslation`] when the rule does not apply to the principal and
/// [`Error::LimitExceeded`] when its selection string or a result grows past
/// [`MAX_SELECTION_BYTES`] or a substitution past [`MAX_MATCHES`] replacements.
pub(crate) fn evaluate(
    kind: &Kind,
    principal: &Principal,
    default_realm: &str,
) -> Result<String, Error> {
    match kind {
        Kind::Default => default_name(principal, default_realm),
        Kind::Rule(rule) => rule.apply(principal),
    }
}

/// `an2ln_default` (`localauth.c:264-292`).
///
/// # Errors
///
/// [`Error::NoTranslation`] outside the default realm or for another shape.
fn default_name(principal: &Principal, default_realm: &str) -> Result<String, Error> {
    if principal.realm != default_realm {
        return Err(Error::NoTranslation);
    }
    match principal.components.as_slice() {
        [name] => Ok(name.clone()),
        [name, realm] if realm == default_realm => Ok(name.clone()),
        _ => Err(Error::NoTranslation),
    }
}

/// The result grew past the selection bound.
const fn too_long(what: &'static str) -> Error {
    Error::LimitExceeded {
        what,
        limit: MAX_SELECTION_BYTES,
    }
}

impl Compiled {
    /// `an2ln_rule` (`localauth_rule.c:272-302`).
    ///
    /// # Errors
    ///
    /// [`Error::NoTranslation`] or [`Error::LimitExceeded`].
    fn apply(&self, principal: &Principal) -> Result<String, Error> {
        let selection = self.selection(principal)?;
        if self
            .matcher
            .as_ref()
            .is_some_and(|matcher| !matcher.is_match(&selection))
        {
            return Err(Error::NoTranslation);
        }
        self.edits
            .iter()
            .try_fold(selection, |current, edit| edit.apply(&current))
    }

    /// `aname_get_selstring` (`localauth_rule.c:205-269`).
    ///
    /// # Errors
    ///
    /// [`Error::NoTranslation`] or [`Error::LimitExceeded`].
    fn selection(&self, principal: &Principal) -> Result<String, Error> {
        let Some(selector) = &self.selector else {
            return unparse::without_realm(principal).ok_or(Error::NoTranslation);
        };
        if principal.components.len() != selector.count {
            return Err(Error::NoTranslation);
        }
        let mut out = String::new();
        for part in &selector.parts {
            let text = match part {
                Part::Literal(literal) => literal,
                Part::Reference(0) => &principal.realm,
                Part::Reference(index) => index
                    .checked_sub(1)
                    .and_then(|position| principal.components.get(position))
                    .ok_or(Error::NoTranslation)?,
            };
            out.push_str(text);
            if out.len() > MAX_SELECTION_BYTES {
                return Err(too_long("selection string"));
            }
        }
        Ok(out)
    }
}

impl Edit {
    /// `do_replacement` (`localauth_rule.c:110-133`): each search starts on
    /// the text after the previous match (so `^` matches again, as in MIT),
    /// and an empty match takes one character along so the loop ends.
    ///
    /// # Errors
    ///
    /// [`Error::LimitExceeded`] past the replacement or result bound.
    fn apply(&self, input: &str) -> Result<String, Error> {
        let mut out = String::new();
        let mut rest = input;
        let mut matches = 0_usize;
        while let Some(found) = self.pattern.find(rest) {
            matches = matches.saturating_add(1);
            if matches > MAX_MATCHES {
                return Err(Error::LimitExceeded {
                    what: "replacements",
                    limit: MAX_MATCHES,
                });
            }
            let (before, from_match) = rest
                .split_at_checked(found.start())
                .ok_or(Error::NoTranslation)?;
            out.push_str(before);
            out.push_str(&self.text);
            let (_matched, after) = from_match
                .split_at_checked(found.len())
                .ok_or(Error::NoTranslation)?;
            rest = after;
            if !self.global {
                break;
            }
            if found.is_empty() {
                let Some(next) = rest.chars().next() else {
                    break;
                };
                out.push(next);
                rest = rest
                    .split_at_checked(next.len_utf8())
                    .map_or("", |(_taken, tail)| tail);
            }
            if out.len() > MAX_SELECTION_BYTES {
                return Err(too_long("substitution result"));
            }
        }
        out.push_str(rest);
        if out.len() > MAX_SELECTION_BYTES {
            return Err(too_long("substitution result"));
        }
        Ok(out)
    }
}
