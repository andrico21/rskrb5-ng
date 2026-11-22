//! `auth_to_local` rule parsing and application (`localauth_rule.c`).
//!
//! Grammar (MIT `localauth_rule.c:36-65`): `DEFAULT`, or `RULE:` followed by
//! an optional `[count:format]` selector, an optional `(regex)` match and any
//! number of `s/regex/text/` or `s/regex/text/g` substitutions. The pattern
//! text of a match cannot contain `)`, and neither pattern nor text of a
//! substitution can contain `/`; the text is literal.

use regex::{Regex, RegexBuilder};

use crate::{ccache::Principal, error::LocalAuth as Error};

use super::{
    AuthToLocalRule, MAX_MATCHES, MAX_PATTERN_BYTES, MAX_REPLACEMENT_BYTES, MAX_RULE_BYTES,
    MAX_SELECTION_BYTES, MAX_SUBSTITUTIONS, unparse,
};

/// The compiled-size limit of a pattern in bytes.
const REGEX_SIZE_LIMIT: usize = 1_048_576;
/// The nesting limit of a pattern.
const REGEX_NEST_LIMIT: u32 = 32;

/// A compiled rule.
#[derive(Clone, Debug)]
pub(super) enum Kind {
    /// `DEFAULT`.
    Default,
    /// `RULE:...`.
    Rule(Box<Compiled>),
}

/// One `RULE:` value.
#[derive(Clone, Debug)]
pub(super) struct Compiled {
    /// `[count:format]`.
    selector: Option<Selector>,
    /// `(regex)`, anchored at both ends.
    matcher: Option<Regex>,
    /// The `s/regex/text/` substitutions in order.
    edits: Vec<Edit>,
}

/// `[count:format]`.
#[derive(Clone, Debug)]
struct Selector {
    /// The number of components the principal must have.
    count: usize,
    /// The format, split into literals and `$n` references.
    parts: Vec<Part>,
}

/// A piece of a selection format.
#[derive(Clone, Debug)]
enum Part {
    /// Literal text.
    Literal(String),
    /// `$0` (the realm, `0`) or `$n` (component `n`).
    Reference(usize),
}

/// `s/regex/text/[g]`.
#[derive(Clone, Debug)]
struct Edit {
    /// The pattern.
    pattern: Regex,
    /// The literal replacement.
    text: String,
    /// Whether every match is replaced.
    global: bool,
}

/// A malformed rule.
const fn malformed(reason: &'static str) -> Error {
    Error::MalformedRule { reason }
}

/// Compile `pattern`, refusing what the bounds or the engine refuse.
fn compile(pattern: &str, anchored: bool) -> Result<Regex, Error> {
    if pattern.len() > MAX_PATTERN_BYTES {
        return Err(Error::LimitExceeded {
            what: "pattern",
            limit: MAX_PATTERN_BYTES,
        });
    }
    let source = if anchored {
        format!("^(?:{pattern})$")
    } else {
        pattern.to_owned()
    };
    RegexBuilder::new(&source)
        .size_limit(REGEX_SIZE_LIMIT)
        .nest_limit(REGEX_NEST_LIMIT)
        .build()
        .map_err(|error| Error::InvalidRegex {
            message: error.to_string(),
        })
}

/// C `isspace` in the C locale.
const fn is_space(character: char) -> bool {
    matches!(character, ' ' | '\t' | '\n' | '\u{b}' | '\u{c}' | '\r')
}

/// Parse `[count:format]` at the start of `rest`; return the rest after `]`.
fn parse_selector(rest: &str) -> Result<(Selector, &str), Error> {
    let body = rest.strip_prefix('[').ok_or_else(|| malformed("selector"))?;
    let digits = body.bytes().take_while(u8::is_ascii_digit).count();
    let (number, after) = body
        .split_at_checked(digits)
        .ok_or_else(|| malformed("selector"))?;
    let count = number
        .parse::<usize>()
        .ok()
        .ok_or_else(|| malformed("component count"))?;
    let mut format = after
        .strip_prefix(':')
        .ok_or_else(|| malformed("selector colon"))?;
    let mut parts = Vec::new();
    loop {
        let stop = format.find(['$', ']']).ok_or_else(|| malformed("selector end"))?;
        let (literal, tail) = format
            .split_at_checked(stop)
            .ok_or_else(|| malformed("selector"))?;
        if !literal.is_empty() {
            parts.push(Part::Literal(literal.to_owned()));
        }
        if let Some(after_bracket) = tail.strip_prefix(']') {
            return Ok((Selector { count, parts }, after_bracket));
        }
        let reference = tail.strip_prefix('$').ok_or_else(|| malformed("selector"))?;
        let width = reference.bytes().take_while(u8::is_ascii_digit).count();
        let (index, remainder) = reference
            .split_at_checked(width)
            .ok_or_else(|| malformed("selector"))?;
        let index = index
            .parse::<usize>()
            .ok()
            .ok_or_else(|| malformed("selector reference"))?;
        if index > count {
            return Err(malformed("selector reference beyond the component count"));
        }
        parts.push(Part::Reference(index));
        format = remainder;
    }
}

/// Parse one `s/regex/text/[g]` at the start of `rest`; return the rest.
fn parse_edit(rest: &str) -> Result<(Edit, &str), Error> {
    let body = rest.strip_prefix("s/").ok_or_else(|| malformed("substitution"))?;
    let (pattern, after_pattern) = body
        .split_once('/')
        .ok_or_else(|| malformed("substitution pattern"))?;
    let (text, after_text) = after_pattern
        .split_once('/')
        .ok_or_else(|| malformed("substitution text"))?;
    if text.len() > MAX_REPLACEMENT_BYTES {
        return Err(Error::LimitExceeded {
            what: "replacement",
            limit: MAX_REPLACEMENT_BYTES,
        });
    }
    let (global, remainder) = after_text
        .strip_prefix('g')
        .map_or((false, after_text), |tail| (true, tail));
    Ok((
        Edit {
            pattern: compile(pattern, false)?,
            text: text.to_owned(),
            global,
        },
        remainder,
    ))
}

impl AuthToLocalRule {
    /// Parse one `auth_to_local` value: `DEFAULT` or `RULE:...`.
    ///
    /// Everything is checked here, not when the rule is first used (MIT finds
    /// syntax errors at use): the grammar, the bounds
    /// ([`MAX_RULE_BYTES`], [`MAX_PATTERN_BYTES`], [`MAX_REPLACEMENT_BYTES`],
    /// [`MAX_SUBSTITUTIONS`]) and the compilation of every pattern.
    ///
    /// # Errors
    ///
    /// [`Error::UnsupportedRuleType`] for another type, [`Error::MalformedRule`]
    /// for a syntax error, [`Error::LimitExceeded`] past a bound and
    /// [`Error::InvalidRegex`] for a pattern the engine refuses.
    #[inline]
    pub fn parse(text: &str) -> Result<Self, Error> {
        if text.len() > MAX_RULE_BYTES {
            return Err(Error::LimitExceeded {
                what: "rule",
                limit: MAX_RULE_BYTES,
            });
        }
        if text == "DEFAULT" {
            return Ok(Self::default_rule());
        }
        let Some(mut rest) = text.strip_prefix("RULE:") else {
            return if text == "RULE" {
                Err(malformed("RULE needs a colon"))
            } else {
                Err(Error::UnsupportedRuleType {
                    kind: text.split(':').next().unwrap_or_default().chars().take(32).collect(),
                })
            };
        };
        let selector = if rest.starts_with('[') {
            let (selector, after) = parse_selector(rest)?;
            rest = after;
            Some(selector)
        } else {
            None
        };
        let matcher = if let Some(body) = rest.strip_prefix('(') {
            let (pattern, after) = body.split_once(')').ok_or_else(|| malformed("match"))?;
            rest = after;
            Some(compile(pattern, true)?)
        } else {
            None
        };
        let mut edits = Vec::new();
        while !rest.is_empty() {
            let (edit, after) = parse_edit(rest.trim_start_matches(is_space))?;
            if edits.len() >= MAX_SUBSTITUTIONS {
                return Err(Error::LimitExceeded {
                    what: "substitutions",
                    limit: MAX_SUBSTITUTIONS,
                });
            }
            edits.push(edit);
            rest = after;
        }
        Ok(Self {
            kind: Kind::Rule(Box::new(Compiled {
                selector,
                matcher,
                edits,
            })),
        })
    }

    /// The `DEFAULT` rule.
    #[must_use]
    #[inline]
    pub const fn default_rule() -> Self {
        Self {
            kind: Kind::Default,
        }
    }

    /// Apply the rule to `principal` of a configuration whose default realm
    /// is `default_realm`.
    ///
    /// # Errors
    ///
    /// [`Error::NoTranslation`] when the rule does not apply to the principal
    /// and [`Error::LimitExceeded`] when its selection string or a result
    /// grows past [`MAX_SELECTION_BYTES`] or a substitution past
    /// [`MAX_MATCHES`] replacements.
    #[inline]
    pub fn apply(&self, principal: &Principal, default_realm: &str) -> Result<String, Error> {
        match &self.kind {
            Kind::Default => default_name(principal, default_realm),
            Kind::Rule(rule) => rule.apply(principal),
        }
    }
}

/// `an2ln_default` (`localauth.c:264-292`).
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
