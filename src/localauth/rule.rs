//! `auth_to_local` rule parsing and application (`localauth_rule.c`).
//!
//! Grammar (MIT `localauth_rule.c:36-65`): `DEFAULT`, or `RULE:` followed by
//! an optional `[count:format]` selector, an optional `(regex)` match and any
//! number of `s/regex/text/` or `s/regex/text/g` substitutions. The pattern
//! text of a match cannot contain `)`, and neither pattern nor text of a
//! substitution can contain `/`; the text is literal.

use regex::{Regex, RegexBuilder};

use super::{MAX_PATTERN_BYTES, MAX_REPLACEMENT_BYTES, MAX_RULE_BYTES, MAX_SUBSTITUTIONS};
use crate::error::LocalAuth as Error;

/// Applying a compiled rule to a principal.
pub(super) mod eval;

/// The compiled-size limit of a pattern in bytes.
const REGEX_SIZE_LIMIT: usize = 0x10_0000;
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
///
/// # Errors
///
/// [`Error::LimitExceeded`] or [`Error::InvalidRegex`].
fn compile_pattern(pattern: &str, anchored: bool) -> Result<Regex, Error> {
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
///
/// # Errors
///
/// [`Error::MalformedRule`] for a syntax error.
fn selector_at(rest: &str) -> Result<(Selector, &str), Error> {
    let body = rest
        .strip_prefix('[')
        .ok_or_else(|| malformed("selector"))?;
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
        let stop = format
            .find(['$', ']'])
            .ok_or_else(|| malformed("selector end"))?;
        let (literal, tail) = format
            .split_at_checked(stop)
            .ok_or_else(|| malformed("selector"))?;
        if !literal.is_empty() {
            parts.push(Part::Literal(literal.to_owned()));
        }
        if let Some(after_bracket) = tail.strip_prefix(']') {
            return Ok((Selector { count, parts }, after_bracket));
        }
        let reference = tail
            .strip_prefix('$')
            .ok_or_else(|| malformed("selector"))?;
        let width = reference.bytes().take_while(u8::is_ascii_digit).count();
        let (index, remainder) = reference
            .split_at_checked(width)
            .ok_or_else(|| malformed("selector"))?;
        let reference_index = index
            .parse::<usize>()
            .ok()
            .ok_or_else(|| malformed("selector reference"))?;
        if reference_index > count {
            return Err(malformed("selector reference beyond the component count"));
        }
        parts.push(Part::Reference(reference_index));
        format = remainder;
    }
}

/// Parse one `s/regex/text/[g]` at the start of `rest`; return the rest.
///
/// # Errors
///
/// [`Error::MalformedRule`], [`Error::LimitExceeded`] or [`Error::InvalidRegex`].
fn edit_at(rest: &str) -> Result<(Edit, &str), Error> {
    let body = rest
        .strip_prefix("s/")
        .ok_or_else(|| malformed("substitution"))?;
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
            pattern: compile_pattern(pattern, false)?,
            text: text.to_owned(),
            global,
        },
        remainder,
    ))
}

/// Compile one `auth_to_local` value: `DEFAULT` or `RULE:...`.
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
pub(super) fn compile(text: &str) -> Result<Kind, Error> {
    if text.len() > MAX_RULE_BYTES {
        return Err(Error::LimitExceeded {
            what: "rule",
            limit: MAX_RULE_BYTES,
        });
    }
    if text == "DEFAULT" {
        return Ok(Kind::Default);
    }
    let Some(mut rest) = text.strip_prefix("RULE:") else {
        return if text == "RULE" {
            Err(malformed("RULE needs a colon"))
        } else {
            Err(Error::UnsupportedRuleType {
                kind: text
                    .split(':')
                    .next()
                    .unwrap_or_default()
                    .chars()
                    .take(32)
                    .collect(),
            })
        };
    };
    let selector = if rest.starts_with('[') {
        let (selector, after) = selector_at(rest)?;
        rest = after;
        Some(selector)
    } else {
        None
    };
    let matcher = if let Some(body) = rest.strip_prefix('(') {
        let (pattern, after) = body.split_once(')').ok_or_else(|| malformed("match"))?;
        rest = after;
        Some(compile_pattern(pattern, true)?)
    } else {
        None
    };
    let mut edits = Vec::new();
    while !rest.is_empty() {
        let (edit, after) = edit_at(rest.trim_start_matches(is_space))?;
        if edits.len() >= MAX_SUBSTITUTIONS {
            return Err(Error::LimitExceeded {
                what: "substitutions",
                limit: MAX_SUBSTITUTIONS,
            });
        }
        edits.push(edit);
        rest = after;
    }
    Ok(Kind::Rule(Box::new(Compiled {
        selector,
        matcher,
        edits,
    })))
}
