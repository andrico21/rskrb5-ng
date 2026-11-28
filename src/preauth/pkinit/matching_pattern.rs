//! The regular expressions of `pkinit_cert_match`.
//!
//! MIT 1.22.2 compiles them as POSIX extended syntax (`pkinit_matching.c:342`,
//! `regcomp(REG_EXTENDED)`); here they run on the linear-time `regex` engine.
//!
//! The engine is not POSIX: a pattern is accepted only when both read it the
//! same way. [`validate`] walks the pattern first and refuses what differs
//! (a backslash before anything but ASCII punctuation, which would be a
//! back-reference or a Perl class, and before the punctuation GNU reads as an
//! operator; `(?` groups; inside a bracket expression a
//! backslash, a nested class, `[.x.]`, `[=x=]`, the `&&`, `--` and `~~`
//! operators and the non-POSIX class names). `.` also matches a line feed, as
//! POSIX does without `REG_NEWLINE`.

use regex::{Regex, RegexBuilder};

use super::matching::MAX_PATTERN_BYTES;

/// The compiled-size limit of one pattern.
const SIZE_LIMIT: usize = 256 * 1024;
/// The nesting limit of one pattern.
const NEST_LIMIT: u32 = 16;
/// The POSIX character class names (`[:alpha:]` and the rest of `regex(7)`).
const POSIX_CLASSES: [&str; 12] = [
    "alnum", "alpha", "blank", "cntrl", "digit", "graph", "lower", "print", "punct", "space",
    "upper", "xdigit",
];
/// The punctuation GNU `regcomp` reads as an operator after a backslash
/// (`\<`, `\>`, `` \` ``, `\'`): it is not the literal both engines agree on.
const GNU_OPERATORS: [char; 4] = ['<', '>', '`', '\''];

/// Why a pattern is refused.
pub(super) type Refusal = &'static str;

/// Compile `pattern` as a POSIX extended expression.
///
/// # Errors
/// Returns the reason the pattern is over a bound, outside the accepted
/// subset, or not a valid expression.
pub(super) fn compile(pattern: &str) -> Result<Regex, Refusal> {
    if pattern.len() > MAX_PATTERN_BYTES {
        return Err("the pattern is over the length bound");
    }
    validate(pattern)?;
    RegexBuilder::new(pattern)
        .size_limit(SIZE_LIMIT)
        .nest_limit(NEST_LIMIT)
        .dot_matches_new_line(true)
        .build()
        .map_err(|_syntax| "the pattern is not a valid or bounded extended regular expression")
}

/// Walk `pattern`, refusing every construct POSIX and the engine read differently.
///
/// # Errors
/// Returns the reason for the first such construct.
fn validate(pattern: &str) -> Result<(), Refusal> {
    let mut rest = pattern;
    while let Some(character) = rest.chars().next() {
        let after = rest.get(character.len_utf8()..).unwrap_or_default();
        rest = match character {
            '\\' => {
                let mut escaped = after.chars();
                match escaped.next() {
                    Some(next) if next.is_ascii_punctuation() && !GNU_OPERATORS.contains(&next) => {
                        escaped.as_str()
                    }
                    Some(_) => {
                        return Err("only escaped punctuation is a literal (no \\d, \\1, \\<)");
                    }
                    None => return Err("a trailing backslash"),
                }
            }
            '(' if after.starts_with('?') => return Err("`(?` groups are not POSIX"),
            '[' => bracket(after)?,
            _ => after,
        };
    }
    Ok(())
}

/// Validate the bracket expression that follows its `[` in `after`; the text after its `]`.
///
/// # Errors
/// Returns the reason for a construct the engine reads differently.
fn bracket(after: &str) -> Result<&str, Refusal> {
    let body = after.strip_prefix('^').unwrap_or(after);
    // A `]` first in the expression is a member (POSIX and the engine agree).
    let mut rest = body.strip_prefix(']').unwrap_or(body);
    let mut previous = None;
    while let Some(character) = rest.chars().next() {
        let tail = rest.get(character.len_utf8()..).unwrap_or_default();
        match character {
            ']' => return Ok(tail),
            '\\' => return Err("a backslash inside a bracket expression is not POSIX"),
            '[' => {
                rest = class(tail)?;
                previous = Some(character);
                continue;
            }
            '&' | '-' | '~' if previous == Some(character) => {
                return Err("`&&`, `--` and `~~` inside a bracket expression are set operators");
            }
            _ => {}
        }
        previous = Some(character);
        rest = tail;
    }
    Err("an unterminated bracket expression")
}

/// Validate `[:name:]` after the `[` that opens it inside a bracket
/// expression; the text after its `]`.
///
/// # Errors
/// Returns the reason for a nested bracket, `[.x.]`, `[=x=]` or an unsupported class.
fn class(tail: &str) -> Result<&str, Refusal> {
    let body = tail
        .strip_prefix(':')
        .ok_or("a nested bracket, `[.x.]` or `[=x=]` inside a bracket expression")?;
    let (name, after) = body
        .split_once(":]")
        .ok_or("an unterminated character class")?;
    if POSIX_CLASSES.contains(&name) {
        Ok(after)
    } else {
        Err("an unsupported character class name")
    }
}
