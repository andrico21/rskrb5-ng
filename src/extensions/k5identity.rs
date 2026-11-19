//! The `.k5identity` grammar (MIT 1.22.2 `ccselect_k5identity.c`) and the
//! `fnmatch` subset its patterns use.

use super::checks;
use crate::ccache::Principal;

/// MIT reads lines with `fgets` into a 256-byte buffer
/// (`ccselect_k5identity.c:162`); a longer line never matches here.
const MAX_LINE_BYTES: usize = 255;
/// MIT `KRB5_NT_PRINCIPAL`, the name type `krb5_parse_name` assigns.
const NT_PRINCIPAL: i32 = 1;
/// MIT `KRB5_NT_SRV_HST`.
const NT_SRV_HST: i32 = 3;
/// The separators MIT's line parser skips (`ccselect_k5identity.c:94`).
const BLANKS: [u8; 4] = *b" \t\r\n";

/// The client principal of the first line whose constraints `server`
/// satisfies (MIT `k5identity_choose`, `ccselect_k5identity.c:183-187`).
pub(super) fn choose(
    bytes: &[u8],
    server: &Principal,
    default_realm: Option<&str>,
) -> Option<Principal> {
    bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| line.len() < MAX_LINE_BYTES)
        .find_map(|line| parse_line(line, server, default_realm))
}

/// One line: a principal, then `name=pattern` constraints; any unknown or
/// malformed constraint fails the line (`ccselect_k5identity.c:85-127`).
fn parse_line(line: &[u8], server: &Principal, default_realm: Option<&str>) -> Option<Principal> {
    let mut fields = line
        .split(|byte| BLANKS.contains(byte))
        .filter(|field| !field.is_empty());
    let principal = fields.next().filter(|field| field.first() != Some(&b'#'))?;
    for field in fields {
        let separator = field.iter().position(|byte| *byte == b'=')?;
        let name = field.get(..separator)?;
        let pattern = field.get(separator.saturating_add(1)..)?;
        if !constraint(name, pattern, server) {
            return None;
        }
    }
    parse_principal(principal, default_realm)
}

/// MIT `check_constraint` (`ccselect_k5identity.c:68-82`).
fn constraint(name: &[u8], pattern: &[u8], server: &Principal) -> bool {
    let host_based = server.name_type == NT_SRV_HST && server.components.len() >= 2;
    match name {
        b"realm" => fnmatch(pattern, server.realm.as_bytes()),
        b"service" => {
            host_based
                && server
                    .components
                    .first()
                    .is_some_and(|service| fnmatch(pattern, service.as_bytes()))
        }
        b"host" => {
            host_based
                && server
                    .components
                    .get(1)
                    .is_some_and(|host| fnmatch(pattern, host.to_ascii_lowercase().as_bytes()))
        }
        _ => false,
    }
}

/// `krb5_parse_name` for the principal field (MIT `parse.c:43-118,128-170`).
///
/// `/` separates components, the first unescaped `@` starts the realm, and
/// `\n`, `\t`, `\b`, `\0` and `\<char>` are escapes. A missing realm takes the
/// default realm; without one the line does not match. A principal with an
/// empty realm, a control character or too many components never matches.
fn parse_principal(field: &[u8], default_realm: Option<&str>) -> Option<Principal> {
    let mut components: Vec<Vec<u8>> = vec![Vec::new()];
    let mut realm: Option<Vec<u8>> = None;
    let mut bytes = field.iter();
    while let Some(byte) = bytes.next() {
        let current = match realm.as_mut() {
            Some(text) => {
                if matches!(byte, b'/' | b'@') {
                    return None;
                }
                text
            }
            None if *byte == b'/' => {
                components.push(Vec::new());
                continue;
            }
            None if *byte == b'@' => {
                realm = Some(Vec::new());
                continue;
            }
            None => components.last_mut()?,
        };
        let value = if *byte == b'\\' {
            match bytes.next()? {
                b'n' => b'\n',
                b't' => b'\t',
                b'b' => 0x08,
                b'0' => 0x00,
                other => *other,
            }
        } else {
            *byte
        };
        current.push(value);
    }
    let realm_text = match realm {
        Some(text) => String::from_utf8(text).ok()?,
        None => default_realm?.to_owned(),
    };
    let names = components
        .into_iter()
        .map(String::from_utf8)
        .collect::<Result<Vec<_>, _>>()
        .ok()?;
    let principal = Principal::new(realm_text, NT_PRINCIPAL, names);
    checks::principal(&principal).then_some(principal)
}

/// POSIX `fnmatch(pattern, text, 0)` in the C locale.
///
/// `*`, `?`, bracket
/// expressions with ranges, `!`/`^` negation and the ASCII classes, and `\`
/// quoting. `*` and `?` match `/` and a leading `.`, as with flags 0. One
/// backtracking point keeps the work at `pattern.len() * text.len()`.
pub(super) fn fnmatch(pattern: &[u8], text: &[u8]) -> bool {
    let mut position = 0_usize;
    let mut cursor = 0_usize;
    let mut restart: Option<(usize, usize)> = None;
    loop {
        match step(pattern, position, text, cursor) {
            Step::Star(next) => {
                restart = Some((next, cursor));
                position = next;
            }
            Step::Matched(next_pattern) => {
                position = next_pattern;
                cursor = cursor.saturating_add(1);
            }
            Step::End => return true,
            Step::Mismatch => {
                let Some((star, from)) = restart else {
                    return false;
                };
                if from >= text.len() {
                    return false;
                }
                let advanced = from.saturating_add(1);
                restart = Some((star, advanced));
                position = star;
                cursor = advanced;
            }
        }
    }
}

/// A character-class predicate.
type Class = fn(u8) -> bool;

/// One matcher step.
enum Step {
    /// A `*` whose remaining pattern starts at the index.
    Star(usize),
    /// One text byte matched; the pattern continues at the index.
    Matched(usize),
    /// Pattern and text both ended.
    End,
    /// No match at this alignment.
    Mismatch,
}

/// Match the pattern item at `position` against the text byte at `cursor`.
fn step(pattern: &[u8], position: usize, text: &[u8], cursor: usize) -> Step {
    let Some(token) = pattern.get(position) else {
        return if cursor == text.len() {
            Step::End
        } else {
            Step::Mismatch
        };
    };
    if *token == b'*' {
        return Step::Star(position.saturating_add(1));
    }
    let Some(byte) = text.get(cursor) else {
        return Step::Mismatch;
    };
    let after = position.saturating_add(1);
    let outcome = match token {
        b'?' => Some(after),
        b'\\' => pattern
            .get(after)
            .and_then(|quoted| (quoted == byte).then_some(after.saturating_add(1))),
        b'[' => match bracket(pattern, after, *byte) {
            Some((matched, next)) => matched.then_some(next),
            None => (*byte == b'[').then_some(after),
        },
        literal => (literal == byte).then_some(after),
    };
    outcome.map_or(Step::Mismatch, Step::Matched)
}

/// Evaluate the bracket expression that starts at `start` (after `[`) against
/// `byte`. Returns whether it matched and the index after `]`, or `None` for an
/// unterminated bracket, which then matches a literal `[`.
fn bracket(pattern: &[u8], start: usize, byte: u8) -> Option<(bool, usize)> {
    let negated = matches!(pattern.get(start), Some(b'!' | b'^'));
    let mut index = if negated {
        start.saturating_add(1)
    } else {
        start
    };
    let mut matched = false;
    let mut first = true;
    loop {
        let current = *pattern.get(index)?;
        if current == b']' && !first {
            return Some((matched != negated, index.saturating_add(1)));
        }
        first = false;
        if current == b'['
            && pattern.get(index.saturating_add(1)) == Some(&b':')
            && let Some((class, next)) = class(pattern, index.saturating_add(2))
        {
            matched |= class(byte);
            index = next;
            continue;
        }
        let (low, next) = bracket_byte(pattern, index)?;
        let range = pattern.get(next) == Some(&b'-')
            && pattern
                .get(next.saturating_add(1))
                .is_some_and(|item| *item != b']');
        if range {
            let (high, after) = bracket_byte(pattern, next.saturating_add(1))?;
            matched |= (low..=high).contains(&byte);
            index = after;
        } else {
            matched |= low == byte;
            index = next;
        }
    }
}

/// One possibly quoted bracket byte and the index after it.
fn bracket_byte(pattern: &[u8], index: usize) -> Option<(u8, usize)> {
    let current = *pattern.get(index)?;
    if current == b'\\' {
        let quoted = *pattern.get(index.saturating_add(1))?;
        Some((quoted, index.saturating_add(2)))
    } else {
        Some((current, index.saturating_add(1)))
    }
}

/// A `[:name:]` class that starts at `start` (after `[:`): its predicate and
/// the index after `:]`.
fn class(pattern: &[u8], start: usize) -> Option<(Class, usize)> {
    let rest = pattern.get(start..)?;
    let end = rest.windows(2).position(|pair| pair == b":]")?;
    let predicate: Class = match rest.get(..end)? {
        b"alnum" => |byte| byte.is_ascii_alphanumeric(),
        b"alpha" => |byte| byte.is_ascii_alphabetic(),
        b"blank" => |byte| matches!(byte, b' ' | b'\t'),
        b"cntrl" => |byte| byte.is_ascii_control(),
        b"digit" => |byte| byte.is_ascii_digit(),
        b"graph" => |byte| byte.is_ascii_graphic(),
        b"lower" => |byte| byte.is_ascii_lowercase(),
        b"print" => |byte| byte.is_ascii_graphic() || byte == b' ',
        b"punct" => |byte| byte.is_ascii_punctuation(),
        b"space" => |byte| matches!(byte, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r'),
        b"upper" => |byte| byte.is_ascii_uppercase(),
        b"xdigit" => |byte| byte.is_ascii_hexdigit(),
        _ => return None,
    };
    Some((predicate, start.saturating_add(end).saturating_add(2)))
}
