//! Principal names in MIT's string form (`krb5_unparse_name` and
//! `krb5_parse_name`, `unparse.c`, `parse.c`), the form `xdr_krb5_principal`
//! puts on the wire (`kadm_rpc_xdr.c`).

use crate::{client::principal::Principal, error::Kadm5 as Error};

/// The most components a principal from kadmind may have.
const MAX_COMPONENTS: usize = 64;

/// The name type of a parsed principal: `KRB5_NT_PRINCIPAL`, as `krb5_parse_name` sets it.
const NT_PRINCIPAL: i32 = 1;

/// Append `text` with MIT's quoting: `\`, `/` and `@` escaped, tab, newline,
/// backspace and NUL as `\t`, `\n`, `\b`, `\0`.
fn quote(text: &str, out: &mut String) {
    for character in text.chars() {
        match character {
            '@' | '/' | '\\' => {
                out.push('\\');
                out.push(character);
            }
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{8}' => out.push_str("\\b"),
            '\0' => out.push_str("\\0"),
            other => out.push(other),
        }
    }
}

/// `principal` in MIT's string form, realm included.
pub(super) fn unparse(principal: &Principal) -> String {
    let mut out = String::new();
    for (index, component) in principal.components.iter().enumerate() {
        if index > 0 {
            out.push('/');
        }
        quote(component, &mut out);
    }
    out.push('@');
    quote(&principal.realm, &mut out);
    out
}

/// Parse a principal from kadmind: components and a realm.
///
/// # Errors
///
/// Returns [`Error::Malformed`] without a realm, for a separator inside the
/// realm, a trailing escape, an empty first component or more than 64
/// components.
pub(super) fn parse(text: &str) -> Result<Principal, Error> {
    let mut components = vec![String::new()];
    let mut realm: Option<String> = None;
    let mut characters = text.chars();
    while let Some(next) = characters.next() {
        let literal = match next {
            '/' if realm.is_none() => {
                if components.len() >= MAX_COMPONENTS {
                    return Err(Error::Malformed("a principal has more than 64 components"));
                }
                components.push(String::new());
                continue;
            }
            '@' if realm.is_none() => {
                realm = Some(String::new());
                continue;
            }
            '/' | '@' => return Err(Error::Malformed("a separator inside a realm")),
            '\\' => match characters.next() {
                None => return Err(Error::Malformed("a principal ends with an escape")),
                Some('n') => '\n',
                Some('t') => '\t',
                Some('b') => '\u{8}',
                Some('0') => '\0',
                Some(other) => other,
            },
            other => other,
        };
        let target = match realm.as_mut() {
            Some(text) => text,
            None => components
                .last_mut()
                .ok_or(Error::Malformed("a principal has a component"))?,
        };
        target.push(literal);
    }
    let named_realm = realm
        .filter(|text| !text.is_empty())
        .ok_or(Error::Malformed("a principal from kadmind names its realm"))?;
    if components.first().is_none_or(String::is_empty) {
        return Err(Error::Malformed("a principal has an empty first component"));
    }
    Ok(Principal::new(named_realm, NT_PRINCIPAL, components))
}
