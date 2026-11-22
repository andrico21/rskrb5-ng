//! MIT principal-name unparsing (`krb5_unparse_name_flags`, `unparse.c:44-170`).

use crate::ccache::Principal;

/// Append `text` quoted as MIT does: `\`, `/` and (when `escape_at`) `@` get a
/// backslash, tab, newline, backspace and NUL become `\t`, `\n`, `\b`, `\0`.
fn quote(text: &str, escape_at: bool, out: &mut String) {
    for character in text.chars() {
        match character {
            '@' if !escape_at => out.push('@'),
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

/// The components of `principal` joined by `/`, each quoted.
fn name(principal: &Principal, escape_at: bool, out: &mut String) {
    for (index, component) in principal.components.iter().enumerate() {
        if index > 0 {
            out.push('/');
        }
        quote(component, escape_at, out);
    }
}

/// Unparse `principal` with its realm (flags 0), the form of a `.k5login` line.
#[must_use]
pub(super) fn with_realm(principal: &Principal) -> String {
    let mut out = String::new();
    name(principal, true, &mut out);
    out.push('@');
    quote(&principal.realm, true, &mut out);
    out
}

/// Unparse `principal` without its realm (`KRB5_PRINCIPAL_UNPARSE_NO_REALM`,
/// where `@` is not escaped), or `None` when a component contains `@`: the
/// result could then be taken for the name of another principal.
#[must_use]
pub(super) fn without_realm(principal: &Principal) -> Option<String> {
    if principal.components.iter().any(|component| component.contains('@')) {
        return None;
    }
    let mut out = String::new();
    name(principal, false, &mut out);
    Some(out)
}
