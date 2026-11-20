//! Principal names as text, the form CCAPI stores them in.
//!
//! The forms are those of MIT 1.22.2 `krb5_unparse_name` and
//! `krb5_parse_name` (`src/lib/krb5/krb/unparse.c`, `parse.c`).
//!
//! Components are joined by `/` and followed by `@realm`; `/`, `@`, `\`,
//! NUL, newline, tab and backspace are escaped with a backslash.

use rskrb5_ng::ccache::Principal;

/// `KRB5_NT_PRINCIPAL`.
const NT_PRINCIPAL: i32 = 1;
/// `KRB5_NT_SRV_INST`, which `krb5_parse_name` gives a two-component
/// `krbtgt` name.
const NT_SRV_INST: i32 = 2;

/// Append `text` with the escapes of `krb5_unparse_name`.
fn escape(out: &mut String, text: &str) {
    for character in text.chars() {
        match character {
            '/' | '@' | '\\' => {
                out.push('\\');
                out.push(character);
            }
            '\0' => out.push_str("\\0"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            other => out.push(other),
        }
    }
}

/// The text form of `principal`.
pub(crate) fn unparse(principal: &Principal) -> String {
    let mut out = String::new();
    for (index, component) in principal.components.iter().enumerate() {
        if index > 0 {
            out.push('/');
        }
        escape(&mut out, component);
    }
    out.push('@');
    escape(&mut out, &principal.realm);
    out
}

/// Parse the text form of a principal; `None` for a malformed name (no
/// realm, an empty component or a dangling escape).
pub(crate) fn parse(text: &str) -> Option<Principal> {
    let mut parts = vec![String::new()];
    let mut realm: Option<String> = None;
    let mut characters = text.chars();
    while let Some(character) = characters.next() {
        let in_realm = realm.is_some();
        let decoded = match character {
            '\\' => Some(match characters.next()? {
                '0' => '\0',
                'n' => '\n',
                't' => '\t',
                'b' => '\u{8}',
                other => other,
            }),
            '/' if !in_realm => {
                parts.push(String::new());
                None
            }
            '@' if !in_realm => {
                realm = Some(String::new());
                None
            }
            other => Some(other),
        };
        if let Some(value) = decoded {
            match realm.as_mut() {
                Some(realm_text) => realm_text.push(value),
                None => parts.last_mut()?.push(value),
            }
        }
    }
    let realm_name = realm.filter(|value| !value.is_empty())?;
    if parts.iter().any(String::is_empty) {
        return None;
    }
    let name_type = match parts.as_slice() {
        [first, _] if first == "krbtgt" => NT_SRV_INST,
        _ => NT_PRINCIPAL,
    };
    Some(Principal::new(realm_name, name_type, parts))
}

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use rskrb5_ng::ccache::Principal;

    use super::{parse, unparse};

    /// Names round-trip with MIT's escapes and name types.
    #[test]
    fn round_trip_and_escapes() -> Result<(), &'static str> {
        // Given names with separators inside components.
        let odd = Principal::new("EX@MPLE", 1, vec!["a/b".to_owned(), "c\\d\n".to_owned()]);
        let tgt = Principal::new("R", 2, vec!["krbtgt".to_owned(), "R".to_owned()]);
        // When they are unparsed and parsed.
        // Then the text escapes and the value round-trips.
        assert_eq!(unparse(&odd), "a\\/b/c\\\\d\\n@EX\\@MPLE");
        assert_eq!(parse(&unparse(&odd)), Some(odd));
        assert_eq!(parse("krbtgt/R@R").ok_or("krbtgt")?, tgt);
        assert_eq!(parse("alice@R").map(|value| value.name_type), Some(1_i32));
        for bad in ["alice", "alice@", "a//b@R", "/a@R", "a\\", ""] {
            assert_eq!(parse(bad), None, "{bad}");
        }
        Ok(())
    }
}
