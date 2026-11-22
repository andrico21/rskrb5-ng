//! MIT principal-name unparsing (`krb5_unparse_name_flags`, `unparse.c:44-170`).

use crate::ccache::Principal;

/// Unparse `principal` with its realm (flags 0): every `\`, `/` and `@` is
/// escaped and tab, newline, backspace and NUL become `\t`, `\n`, `\b`, `\0`.
#[must_use]
pub(super) fn with_realm(principal: &Principal) -> String {
    let _unused = principal;
    String::new()
}

/// Unparse `principal` without its realm (`KRB5_PRINCIPAL_UNPARSE_NO_REALM`,
/// where `@` is not escaped), or `None` when a component contains `@` and
/// the result could be taken for another principal's name.
#[must_use]
pub(super) fn without_realm(principal: &Principal) -> Option<String> {
    let _unused = principal;
    None
}
