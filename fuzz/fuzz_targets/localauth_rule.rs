//! Fuzz the `auth_to_local` rule language (plan 2 todo 25, WP-17).
//!
//! The input is the text of an `auth_to_local` value, then a newline and a
//! principal (`a/b/c`, in the realm `EXAMPLE.COM`). `AuthToLocalRule::parse`
//! reads configuration text (a bounded `RULE:[n:format](regex)s/re/text/g`
//! with the linear-time `regex` engine); an accepted rule is applied to the
//! principal and the translation goes through a `LocalNameMapper`. None may
//! panic, a result stays within the bounds, and a mapped name is never empty,
//! longer than the account name limit or NUL-holding.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rskrb5_ng::{
    ccache::Principal,
    localauth::{
        AuthToLocalRule, LocalNameMapper, MAX_LOCAL_NAME_BYTES, MAX_SELECTION_BYTES,
        principal_to_local_name,
    },
};

/// The default realm of the fuzzed mapper.
const REALM: &str = "EXAMPLE.COM";

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let (value, subject) = text.split_once('\n').unwrap_or((&text, "alice/admin"));
    let Ok(rule) = AuthToLocalRule::parse(value) else {
        return;
    };
    let principal = Principal::new(REALM, 1, subject.split('/').map(str::to_owned).collect());
    if let Ok(name) = rule.apply(&principal, REALM) {
        assert!(name.len() <= MAX_SELECTION_BYTES, "result bound");
    }
    if let Ok(mapper) = LocalNameMapper::new(Some(REALM.to_owned())).with_rules(vec![rule])
        && let Ok(local) = principal_to_local_name(&mapper, &principal)
    {
        assert!(!local.is_empty(), "no empty account name");
        assert!(local.len() <= MAX_LOCAL_NAME_BYTES, "account name bound");
        assert!(!local.contains('\0'), "no NUL in an account name");
    }
});
