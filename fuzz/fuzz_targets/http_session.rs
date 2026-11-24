//! Fuzz the HTTP session cookie of the session manager (plan 2 todo 26, WP-19).
//!
//! An even first input byte makes the rest the value of a session cookie that
//! `SessionManager::resume` reads (base64url decoding, the sealed-blob framing
//! and the RFC 8009 authentication under a fixed key); a request `Cookie` header
//! is read the same way through `attach`. An odd byte builds a principal from the
//! rest (components split at `/`, the realm up to the first newline), issues a
//! session for it and requires `resume` to give the same principal back. None
//! may panic and nothing but a session the manager sealed may resume.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rskrb5_ng::{
    gss::TransferKey,
    http::sessions::SessionManager,
    service::Principal,
};

/// The key of the fuzzed manager.
const KEY: [u8; 32] = [0x2b; 32];

/// A default value of an inferred type: the request type is only reachable
/// through the crate's signatures, not by name.
fn fresh<T>() -> T
where
    T: Default,
{
    T::default()
}

/// The set-cookie value's cookie value: between the first `=` and the first `;`.
fn value_of(set_cookie: &str) -> Option<&str> {
    let (_, rest) = set_cookie.split_once('=')?;
    rest.split(';').next()
}

fuzz_target!(|data: &[u8]| {
    let manager = SessionManager::new(TransferKey::new(KEY));
    let Some((selector, input)) = data.split_first() else {
        return;
    };
    let text = String::from_utf8_lossy(input);
    if selector & 1 == 0 {
        assert!(
            manager.resume(&text).is_err(),
            "a value this manager never sealed resumed"
        );
        let mut request = fresh();
        if let Ok(header) = text.as_ref().try_into() {
            let _previous = request.headers_mut().insert("cookie", header);
            drop(manager.attach::<()>(&mut request));
        }
        return;
    }
    let (realm, rest) = text.split_once('\n').unwrap_or(("EXAMPLE.COM", &text));
    let principal = Principal::new(
        realm.to_owned(),
        1,
        rest.split('/').map(str::to_owned).collect(),
    );
    let Ok((identity, set_cookie)) = manager.issue(&principal) else {
        return;
    };
    let Ok(header) = set_cookie.to_str() else {
        return;
    };
    let Some(value) = value_of(header) else {
        return;
    };
    let resumed = manager.resume(value).expect("an issued session resumes");
    assert_eq!(resumed.principal().realm, principal.realm);
    assert_eq!(resumed.principal().components, principal.components);
    assert_eq!(resumed, identity);
});
