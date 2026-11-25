//! Fuzz the `Set-Cookie` handling of the HTTP client's cookie jar (plan 2 todo
//! 26, WP-19, the `http-client` leaf).
//!
//! The input is a request URI, a newline and `Set-Cookie` values separated by
//! further newlines. Each value is offered to `CookieStore::store_set_cookie`
//! (parsing, the size, `Secure` and `Domain` refusals and the RFC 6265 storage
//! model with a small public-suffix list); then the jar builds the `Cookie`
//! header for the URI and for its origin root. None may panic, the jar stays
//! within its bound, and a header it builds is visible ASCII.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rskrb5_ng::http::{cookies::CookieStore, wire::CookieJar as _};

/// A public-suffix list with a TLD and a two-label suffix.
const SUFFIXES: &str =
    "// ===BEGIN ICANN DOMAINS===\ncom\nuk\nco.uk\n// ===END ICANN DOMAINS===\n";

/// The most cookies the fuzzed jar holds.
const MAX: usize = 8;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let mut lines = text.split('\n');
    let Some(Ok(uri)) = lines.next().map(str::parse) else {
        return;
    };
    let attempt = CookieStore::new().with_public_suffix_list(SUFFIXES);
    assert!(attempt.is_ok(), "the fixed list parses");
    let Ok(listed) = attempt else {
        return;
    };
    let mut jar = listed.with_max_cookies(MAX);
    for value in lines {
        drop(jar.store_set_cookie(&uri, value));
    }
    assert!(jar.len() <= MAX, "the jar stays within its bound");
    if let Some(header) = jar.cookie_header(&uri) {
        assert!(header.to_str().is_ok(), "a Cookie header is visible ASCII");
    }
});
