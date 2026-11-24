//! Fuzz the redirect-target resolver of the HTTP client (plan 2 todo 26, WP-19).
//!
//! The input is a base URI, a newline and the `Location` value of a response.
//! `http::origin::resolve_location` reads that header from the network; an
//! accepted target must be a plain `http` or `https` URI with a host, without
//! user information, a fragment or a dot segment, and it must have an origin.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rskrb5_ng::http::origin::{Origin, resolve_location};

/// The base when the input's first line is not a usable URI.
const BASE: &str = "https://www.example.com:8443/a/b/c?x=1";

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let (first, location) = text.split_once('\n').unwrap_or((BASE, &text));
    let base = first
        .parse()
        .ok()
        .filter(|uri| Origin::of(uri).is_ok())
        .unwrap_or_else(|| BASE.parse().unwrap_or_default());
    let Ok(target) = resolve_location(&base, location) else {
        return;
    };
    let origin = Origin::of(&target);
    assert!(origin.is_ok(), "a resolved target has an origin");
    let rendered = target.to_string();
    assert!(!rendered.contains('#'), "no fragment");
    assert!(
        target
            .authority()
            .is_some_and(|authority| !authority.as_str().contains('@')),
        "no user information"
    );
    let path = target.path();
    assert!(
        !path.contains("/./") && !path.contains("/../") && !path.ends_with("/.") && !path.ends_with("/.."),
        "no dot segment"
    );
});
