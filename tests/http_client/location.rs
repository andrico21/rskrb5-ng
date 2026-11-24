//! `Location` resolution and origins.

use http_types::Uri;
use pretty_assertions::assert_eq;
use rskrb5_ng::{
    error::HttpClient as ClientError,
    http::origin::{MAX_LOCATION_BYTES, Origin, resolve_location},
};

use super::context::{Context as _, TestError};

/// Parse a test URI.
fn uri(text: &str) -> Result<Uri, TestError> {
    text.parse().context("test URI parses")
}

/// Absolute, scheme-relative, path-absolute, query-only and path-relative
/// references resolve against the base (RFC 3986 section 5.2) and lose their
/// fragments and dot segments.
#[test]
fn references_resolve_against_the_base() -> Result<(), TestError> {
    let base = uri("https://www.example.com:8443/a/b/c?x=1")?;
    for (location, expected) in [
        (
            "https://other.example.org/p?q=1#frag",
            "https://other.example.org/p?q=1",
        ),
        ("//cdn.example.org/lib.js", "https://cdn.example.org/lib.js"),
        ("/root/file", "https://www.example.com:8443/root/file"),
        ("?y=2", "https://www.example.com:8443/a/b/c?y=2"),
        ("d", "https://www.example.com:8443/a/b/d"),
        ("../d", "https://www.example.com:8443/a/d"),
        ("../../../../d", "https://www.example.com:8443/d"),
        ("./d/./e/", "https://www.example.com:8443/a/b/d/e/"),
        ("d/..", "https://www.example.com:8443/a/b/"),
        ("/x/../y", "https://www.example.com:8443/y"),
        ("HTTP://Host.Example.org", "http://host.example.org/"),
        ("#only-a-fragment", "https://www.example.com:8443/a/b/c?x=1"),
    ] {
        assert_eq!(
            resolve_location(&base, location)?.to_string(),
            expected,
            "{location}"
        );
    }
    Ok(())
}

/// A base with an empty path resolves a relative reference at the root.
#[test]
fn a_base_without_a_path_resolves_at_the_root() -> Result<(), TestError> {
    assert_eq!(
        resolve_location(&uri("http://example.com")?, "next")?.to_string(),
        "http://example.com/next"
    );
    Ok(())
}

/// Anything that is not plain `http`/`https` without user information, and
/// every byte a header injection or a parser confusion needs, is refused.
#[test]
fn unsafe_locations_are_refused() -> Result<(), TestError> {
    let base = uri("https://www.example.com/a")?;
    let oversized = format!("/{}", "a".repeat(MAX_LOCATION_BYTES));
    for location in [
        "",
        "ftp://files.example.org/x",
        "javascript:alert(1)",
        "mailto:a@example.org",
        "http:relative",
        "https://user:secret@evil.example.org/",
        "https://evil.example.org\\@www.example.com/",
        "/a b",
        "/a\r\nSet-Cookie: x=1",
        "/\u{e9}",
        "https:///nohost",
        oversized.as_str(),
    ] {
        let refused = resolve_location(&base, location);
        assert!(
            matches!(refused, Err(ClientError::InvalidLocation { reason: _ })),
            "{location:?} gave {refused:?}"
        );
    }
    Ok(())
}

/// The origin is scheme, lower-cased host and port, with the scheme's default port.
#[test]
fn origins_compare_by_scheme_host_and_port() -> Result<(), TestError> {
    let first = Origin::of(&uri("https://WWW.Example.com/x")?)?;
    assert_eq!(first, Origin::of(&uri("https://www.example.com:443/y?z")?)?);
    assert_eq!(first.port(), 443);
    assert!(first.is_secure());
    for other in [
        "http://www.example.com/",
        "https://www.example.com:8443/",
        "https://example.com/",
    ] {
        assert_ne!(first, Origin::of(&uri(other)?)?, "{other}");
    }
    for refused in [
        "/relative",
        "ftp://example.com/",
        "https://user@example.com/",
    ] {
        assert!(
            matches!(
                Origin::of(&uri(refused)?),
                Err(ClientError::InvalidUri { reason: _ })
            ),
            "{refused}"
        );
    }
    Ok(())
}
