//! `https://` server entries: MIT's split into host, port and path, and the refusals.

use core::error::Error as StdError;

use super::{Error, Url};

/// MIT's examples and the forms around them parse into host, port and path.
#[test]
fn urls_split_into_host_port_and_path() -> Result<(), Box<dyn StdError>> {
    for (value, host, port, path, shown) in [
        (
            "https://kdc.example.com/KdcProxy",
            "kdc.example.com",
            443,
            "KdcProxy",
            "https://kdc.example.com:443/KdcProxy",
        ),
        (
            " https://kdc.example.com:8443/kdc/proxy?x=1 ",
            "kdc.example.com",
            8443,
            "kdc/proxy?x=1",
            "https://kdc.example.com:8443/kdc/proxy?x=1",
        ),
        (
            "https://kdc.example.com",
            "kdc.example.com",
            443,
            "",
            "https://kdc.example.com:443/",
        ),
        (
            "https://192.0.2.1:444/",
            "192.0.2.1",
            444,
            "",
            "https://192.0.2.1:444/",
        ),
        (
            "https://[2001:db8::1]:8443/p",
            "2001:db8::1",
            8443,
            "p",
            "https://[2001:db8::1]:8443/p",
        ),
        (
            "https://[2001:db8::1]/p",
            "2001:db8::1",
            443,
            "p",
            "https://[2001:db8::1]:443/p",
        ),
    ] {
        let url = Url::parse(value)?.ok_or("not a proxy URL")?;
        assert_eq!(
            (url.host(), url.port(), url.path()),
            (host, port, path),
            "{value}"
        );
        assert_eq!(url.to_string(), shown);
    }
    Ok(())
}

/// Entries without the exact `https://` prefix are endpoints, not proxy URLs.
#[test]
fn other_entries_are_not_proxy_urls() -> Result<(), Box<dyn StdError>> {
    for value in [
        "kdc.example.com:88",
        "HTTPS://kdc.example.com/",
        "http://kdc.example.com/",
        "[::1]:88",
    ] {
        assert!(Url::parse(value)?.is_none(), "{value}");
    }
    Ok(())
}

/// User information, queries or fragments before the path, request-line bytes in the
/// path, zone ids, bad ports and overlong URLs are refused.
#[test]
fn unsafe_urls_are_refused() {
    let long = format!("https://kdc.example.com/{}", "a".repeat(2048));
    for value in [
        "https://",
        "https:///KdcProxy",
        "https://user@kdc.example.com/KdcProxy",
        "https://user:pw@kdc.example.com/",
        "https://kdc.example.com?x/KdcProxy",
        "https://kdc.example.com#x/KdcProxy",
        "https://kdc.example.com/Kdc Proxy",
        "https://kdc.example.com/KdcProxy\r\nHost: evil",
        "https://kdc.example.com/KdcProxy#frag",
        "https://kdc.example.com/caf\u{e9}",
        "https://kdc.example.com:99999/",
        "https://kdc.example.com:x/",
        "https://[fe80::1%eth0]:443/",
        "https://[2001:db8::1/",
        "https:// kdc.example.com/p",
        "https://kdc\u{0}.example.com/p",
        "https://kdc\texample.com:1/p",
        "https://[ \u{0}\u{0}\u{0}]:01/:bp",
        long.as_str(),
    ] {
        let outcome = Url::parse(value);
        assert!(
            matches!(outcome, Err(Error::InvalidUrl { reason: _ })),
            "{value:?}: {outcome:?}"
        );
    }
}
