//! Residual parsing, principal descriptions and key payloads.

use super::TestError;
use crate::ccache::{
    Error, Principal,
    keyring::{
        Fault,
        residual::{
            Anchor, Residual, parse_description, parse_owner, parse_primary, parse_serials,
            primary_payload, unparse,
        },
    },
};

/// Parse a residual that must be valid.
fn parsed(text: &str) -> Result<Residual, Error> {
    Residual::parse(text)
}

/// A bare collection name uses the legacy anchor (`cc_keyring.c:285-292`).
#[test]
fn bare_collection_is_legacy() -> Result<(), TestError> {
    let residual = parsed("login")?;
    assert_eq!(residual.anchor, Anchor::Legacy, "anchor");
    assert_eq!(residual.collection, "login", "collection");
    assert_eq!(residual.subsidiary, None, "subsidiary");
    Ok(())
}

/// Every anchor name is recognised and an anchor with a collection has no
/// subsidiary (`cc_keyring.c:494-522`).
#[test]
fn anchors_are_recognised() -> Result<(), TestError> {
    for (text, anchor) in [
        ("persistent:1000", Anchor::Persistent),
        ("process:krb", Anchor::Process),
        ("thread:krb", Anchor::Thread),
        ("session:krb", Anchor::Session),
        ("user:krb", Anchor::User),
        ("legacy:krb", Anchor::Legacy),
    ] {
        let residual = parsed(text)?;
        assert_eq!(residual.anchor, anchor, "{text}");
        assert_eq!(residual.subsidiary, None, "{text}");
    }
    Ok(())
}

/// The subsidiary is everything after the second colon, colons included
/// (`cc_keyring.c:299-306`); an empty collection is allowed.
#[test]
fn subsidiary_keeps_later_colons() -> Result<(), TestError> {
    let residual = parsed("thread:krb:a:b")?;
    assert_eq!(residual.collection, "krb", "collection");
    assert_eq!(residual.subsidiary.as_deref(), Some("a:b"), "subsidiary");
    let empty = parsed("process:")?;
    assert_eq!(empty.collection, "", "empty collection");
    Ok(())
}

/// An unknown anchor is MIT `KRB5_KCC_INVALID_ANCHOR` (`cc_keyring.c:520-522`).
#[test]
fn unknown_anchor_is_rejected() {
    assert!(
        matches!(
            Residual::parse("Process:krb"),
            Err(Error::Keyring(Fault::InvalidAnchor { anchor })) if anchor == "Process"
        ),
        "anchors match case-sensitively, as strcmp does"
    );
}

/// A NUL cannot be a key description, and an empty subsidiary cannot name a
/// key.
#[test]
fn unusable_names_are_rejected() {
    for text in ["process:a\0b", "process:a:b\0", "process:a:"] {
        assert!(
            matches!(Residual::parse(text), Err(Error::InvalidCacheName)),
            "{text:?}"
        );
    }
}

/// The primary-name payload is version 1, a length, then the name (`cc_keyring.c:541-553`).
#[test]
fn primary_payload_matches_mit() -> Result<(), TestError> {
    let payload = primary_payload("abc");
    assert_eq!(
        payload, b"\0\0\0\x01\0\0\0\x03abc",
        "big-endian version and length"
    );
    assert_eq!(parse_primary(&payload)?, "abc", "round trip");
    let mut trailing = payload;
    trailing.push(0xff);
    assert_eq!(
        parse_primary(&trailing)?,
        "abc",
        "MIT ignores bytes after the name"
    );
    Ok(())
}

/// The malformed primary payloads of `parse_index` and the version check
/// (`cc_keyring.c:556-571,622-625`): a short header, a length past the
/// payload, an empty name, a NUL, and a name that is not UTF-8.
#[test]
fn malformed_primary_payloads_are_rejected() {
    for payload in [
        &b"\0\0\0\x01\0\0\0"[..],
        &b"\0\0\0\x01\0\0\0\x04a"[..],
        &b"\0\0\0\x01\0\0\0\0"[..],
        &b"\0\0\0\x01\0\0\0\x02a\0"[..],
        &b"\0\0\0\x01\0\0\0\x01\xff"[..],
    ] {
        assert!(
            matches!(
                parse_primary(payload),
                Err(Error::Keyring(Fault::MalformedPrimary))
            ),
            "{payload:?}"
        );
    }
    assert!(
        matches!(
            parse_primary(b"\0\0\0\x02\0\0\0\x01a"),
            Err(Error::Keyring(Fault::UnknownCollectionVersion {
                version: 2_i32
            }))
        ),
        "version 2"
    );
}

/// `keyctl_describe` is `type;uid;gid;permissions;description`; the
/// description may hold semicolons.
#[test]
fn descriptions_split_on_the_first_four_semicolons() {
    assert_eq!(
        parse_description("keyring;1000;-1;3f010000;krb_ccache_AbC"),
        Some(("keyring", "krb_ccache_AbC")),
        "keyring"
    );
    assert_eq!(
        parse_description("user;0;0;1;a;b"),
        Some(("user", "a;b")),
        "semicolon in the description"
    );
    assert_eq!(parse_description("user;0;0"), None, "too few fields");
}

/// The owner of a key is the second field of its description.
#[test]
fn owner_is_the_second_field() {
    assert_eq!(
        parse_owner("keyring;1000;-1;3f010000;_uid.1000"),
        Some(1000_u32),
        "uid"
    );
    assert_eq!(
        parse_owner("keyring;x;-1;3f010000;_uid"),
        None,
        "not a number"
    );
}

/// The bytes of the serials 5, 0 and -7 in native byte order, and a partial
/// tail.
#[cfg(target_endian = "little")]
const SERIALS: [u8; 15] = [5, 0, 0, 0, 0, 0, 0, 0, 249, 255, 255, 255, 1, 2, 3];
/// The bytes of the serials 5, 0 and -7 in native byte order, and a partial
/// tail.
#[cfg(target_endian = "big")]
const SERIALS: [u8; 15] = [0, 0, 0, 5, 0, 0, 0, 0, 255, 255, 255, 249, 1, 2, 3];

/// A keyring read is native-endian serials; a partial tail and a zero serial
/// are dropped.
#[test]
fn serials_are_native_endian() {
    assert_eq!(
        parse_serials(&SERIALS)
            .iter()
            .map(|serial| serial.get())
            .collect::<Vec<i32>>(),
        [5_i32, -7_i32]
    );
}

/// Names print as MIT `krb5_unparse_name` does (`unparse.c:74-130`).
#[test]
fn principals_unparse_with_mit_escapes() -> Result<(), TestError> {
    let plain = Principal::new(
        "EXAMPLE.COM",
        2,
        vec!["host".into(), "kdc.example.com".into()],
    );
    assert_eq!(unparse(&plain), "host/kdc.example.com@EXAMPLE.COM");
    let control = String::from_utf8(b"g\th\ni\x08j\0".to_vec())?;
    let escaped = Principal::new(
        "R@",
        1,
        vec!["a/b".into(), "c@d".into(), "e\\f".into(), control],
    );
    assert_eq!(
        unparse(&escaped),
        "a\\/b/c\\@d/e\\\\f/g\\th\\ni\\bj\\0@R\\@"
    );
    Ok(())
}
