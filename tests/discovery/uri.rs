//! The `krb5srv:` URI record target and `host[:port]` splitting (MIT-dns-2): MIT
//! `locate_kdc.c:552-601` (`parse_uri_fields`) and `parse_host_string.c`.

use rskrb5_ng::discovery::uri::{self, MAX_TARGET_BYTES, Transport};

use crate::TestError;

/// One record: transport, primary flag, target text.
fn parsed(record: &str) -> Option<(Transport, bool, String)> {
    uri::parse(record.as_bytes()).map(|target| (target.transport, target.primary, target.spec))
}

/// The flags field carries `m` in any letter case among other letters; the transport is matched
/// in any letter case.
#[test]
fn the_fields_follow_parse_uri_fields() {
    assert_eq!(
        parsed("krb5srv::udp:kdc.example"),
        Some((Transport::Udp, false, "kdc.example".to_owned()))
    );
    assert_eq!(
        parsed("KRB5SRV:xMz:TCP:kdc.example:1088"),
        Some((Transport::Tcp, true, "kdc.example:1088".to_owned()))
    );
    assert_eq!(
        parsed("krb5srv:m:kkdcp:https://p.example/KdcProxy"),
        Some((
            Transport::Kkdcp,
            true,
            "https://p.example/KdcProxy".to_owned()
        ))
    );
    // The target may be empty here; `host_port` then refuses it.
    assert_eq!(
        parsed("krb5srv::tcp:"),
        Some((Transport::Tcp, false, String::new()))
    );
}

/// Anything else is a record to ignore, never an error.
#[test]
fn other_records_are_ignored() {
    for record in [
        "",
        "krb5srv",
        "krb5srv:",
        "krb5srv:tcp:host",
        "krb5srv::tcp",
        "krb5srv::sctp:host",
        "krb5srv::udpx:host",
        "krb5srv::kkdc:host",
        "http::tcp:host",
        "krb5srvx::tcp:host",
        "krb5srv:::host",
    ] {
        assert_eq!(parsed(record), None, "{record:?}");
    }
    assert_eq!(uri::parse(b"krb5srv::tcp:\xff\xfe"), None);
}

/// The target is bounded.
#[test]
fn an_oversized_target_is_ignored() -> Result<(), TestError> {
    let within = format!("krb5srv::tcp:{}", "a".repeat(MAX_TARGET_BYTES - 4));
    let over = format!("krb5srv::tcp:{}", "a".repeat(MAX_TARGET_BYTES + 1));
    let accepted = parsed(&within).ok_or("a target at the bound is accepted")?;
    assert_eq!(accepted.0, Transport::Tcp);
    assert_eq!(parsed(&over), None);
    Ok(())
}

/// `host[:port]` as `k5_parse_host_string` reads it, with digits-only ports.
#[test]
fn host_and_port_are_split_by_the_endpoint_rule() -> Result<(), TestError> {
    let plain = uri::host_port("kdc.example:1", 88).ok_or("a plain host and port")?;
    assert_eq!(plain.1, 1);
    for (text, expected) in [
        ("kdc.example", Some(("kdc.example", 88))),
        ("kdc.example:1088", Some(("kdc.example", 1088))),
        ("[fd00::1]", Some(("fd00::1", 88))),
        ("[fd00::1]:1088", Some(("fd00::1", 1088))),
        ("kdc.example:65535", Some(("kdc.example", u16::MAX))),
        ("kdc.example:65536", None),
        ("kdc.example:+88", None),
        ("kdc.example:", None),
        ("kdc.example: 88", None),
        ("kdc.example:8x", None),
        ("[fd00::1]x", None),
        ("[fd00::1", None),
        ("[[fd00::1]", None),
        ("[]:88", None),
        (":88", None),
        ("88", None),
        ("", None),
        ("host name", None),
    ] {
        assert_eq!(
            uri::host_port(text, 88),
            expected.map(|(host, port)| (host.to_owned(), port)),
            "{text:?}"
        );
    }
    Ok(())
}

/// The URI record data is priority, weight and the target, which may be empty.
#[test]
fn rdata_splits_into_priority_and_target() {
    assert_eq!(
        uri::split_rdata(&[0, 7, 0, 9, b'k', b'r']),
        Some((7, &b"kr"[..]))
    );
    assert_eq!(uri::split_rdata(&[1, 2, 3, 4]), Some((258, &b""[..])));
    for short in [&[][..], &[0][..], &[0, 1, 2][..]] {
        assert_eq!(uri::split_rdata(short), None);
    }
}

/// A TXT realm is accepted only as a plain realm name, with one trailing dot removed.
#[test]
fn a_txt_realm_must_be_a_plain_realm_name() -> Result<(), TestError> {
    let plain = uri::realm_from_txt(b"R").ok_or("a plain realm")?;
    assert_eq!(plain, "R");
    assert_eq!(
        uri::realm_from_txt(b"EXAMPLE.COM"),
        Some("EXAMPLE.COM".to_owned())
    );
    assert_eq!(
        uri::realm_from_txt(b"EXAMPLE.COM."),
        Some("EXAMPLE.COM".to_owned())
    );
    assert_eq!(uri::realm_from_txt(b"EXAMPLE.COM.."), None);
    let longest = "R".repeat(255);
    assert_eq!(
        uri::realm_from_txt(longest.as_bytes()),
        Some(longest.clone())
    );
    assert_eq!(uri::realm_from_txt(format!("{longest}R").as_bytes()), None);
    for bad in [
        &b""[..],
        b".",
        b"A@B",
        b"A/B",
        b"A\\B",
        b"A:B",
        b"A B",
        b"A\x00B",
        &[0xff],
    ] {
        assert_eq!(uri::realm_from_txt(bad), None, "{bad:?}");
    }
    Ok(())
}
