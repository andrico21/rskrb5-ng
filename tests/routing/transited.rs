//! DOMAIN-X500-COMPRESS (RFC 4120 section 3.3.3.2).
//!
//! MIT 1.22.2 `src/lib/krb5/krb/transit-tests` (sha256
//! d4536626111bbe422e741c49e4d2f5fda7a9c9cf27fe0a7d654f053d02f8a0fa, the
//! expansion `t_expand -x` prints through `chk_trans.c:169-286`), the encoder
//! round trip and the bounds of this crate.

use proptest::prelude::*;
use rskrb5_ng::{error::Routing, routing::transited};

use crate::TestError;

/// `transit-tests:18-49`: client realm, server realm, encoding and the expanded
/// realms (MIT compares them sorted).
const EXPANSIONS: [(&str, &str, &str, &[&str]); 8] = [
    (
        "ATHENA.MIT.EDU",
        "HACK.FOOBAR.COM",
        ",EDU,BLORT.COM,COM,",
        &["MIT.EDU", "EDU", "BLORT.COM", "COM", "FOOBAR.COM"],
    ),
    ("ATHENA.MIT.EDU", "EDU", ",", &["MIT.EDU"]),
    ("EDU", "ATHENA.MIT.EDU", ",", &["MIT.EDU"]),
    (
        "x",
        "x",
        "/COM,/HP,/APOLLO, /COM/DEC",
        &["/COM", "/COM/HP", "/COM/HP/APOLLO", "/COM/DEC"],
    ),
    (
        "x",
        "x",
        "EDU,MIT.,ATHENA.,WASHINGTON.EDU,CS.",
        &[
            "EDU",
            "MIT.EDU",
            "ATHENA.MIT.EDU",
            "WASHINGTON.EDU",
            "CS.WASHINGTON.EDU",
        ],
    ),
    (
        "ATHENA.MIT.EDU",
        "/COM/HP/APOLLO",
        ",EDU, /COM,",
        &["EDU", "MIT.EDU", "/COM", "/COM/HP"],
    ),
    (
        "ATHENA.MIT.EDU",
        "CS.CMU.EDU",
        ",EDU,",
        &["EDU", "MIT.EDU", "CMU.EDU"],
    ),
    (
        "XYZZY.ATHENA.MIT.EDU",
        "XYZZY.CS.CMU.EDU",
        ",EDU,",
        &["EDU", "MIT.EDU", "ATHENA.MIT.EDU", "CMU.EDU", "CS.CMU.EDU"],
    ),
];

/// Sort a realm list the way `transit-tests` compares it.
fn sorted<S>(realms: &[S]) -> Vec<String>
where
    S: AsRef<str>,
{
    let mut list: Vec<String> = realms
        .iter()
        .map(|realm| realm.as_ref().to_owned())
        .collect();
    list.sort();
    list
}

/// Every expansion vector of `transit-tests` gives MIT's realms.
#[test]
fn expansions_match_the_mit_vectors() -> Result<(), TestError> {
    for (client, server, encoding, expected) in EXPANSIONS {
        // When the encoding is decoded between the two realms.
        let realms = transited::decode(encoding.as_bytes(), client, server)?;
        // Then it names MIT's realms.
        assert_eq!(sorted(&realms), sorted(expected), "{encoding}");
    }
    Ok(())
}

/// `transit-tests:38`: a domain name joined to an X.500 name gives mixed name
/// styles between two neighbours, which MIT and this crate refuse.
#[test]
fn mixed_name_styles_are_refused() -> Result<(), TestError> {
    // When the MIT error vector is decoded.
    let error = transited::decode(b",EDU,/COM,", "ATHENA.MIT.EDU", "/COM/HP/APOLLO")
        .err()
        .ok_or("mixed styles accepted")?;
    // Then it is malformed.
    assert!(
        matches!(error, Routing::MalformedTransited { reason: _ }),
        "{error:?}"
    );
    Ok(())
}

/// Malformed encodings are refused.
///
/// A trailing escape, a NUL inside the encoding, unequal names of equal length
/// around an intermediate marker, and an empty name next to one. One trailing
/// NUL is stripped as MIT does (`chk_trans.c:319-320`).
#[test]
fn malformed_encodings_are_refused() -> Result<(), TestError> {
    for (encoding, client, server) in [
        (&b"EDU\\"[..], "A.EDU", "B.EDU"),
        (&b"ED\0U"[..], "A.EDU", "B.EDU"),
        (&b",,"[..], "A.EDU", "B.ORG"),
        (&b" ,"[..], "A.EDU", "B.EDU"),
        (&b"\xff"[..], "A.EDU", "B.EDU"),
    ] {
        // When the malformed encoding is decoded.
        let result = transited::decode(encoding, client, server);
        // Then it is refused as malformed.
        assert!(
            matches!(result, Err(Routing::MalformedTransited { reason: _ })),
            "{encoding:?}: {result:?}"
        );
    }
    // A single trailing NUL is not part of the encoding.
    assert_eq!(transited::decode(b"EDU\0", "A.EDU", "B.EDU")?, ["EDU"]);
    Ok(())
}

/// The byte, name and realm-count bounds hold before any expansion is kept.
#[test]
fn bounds_are_enforced() -> Result<(), TestError> {
    // Given an encoding, a name and a realm list just past each bound.
    let long_encoding = vec![b'A'; transited::MAX_ENCODED_BYTES + 1];
    let long_name = vec![b'A'; transited::MAX_REALM_BYTES + 1];
    let many: Vec<u8> = (0..=transited::MAX_REALMS)
        .map(|index| format!("R{index}"))
        .collect::<Vec<_>>()
        .join(",")
        .into_bytes();
    // When each is decoded.
    let encoding = transited::decode(&long_encoding, "A", "B")
        .err()
        .ok_or("long encoding accepted")?;
    let name = transited::decode(&long_name, "A", "B")
        .err()
        .ok_or("long name accepted")?;
    let count = transited::decode(&many, "A", "B")
        .err()
        .ok_or("many realms accepted")?;
    // Then each bound is named.
    assert!(
        matches!(encoding, Routing::TransitedTooLong { max } if max == transited::MAX_ENCODED_BYTES),
        "{encoding:?}"
    );
    assert!(
        matches!(name, Routing::TransitedRealmTooLong { max } if max == transited::MAX_REALM_BYTES),
        "{name:?}"
    );
    assert!(
        matches!(count, Routing::TransitedTooManyRealms { max } if max == transited::MAX_REALMS),
        "{count:?}"
    );
    Ok(())
}

/// The encoder uses the RFC 4120 forms.
///
/// It compresses with the suffix and prefix forms and escapes the characters
/// the decoder treats specially.
#[test]
fn encoder_uses_the_rfc_forms() -> Result<(), TestError> {
    // When the realms of the RFC 4120 section 3.3.3.2 example are encoded.
    let encoded = transited::encode(&[
        "EDU",
        "MIT.EDU",
        "ATHENA.MIT.EDU",
        "WASHINGTON.EDU",
        "CS.WASHINGTON.EDU",
    ])?;
    // Then the RFC's compressed form comes out.
    assert_eq!(encoded, b"EDU,MIT.,ATHENA.,WASHINGTON.EDU,CS.");
    // And special characters and standalone names that would join are protected.
    assert_eq!(
        transited::encode(&["A,B", "/X", "TRAIL.", " LEAD"])?,
        b"A\\,B, /X, TRAIL.,\\ LEAD"
    );
    Ok(())
}

/// Empty, NUL-bearing and oversized realms cannot be encoded.
#[test]
fn encoder_refuses_unrepresentable_realms() -> Result<(), TestError> {
    for realm in [
        String::new(),
        "A\0B".to_owned(),
        "A".repeat(transited::MAX_REALM_BYTES + 1),
    ] {
        // When the realm is encoded.
        let error = transited::encode(&[realm.as_str()])
            .err()
            .ok_or_else(|| format!("{realm:?} was encoded"))?;
        // Then it is refused.
        assert!(
            matches!(
                error,
                Routing::MalformedTransited { reason: _ }
                    | Routing::TransitedRealmTooLong { max: _ }
            ),
            "{error:?}"
        );
    }
    Ok(())
}

proptest! {
    /// Decoding an encoded realm list gives the list back.
    #[test]
    fn encoding_round_trips(
        realms in prop::collection::vec("[ ,./\\\\A-Z]{1,12}", 0..8),
    ) {
        // Given realms built from the characters the codec treats specially.
        // When they are encoded and decoded between two unrelated realms.
        let encoded = transited::encode(&realms).map_err(|error| TestCaseError::fail(error.to_string()))?;
        let decoded = transited::decode(&encoded, "CLIENT", "SERVER").map_err(|error| TestCaseError::fail(error.to_string()))?;
        // Then the same realms come back in the same order.
        prop_assert_eq!(decoded, realms);
    }
}
