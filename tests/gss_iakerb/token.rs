//! The IAKERB token: the RFC 2743 framing, the `IAKERB-HEADER` and the KDC
//! message (MIT `iakerb.c:203-330`, `asn1_k_encode.c:1094-1100`).

use rskrb5_ng::{error::Iakerb, gss::iakerb::Token};

use super::context::TestError;

/// The IAKERB mechanism OID `1.3.6.1.5.2.5` as a DER OBJECT IDENTIFIER.
const OID: [u8; 8] = [0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x02, 0x05];

/// An AS-REQ-looking message.
const MESSAGE: [u8; 5] = [0x6a, 0x03, 0x01, 0x02, 0x03];

/// The `IAKERB-HEADER` of `EXAMPLE.COM` without a cookie, as the ASN.1 module
/// lays it out: SEQUENCE { [1] UTF8String }.
fn header() -> Vec<u8> {
    let mut header = vec![0x30, 0x0f, 0xa1, 0x0d, 0x0c, 0x0b];
    header.extend_from_slice(b"EXAMPLE.COM");
    header
}

/// An RFC 2743 initial context token of the mechanism `oid` (a DER OBJECT
/// IDENTIFIER), token id `id` and `body`.
fn frame(oid: &[u8], id: [u8; 2], body: &[u8]) -> Vec<u8> {
    let mut content = oid.to_vec();
    content.extend_from_slice(&id);
    content.extend_from_slice(body);
    let mut token = vec![0x60, u8::try_from(content.len()).unwrap_or(0)];
    token.extend_from_slice(&content);
    token
}

/// The token MIT's layout gives for `EXAMPLE.COM`, no cookie and `MESSAGE`:
/// built here by hand from the ASN.1 module and the frame, not by the crate.
fn expected() -> Vec<u8> {
    frame(&OID, [0x05, 0x01], &[header(), MESSAGE.to_vec()].concat())
}

/// A token encodes to the layout MIT's ASN.1 module and framing give, and the
/// layout decodes back to the same token.
#[test]
fn encoding_matches_the_layout_of_the_asn1_module() -> Result<(), TestError> {
    // Given a token of a realm, no cookie and a message,
    let token = Token::new("EXAMPLE.COM", None, MESSAGE.to_vec());
    // when it is encoded, it is the hand-built layout,
    assert_eq!(token.encode()?, expected());
    // and the layout decodes to the same token.
    assert_eq!(Token::decode(&expected())?, token);
    Ok(())
}

/// The cookie rides in the second header field and survives a round trip.
#[test]
fn the_cookie_round_trips() -> Result<(), TestError> {
    // Given a token with a cookie,
    let token = Token::new("EXAMPLE.COM", Some(vec![1, 2]), MESSAGE.to_vec());
    let bytes = token.encode()?;
    // then the header holds the cookie field after the realm,
    assert!(
        bytes
            .windows(6)
            .any(|window| window == [0xa2, 0x04, 0x04, 0x02, 0x01, 0x02]),
        "context tag 2 holds the OCTET STRING"
    );
    // and the cookie comes back.
    assert_eq!(Token::decode(&bytes)?.cookie(), Some(&[1_u8, 2][..]));
    Ok(())
}

/// A realm-discovery request has an empty realm and an empty message.
#[test]
fn a_discovery_token_round_trips_with_empty_fields() -> Result<(), TestError> {
    // Given a discovery token,
    let bytes = Token::new("", None, Vec::new()).encode()?;
    // when it is decoded, both fields are empty,
    let decoded = Token::decode(&bytes)?;
    assert_eq!((decoded.realm(), decoded.message()), ("", &[][..]));
    // and it is an IAKERB token.
    assert!(Token::is_iakerb(&bytes));
    Ok(())
}

/// Only the IAKERB mechanism with token id `05 01` is an IAKERB token (MIT
/// `iakerb_is_iakerb_token`).
#[test]
fn other_mechanisms_and_token_ids_are_not_iakerb() {
    // Given the layout with the krb5 OID instead,
    let krb5_oid = [
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02,
    ];
    let krb5 = frame(&krb5_oid, [0x05, 0x01], &[header(), MESSAGE.to_vec()].concat());
    // then it is not an IAKERB token and does not decode as one,
    assert!(!Token::is_iakerb(&krb5));
    assert!(matches!(Token::decode(&krb5), Err(Iakerb::NotIakerb(_))));
    // and the layout with the AP-REQ token id is not one either.
    let ap_req = frame(&OID, [0x01, 0x00], &[header(), MESSAGE.to_vec()].concat());
    assert!(!Token::is_iakerb(&ap_req));
    assert!(matches!(Token::decode(&ap_req), Err(Iakerb::NotIakerb(_))));
}

/// Every prefix of a valid token, trailing bytes, a header that is not a
/// sequence and an oversized token are errors, not panics.
#[test]
fn malformed_tokens_are_errors() {
    let valid = expected();
    for end in 0..valid.len() {
        assert!(
            Token::decode(valid.get(..end).unwrap_or_default()).is_err(),
            "the {end}-byte prefix"
        );
    }
    let mut trailing = valid.clone();
    trailing.push(0);
    assert!(Token::decode(&trailing).is_err(), "a trailing byte");
    let mut not_a_sequence = valid;
    if let Some(tag) = not_a_sequence.get_mut(12) {
        *tag = 0x31;
    }
    assert!(Token::decode(&not_a_sequence).is_err(), "a SET header");
    let mut large = vec![0x60, 0x83, 0x04, 0x00, 0x00];
    large.resize(0x4_0010, 0);
    assert!(matches!(
        Token::decode(&large),
        Err(Iakerb::TokenTooLarge {
            maximum: 0x4_0000,
            actual: _
        })
    ));
}

/// A realm above 255 bytes does not encode.
#[test]
fn an_oversized_realm_does_not_encode() {
    let realm = "R".repeat(256);
    assert!(matches!(
        Token::new(&realm, None, Vec::new()).encode(),
        Err(Iakerb::BadToken(_))
    ));
}
