//! KDC-PROXY-MESSAGE vectors: MIT 1.22.2's encoder output and the framing rules.

use core::error::Error as StdError;

use super::{Error, MAX_MESSAGE, ProxyMessage, decode_reply, encode_request};

/// `encode_krb5_kkdcp_message` of MIT 1.22.2's ASN.1 test.
///
/// From `src/tests/asn.1/reference_encode.out:69`, built by
/// `ktest_make_sample_kkdcp_message` (`src/tests/asn.1/ktest.c:863-877`): a sample
/// AS-REQ, target domain `krb5data`, no hint.
const MIT_REFERENCE: &str = include_str!("mit_reference.hex");

/// The message with `kerb_message` and `realm`, DER-encoded.
fn message(kerb_message: &[u8], realm: Option<&[u8]>) -> Result<Vec<u8>, Error> {
    Ok(ProxyMessage::new(kerb_message, realm, None)
        .encode()?
        .to_vec())
}

/// MIT's reference encoding decodes field by field and encodes back to the same bytes.
#[test]
fn mit_reference_encoding_round_trips() -> Result<(), Box<dyn StdError>> {
    let bytes = hex::decode(MIT_REFERENCE.trim())?;
    let decoded = ProxyMessage::decode(&bytes)?;
    assert_eq!(decoded.kerb_message().len(), 488);
    assert_eq!(
        decoded.kerb_message().get(..4),
        Some([0x6a, 0x82, 0x01, 0xe4].as_slice())
    );
    assert_eq!(decoded.target_domain(), Some(b"krb5data".as_slice()));
    assert_eq!(decoded.dclocator_hint(), None);
    assert_eq!(decoded.encode()?.as_slice(), bytes.as_slice());
    Ok(())
}

/// A request is framed as MIT frames it: record mark, request, realm as target.
#[test]
fn request_carries_its_record_mark_and_realm() -> Result<(), Box<dyn StdError>> {
    let encoded = encode_request(&[0x6a, 1, 2], "EXAMPLE.COM")?;
    let decoded = ProxyMessage::decode(&encoded)?;
    assert_eq!(decoded.kerb_message(), [0, 0, 0, 3, 0x6a, 1, 2]);
    assert_eq!(decoded.target_domain(), Some(b"EXAMPLE.COM".as_slice()));
    assert_eq!(decoded.dclocator_hint(), None);
    Ok(())
}

/// A reply yields the message behind a matching record mark, and nothing else.
#[test]
fn reply_needs_a_matching_record_mark() -> Result<(), Box<dyn StdError>> {
    assert_eq!(
        decode_reply(&message(&[0, 0, 0, 2, 0x6b, 9], None)?)?,
        [0x6b, 9]
    );
    for (kerb_message, reason) in [
        (&[0, 0, 0][..], "the Kerberos message has no record mark"),
        (
            &[0, 0, 0, 3, 0x6b, 9][..],
            "the record mark does not match the Kerberos message",
        ),
        (
            &[0, 0, 0, 1, 0x6b, 9][..],
            "the record mark does not match the Kerberos message",
        ),
        (
            &[0x80, 0, 0, 2, 0x6b, 9][..],
            "the record mark does not match the Kerberos message",
        ),
        (&[0, 0, 0, 0][..], "the Kerberos message is empty"),
    ] {
        let outcome = decode_reply(&message(kerb_message, Some(b"R"))?);
        assert!(
            matches!(outcome, Err(Error::Malformed { reason: found }) if found == reason),
            "{kerb_message:?}: {outcome:?}"
        );
    }
    Ok(())
}

/// Bytes that are not exactly one message, or too many bytes, are refused.
#[test]
fn reply_bytes_are_bounded_and_complete() -> Result<(), Box<dyn StdError>> {
    let mut trailing = message(&[0, 0, 0, 1, 0x6b], None)?;
    trailing.push(0);
    for bytes in [
        trailing.as_slice(),
        &[],
        &[0x30, 0x03, 0xa0],
        &[0x04, 0x01, 0x00],
    ] {
        assert!(
            matches!(
                decode_reply(bytes),
                Err(Error::Malformed {
                    reason: "not one DER KDC-PROXY-MESSAGE"
                })
            ),
            "{bytes:?}"
        );
    }
    let oversized = vec![0; MAX_MESSAGE.saturating_add(1)];
    assert!(matches!(
        decode_reply(&oversized),
        Err(Error::TooLarge { actual, limit: MAX_MESSAGE }) if actual == oversized.len()
    ));
    Ok(())
}

/// A request longer than the bound is refused before it is framed.
#[test]
fn request_is_bounded() {
    let request = vec![0; MAX_MESSAGE.saturating_add(1)];
    assert!(matches!(
        encode_request(&request, "R"),
        Err(Error::TooLarge { actual, limit: MAX_MESSAGE }) if actual == request.len()
    ));
}
