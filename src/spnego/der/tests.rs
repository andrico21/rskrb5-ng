//! DER scalar boundary regressions, including the public SPNEGO decoder.

use alloc::collections::TryReserveError;
use core::num::TryFromIntError;

use proptest::{arbitrary::any, collection, prop_assert_eq, proptest};

use super::{
    DerReader, Error, ObjectIdentifier, decode_oid_value, decode_u32, encode_tlv, encode_u32,
};
use crate::spnego::{NegState, NegTokenResp};

/// Long lengths must use the shortest representation, including nested token fields.
#[test]
fn der_lengths_reject_nonminimal_forms() -> Result<(), Error> {
    let [native_count, ..] = size_of::<usize>().to_le_bytes();
    let mut native_length = vec![0x80 | native_count];
    native_length.extend_from_slice(&128_usize.to_be_bytes());
    for (length, size) in [
        (vec![0x81, 0x7f], 127),
        (vec![0x82, 0, 0x80], 128),
        (native_length, 128),
    ] {
        // Given a complete TLV with a redundant length representation.
        let mut bytes = vec![4];
        bytes.extend(length);
        bytes.resize(bytes.len().saturating_add(size), 0);
        // When the DER boundary reads it, then it rejects the encoding.
        assert!(matches!(
            DerReader::new(&bytes).read_tlv(),
            Err(Error::NonminimalLength)
        ));
    }
    matches!(
        NegTokenResp::decode(&[0xa1, 8, 0x30, 6, 0xa0, 4, 0x0a, 0x81, 1, 0]),
        Err(Error::NonminimalLength)
    )
    .ok_or(Error::NonminimalLength)
}

/// Minimal short and long length transitions preserve their complete contents.
#[test]
fn der_lengths_accept_minimal_boundaries() -> Result<(), Error> {
    for (length, size) in [
        (vec![127], 127),
        (vec![0x81, 128], 128),
        (vec![0x81, 255], 255),
        (vec![0x82, 1, 0], 256),
    ] {
        // Given independently encoded length boundary values.
        let mut bytes = vec![4];
        bytes.extend(length);
        bytes.resize(bytes.len().saturating_add(size), 0x42);
        // When decoded, then the exact payload extent remains available.
        assert_eq!(DerReader::new(&bytes).read_tlv()?.value().len(), size);
    }
    Ok(())
}

/// A state above `u32::MAX` must not alias accept-completed through the public decoder.
#[test]
fn der_state_overflow_cannot_alias_accept_completed() {
    let encoded = [
        0xa1, 0x0b, 0x30, 0x09, 0xa0, 0x07, 0x0a, 0x05, 1, 0, 0, 0, 0,
    ];
    assert!(matches!(
        NegTokenResp::decode(&encoded),
        Err(Error::InvalidInteger)
    ));
}

/// Positive integers use one sign octet only when their highest value bit is set.
#[test]
fn der_integer_rejects_nonminimal_and_negative_values() {
    for bytes in [
        &[0, 0][..],
        &[0, 0x7f],
        &[0, 0, 0x80],
        &[0x80],
        &[],
        &[1, 0, 0, 0, 0],
    ] {
        assert!(matches!(decode_u32(bytes), Err(Error::InvalidInteger)));
    }
}

/// Sign-octet transitions and the largest supported integer remain lossless.
#[test]
fn der_integer_preserves_unsigned_boundaries() -> Result<(), Error> {
    for value in [0, 1, 127, 128, 255, 256, 0x7fff_ffff, 0x8000_0000, u32::MAX] {
        assert_eq!(decode_u32(&encode_u32(value))?, value);
    }
    for (wire, expected) in [
        (0, NegState::AcceptCompleted),
        (1, NegState::AcceptIncomplete),
        (2, NegState::Reject),
        (3, NegState::RequestMic),
    ] {
        let encoded = [0xa1, 7, 0x30, 5, 0xa0, 3, 0x0a, 1, wire];
        assert_eq!(NegTokenResp::decode(&encoded)?.neg_state, Some(expected));
    }
    Ok(())
}

/// An oversized later arc must not alias 840 in the Kerberos mechanism OID.
#[test]
fn der_oid_overflow_cannot_alias_kerberos() {
    let encoded = [
        0xa1, 0x12, 0x30, 0x10, 0xa1, 0x0e, 6, 0x0c, 0x2a, 0x90, 0x80, 0x80, 0x86, 0x48, 0x86,
        0xf7, 0x12, 1, 2, 2,
    ];
    assert!(matches!(
        NegTokenResp::decode(&encoded),
        Err(Error::InvalidOidEncoding)
    ));
}

/// Zero leading base-128 groups and unterminated arcs are malformed, not aliases.
#[test]
fn der_oid_rejects_nonminimal_and_truncated_arcs() {
    for bytes in [&[0x2a, 0x80, 0][..], &[0x2a, 0x80, 1], &[0x2a, 0x81], &[]] {
        assert!(matches!(
            decode_oid_value(bytes),
            Err(Error::InvalidOidEncoding)
        ));
    }
}

/// Canonical zero and maximum later arcs stay in the supported u32 domain.
#[test]
fn der_oid_preserves_later_arc_boundaries() -> Result<(), Error> {
    let decoded = decode_oid_value(&[0x2a, 0, 0x8f, 0xff, 0xff, 0xff, 0x7f])?;
    assert_eq!(decoded.arcs(), &[1, 2, 0, u32::MAX]);
    Ok(())
}

/// Arc two uses the complete first subidentifier, including values above one octet.
#[test]
fn der_oid_arc_two_roundtrips_thresholds() -> Result<(), Error> {
    for second in [0, 39, 40, 47, 48, 100, u32::MAX - 80, u32::MAX] {
        let mut token = NegTokenResp::accept_completed();
        token.supported_mech = Some(ObjectIdentifier::from_arcs(vec![2, second, 1])?);
        assert_eq!(NegTokenResp::decode(&token.encode()?)?, token);
    }
    Ok(())
}

/// The constructor's maximum second arc must also be encodable and decodable.
#[test]
fn der_oid_arc_two_maximum_roundtrips() -> Result<(), Error> {
    let mut token = NegTokenResp::accept_completed();
    token.supported_mech = Some(ObjectIdentifier::from_arcs(vec![2, u32::MAX])?);
    assert_eq!(NegTokenResp::decode(&token.encode()?)?, token);
    Ok(())
}

/// Known DER content pins the first-subidentifier thresholds independently of the encoder.
#[test]
fn der_oid_decodes_first_subidentifier_vectors() -> Result<(), Error> {
    for (bytes, arcs) in [
        (&[39][..], [0, 39]),
        (&[40][..], [1, 0]),
        (&[79][..], [1, 39]),
        (&[80][..], [2, 0]),
        (&[120][..], [2, 40]),
        (&[0x81, 0x34][..], [2, 100]),
        (&[0x90, 0x80, 0x80, 0x80, 0x4f][..], [2, u32::MAX]),
    ] {
        assert_eq!(decode_oid_value(bytes)?.arcs(), &arcs);
    }
    Ok(())
}

/// First subidentifiers must be minimal, terminated and within the second arc's domain.
#[test]
fn der_oid_rejects_malformed_first_subidentifier() {
    for bytes in [
        &[0x80, 0][..],
        &[0x81][..],
        &[0x90, 0x80, 0x80, 0x80, 0x50][..],
        &[0x82, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0][..],
    ] {
        assert!(matches!(
            decode_oid_value(bytes),
            Err(Error::InvalidOidEncoding)
        ));
    }
}

proptest! {
    /// Every constructor-valid root and u32 arc survives the public SPNEGO codec.
    #[test]
    fn der_oid_roundtrip_property(
        root in 0_u32..=2,
        second in any::<u32>(),
        later in collection::vec(any::<u32>(), 0..16),
    ) {
        let mut arcs = vec![root, if root < 2 { second.rem_euclid(40) } else { second }];
        arcs.extend(later);
        let mut token = NegTokenResp::accept_completed();
        token.supported_mech = Some(ObjectIdentifier::from_arcs(arcs)?);
        prop_assert_eq!(NegTokenResp::decode(&token.encode()?)?, token);
    }
}

/// Complete token fields reject an extra element rather than prefix-decoding it.
#[test]
fn der_token_rejects_trailing_elements() {
    assert!(matches!(
        NegTokenResp::decode(&[0xa1, 9, 0x30, 7, 0xa0, 5, 0x0a, 1, 0, 5, 0]),
        Err(Error::TrailingData)
    ));
}

/// A length wider than usize cannot wrap around to a small accepted payload.
#[test]
fn der_lengths_reject_overwide_values() -> Result<(), TryFromIntError> {
    let count = size_of::<usize>().saturating_add(1);
    let octet = u8::try_from(count)?;
    let mut bytes = vec![4, 0x80 | octet, 1];
    bytes.resize(count.saturating_add(2), 0);
    bytes.extend_from_slice(&[0x42]);
    assert!(matches!(
        DerReader::new(&bytes).read_tlv(),
        Err(Error::LengthExceedsInput)
    ));
    Ok(())
}

/// Exactly 128 payload octets require the long-form length on the wire.
#[test]
fn der_encoder_uses_long_form_at_128() -> Result<(), TryReserveError> {
    let mut expected = vec![4, 0x81, 0x80];
    expected.try_reserve(128)?;
    expected.extend_from_slice(&[0x42; 128]);
    assert_eq!(encode_tlv(4, &[0x42; 128]), expected);
    Ok(())
}

/// High-tag-number identifiers cannot masquerade as single-octet DER tags.
#[test]
fn der_reader_rejects_high_tag_identifiers() {
    for tag in [0x1f, 0x3f, 0x5f, 0x7f, 0x9f, 0xbf, 0xdf, 0xff] {
        assert!(matches!(
            DerReader::new(&[tag, 0]).read_tlv(),
            Err(Error::HighTagNumber)
        ));
    }
}

/// OID construction rejects invalid roots and out-of-range second arcs.
#[test]
fn der_oid_constructor_rejects_invalid_arc_prefixes() {
    for arcs in [vec![], vec![1], vec![3, 0], vec![0, 40], vec![1, 40]] {
        assert!(matches!(
            ObjectIdentifier::from_arcs(arcs),
            Err(Error::InvalidOid)
        ));
    }
}
