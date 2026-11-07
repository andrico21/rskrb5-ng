//! NDR boundary contracts for hostile wire data.

use super::{Error, Reader, RpcUnicodeStringDescriptor};

/// Null arrays with nonzero counts must name the missing pointer.
#[test]
fn null_arrays_reject_nonzero_counts() -> Result<(), Error> {
    let mut reader = Reader::new(&[]);
    let first_error = super::read_deferred_rpc_unicode_strings(&mut reader, 0, 1, "array")
        .err()
        .ok_or(Error::LengthOverflow)?;
    assert!(
        matches!(first_error, Error::MissingNdrPointer("array")),
        "unicode null pointer"
    );
    assert!(
        matches!(
            super::read_deferred_claims_arrays(&mut reader, 0, 1, "array"),
            Err(Error::MissingNdrPointer("array"))
        ),
        "claims null pointer"
    );
    assert!(
        matches!(
            super::read_deferred_claim_entries(&mut reader, 0, 1, "array"),
            Err(Error::MissingNdrPointer("array"))
        ),
        "entries null pointer"
    );
    assert!(
        matches!(
            super::read_deferred_i64_array(&mut reader, 0, 1, "array"),
            Err(Error::MissingNdrPointer("array"))
        ),
        "i64 null pointer"
    );
    assert!(
        matches!(
            super::read_deferred_u64_array(&mut reader, 0, 1, "array"),
            Err(Error::MissingNdrPointer("array"))
        ),
        "u64 null pointer"
    );
    assert!(
        matches!(
            super::read_deferred_bool_array(&mut reader, 0, 1, "array"),
            Err(Error::MissingNdrPointer("array"))
        ),
        "bool null pointer"
    );
    assert!(
        matches!(
            super::read_deferred_lpwstr_array(&mut reader, 0, 1, "array"),
            Err(Error::MissingNdrPointer("array"))
        ),
        "strings null pointer"
    );
    assert!(
        matches!(
            super::read_deferred_sid_and_attributes(&mut reader, 0, 1, "array"),
            Err(Error::MissingNdrPointer("array"))
        ),
        "SID null pointer"
    );
    assert!(
        matches!(
            super::read_deferred_domain_group_memberships(&mut reader, 0, 1, "array"),
            Err(Error::MissingNdrPointer("array"))
        ),
        "domain null pointer"
    );
    Ok(())
}

/// Count ceilings are inclusive for both aligned and unaligned reads.
#[test]
fn conformant_count_ceiling_is_inclusive() -> Result<(), Error> {
    let ceiling_bytes = 1_000_000_u32.to_le_bytes();
    assert_eq!(
        super::read_ndr_reasonable_count(&mut Reader::new(&ceiling_bytes), "count")?,
        1_000_000
    );
    assert_eq!(
        super::read_reasonable_count(&mut Reader::new(&ceiling_bytes), "count")?,
        1_000_000
    );
    for count in [1_000_001_u32, 1_000_002] {
        let bytes = count.to_le_bytes();
        assert!(
            matches!(super::read_ndr_reasonable_count(&mut Reader::new(&bytes), "count"), Err(Error::UnreasonableNdrCount { count: actual, target: "count" }) if actual == count),
            "aligned ceiling"
        );
        assert!(
            matches!(super::read_reasonable_count(&mut Reader::new(&bytes), "count"), Err(Error::UnreasonableNdrCount { count: actual, target: "count" }) if actual == count),
            "unaligned ceiling"
        );
    }
    Ok(())
}

/// Each unsupported common-header field is rejected independently.
#[test]
fn wrapper_rejects_individually_invalid_header_fields() -> Result<(), Error> {
    for prefix in [[2, 0x10, 8, 0], [1, 0x11, 8, 0], [1, 0x10, 9, 0]] {
        let bytes = [
            prefix.as_slice(),
            &[0; 4],
            &8_u32.to_le_bytes(),
            &[0; 4],
            &1_u32.to_le_bytes(),
            &[0; 4],
        ]
        .concat();
        let error = super::read_ndr_wrapper(&mut Reader::new(&bytes), "wrapper")
            .err()
            .ok_or(Error::LengthOverflow)?;
        assert!(
            matches!(error, Error::InvalidNdrHeader),
            "invalid header accepted"
        );
    }
    Ok(())
}

/// Exact header boundaries reach object validation; truncation reaches the size guard.
#[test]
fn wrapper_distinguishes_exact_header_boundary() -> Result<(), Error> {
    let bytes = [
        [1, 0x10, 8, 0].as_slice(),
        &[0; 4],
        &4_u32.to_le_bytes(),
        &[0; 8],
    ]
    .concat();
    assert!(
        matches!(
            super::read_ndr_wrapper(&mut Reader::new(&bytes), "wrapper"),
            Err(Error::InvalidNdrObjectLength {
                object_len: 4,
                remaining: 4
            })
        ),
        "exact boundary misclassified"
    );
    assert!(
        matches!(
            super::read_ndr_wrapper(
                &mut Reader::new(bytes.get(..19).ok_or(Error::LengthOverflow)?),
                "wrapper"
            ),
            Err(Error::TooShort {
                minimum: 20,
                actual: 19,
                target: "wrapper"
            })
        ),
        "short boundary misclassified"
    );
    Ok(())
}

/// Varying strings check both offset and remaining count independently.
#[test]
fn claim_string_checks_offset_and_remaining_extent() -> Result<(), Error> {
    for (maximum, offset, actual, valid) in [
        (0_u32, 0_u32, 0_u32, true),
        (1, 1, 0, true),
        (1, 2, 0, false),
        (1, 0, 2, false),
        (2, 0, 1, true),
    ] {
        let bytes = [
            maximum.to_le_bytes().as_slice(),
            &offset.to_le_bytes(),
            &actual.to_le_bytes(),
            &[0; 4],
        ]
        .concat();
        let result = super::read_deferred_claim_string(&mut Reader::new(&bytes), 1, "string");
        if valid {
            assert_eq!(result?, "");
        } else {
            assert!(
                matches!(result, Err(Error::InvalidNdrArrayBounds { target: "string", max_count, offset: found_offset, actual_count }) if max_count == maximum && found_offset == offset && actual_count == actual),
                "invalid varying extent accepted"
            );
        }
    }
    Ok(())
}

/// Unicode descriptors reject an offset beyond the extent even with no characters.
#[test]
fn rpc_unicode_rejects_offset_past_extent() -> Result<(), Error> {
    let descriptor = RpcUnicodeStringDescriptor {
        length: 0,
        maximum_length: 0,
        referent_id: 1,
    };
    let bytes = [
        1_u32.to_le_bytes(),
        2_u32.to_le_bytes(),
        0_u32.to_le_bytes(),
    ]
    .concat();
    let error = super::read_deferred_unicode_string(&mut Reader::new(&bytes), descriptor, "string")
        .err()
        .ok_or(Error::LengthOverflow)?;
    assert!(
        matches!(
            error,
            Error::InvalidNdrArrayBounds {
                target: "string",
                max_count: 1,
                offset: 2,
                actual_count: 0
            }
        ),
        "invalid Unicode offset accepted"
    );
    Ok(())
}

/// SID count fifteen is accepted; conformant overflow and sixteen are rejected.
#[test]
fn sid_checks_conformant_and_protocol_limits() -> Result<(), Error> {
    for (maximum, count, valid) in [(15_u32, 15_u8, true), (14, 15, false), (16, 16, false)] {
        let bytes = [
            maximum.to_le_bytes().as_slice(),
            &[1, count],
            &[0, 0, 0, 0, 0, 5],
            &vec![0; usize::from(count).saturating_mul(4)],
        ]
        .concat();
        let result = super::read_deferred_sid(&mut Reader::new(&bytes), 1, "sid");
        if valid {
            assert_eq!(
                result?
                    .ok_or(Error::MissingNdrPointer("sid"))?
                    .sub_authorities
                    .len(),
                15
            );
        } else {
            assert!(
                matches!(result, Err(Error::InvalidSidSubAuthorityCount { target: "sid", max_count, actual_count }) if max_count == maximum && actual_count == count),
                "invalid SID count accepted"
            );
        }
    }
    Ok(())
}

/// Nonzero trailing data cannot be accepted as NDR padding.
#[test]
fn trailing_ndr_data_is_rejected() {
    assert!(
        matches!(
            super::ensure_zero_trailing(&mut Reader::new(&[1, 0, 0, 0]), "padding"),
            Err(Error::TrailingNdrBytesAfter {
                target: "padding",
                remaining: 4
            })
        ),
        "nonzero padding accepted"
    );
}
