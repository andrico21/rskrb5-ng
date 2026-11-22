//! PAC layout limits, duplicate and overlapping buffers, attributes and requestor parsing.

use core::error::Error;

use rskrb5_ng::{
    error::Pac as PacError,
    pac::{
        AttributesInfo, INFO_TYPE_PAC_ATTRIBUTES_INFO, INFO_TYPE_PAC_CLIENT_INFO,
        INFO_TYPE_PAC_REQUESTOR, Pac, RequestorSid,
    },
};

use super::{pac_vectors, vector};

/// A PAC with the buffers `(type, size, offset)` and `body` after the table.
fn raw(table: &[(u32, u32, u64)], body: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut out = u32::try_from(table.len())?.to_le_bytes().to_vec();
    out.extend_from_slice(&0_u32.to_le_bytes());
    for (ul_type, size, offset) in table {
        out.extend_from_slice(&ul_type.to_le_bytes());
        out.extend_from_slice(&size.to_le_bytes());
        out.extend_from_slice(&offset.to_le_bytes());
    }
    out.extend_from_slice(body);
    Ok(out)
}

/// Two buffers of one interpreted type are refused (MIT `k5_pac_locate_buffer` returns `EINVAL`).
#[test]
fn a_duplicate_interpreted_buffer_is_refused() -> Result<(), Box<dyn Error>> {
    // Given a PAC with two client-info buffers at different offsets.
    let bytes = raw(
        &[
            (INFO_TYPE_PAC_CLIENT_INFO, 10, 40),
            (INFO_TYPE_PAC_CLIENT_INFO, 10, 56),
        ],
        &[0; 32],
    )?;
    // When it is processed.
    // Then it is refused as a duplicate.
    assert!(matches!(
        Pac::parse_and_process(&bytes),
        Err(PacError::DuplicateBuffer(INFO_TYPE_PAC_CLIENT_INFO))
    ));
    Ok(())
}

/// Buffers that overlap each other, or that start inside the header and table, are refused.
#[test]
fn overlapping_buffers_are_refused() -> Result<(), Box<dyn Error>> {
    // Given a PAC whose second buffer starts inside the first one.
    let inside = raw(&[(100, 16, 40), (101, 8, 48)], &[0; 24])?;
    // And one whose buffer starts inside the table.
    let table = raw(&[(100, 8, 8)], &[0; 24])?;
    // When they are parsed.
    // Then both are refused.
    assert!(matches!(
        Pac::parse(&inside),
        Err(PacError::BufferOverlap {
            ul_type: 101,
            offset: 48
        })
    ));
    assert!(matches!(
        Pac::parse(&table),
        Err(PacError::BufferOverlap {
            ul_type: 100,
            offset: 8
        })
    ));
    Ok(())
}

/// Empty buffers may share an offset: they cover no byte.
#[test]
fn empty_buffers_do_not_overlap() -> Result<(), Box<dyn Error>> {
    // Given two empty buffers and one buffer at the same offset.
    let bytes = raw(&[(100, 0, 56), (101, 0, 56), (102, 8, 56)], &[0; 16])?;
    // When it is parsed.
    // Then it parses.
    assert_eq!(Pac::parse(&bytes)?.buffer_types(), vec![100, 101, 102]);
    Ok(())
}

/// A header that declares more than 4096 buffers is refused before any table is read (MIT
/// `MAX_BUFFERS`).
#[test]
fn more_than_4096_buffers_are_refused() -> Result<(), Box<dyn Error>> {
    // Given a header declaring 4097 buffers.
    let mut bytes = u32::try_from(4097_i32)?.to_le_bytes().to_vec();
    bytes.extend_from_slice(&0_u32.to_le_bytes());
    // When it is parsed.
    // Then it is refused by count.
    assert!(matches!(
        Pac::parse(&bytes),
        Err(PacError::BufferCountLimit(4097))
    ));
    Ok(())
}

/// The vectors' buffers are enumerated in table order (MIT `krb5_pac_get_types`).
#[test]
fn the_buffer_types_are_listed_in_table_order() -> Result<(), Box<dyn Error>> {
    // Given the service vector.
    let pac = Pac::parse_and_process(&vector(pac_vectors::SERVICE_PAC_AES256)?)?;
    // When its types are listed.
    // Then they follow MIT's signing order.
    assert_eq!(pac.buffer_types(), vec![10, 17, 18, 16, 6, 7, 19]);
    Ok(())
}

/// The attributes and requestor buffers of the vector decode.
#[test]
fn the_attributes_and_the_requestor_of_the_vector_decode() -> Result<(), Box<dyn Error>> {
    // Given the service vector, which carries PAC_REQUESTED and a requestor SID.
    let pac = Pac::parse_and_process(&vector(pac_vectors::SERVICE_PAC_AES256)?)?;
    // When its attributes are read.
    let attributes = pac.attributes_info().ok_or("attributes")?;
    // Then the flags and the SID are those the generator wrote.
    assert_eq!(attributes.flags_length(), 2);
    assert!(attributes.was_requested() && !attributes.was_given_implicitly());
    assert_eq!(
        pac.requestor_sid().ok_or("requestor")?.sid().to_string(),
        "S-1-5-21-1-2-3-1104"
    );
    assert_eq!(
        pac.buffer(INFO_TYPE_PAC_ATTRIBUTES_INFO)
            .map(|buffer| buffer.cb_buffer_size),
        Some(8)
    );
    assert_eq!(
        pac.buffer(INFO_TYPE_PAC_REQUESTOR)
            .map(|buffer| buffer.cb_buffer_size),
        Some(28)
    );
    Ok(())
}

/// `PAC_ATTRIBUTES_INFO` is bounded and exact.
#[test]
fn malformed_attributes_are_refused() -> Result<(), Box<dyn Error>> {
    // Given the Windows form: two bits, one word.
    let ok = AttributesInfo::parse(&[2, 0, 0, 0, 2, 0, 0, 0])?;
    assert!(ok.was_given_implicitly() && !ok.was_requested());
    // When too many bits are declared, the words are missing or non-zero bytes follow.
    let huge = AttributesInfo::parse(&[0xff, 0xff, 0, 0, 0, 0, 0, 0]);
    let short = AttributesInfo::parse(&[2, 0, 0, 0]);
    let trailing = AttributesInfo::parse(&[2, 0, 0, 0, 1, 0, 0, 0, 7, 0, 0, 0]);
    // Then each is refused.
    assert!(matches!(
        huge,
        Err(PacError::UnreasonableNdrCount {
            target: _,
            count: 0xffff
        })
    ));
    assert!(matches!(
        short,
        Err(PacError::Truncated {
            offset: 4,
            needed: 4,
            remaining: 0
        })
    ));
    assert!(matches!(
        trailing,
        Err(PacError::TrailingNdrBytesAfter {
            target: "PAC_ATTRIBUTES_INFO",
            remaining: 4
        })
    ));
    Ok(())
}

/// `PAC_REQUESTOR` is one plain SID with a known revision and at most 15 sub-authorities.
#[test]
fn malformed_requestor_sids_are_refused() -> Result<(), Box<dyn Error>> {
    // Given a valid SID first.
    assert_eq!(
        RequestorSid::parse(&[1, 0, 0, 0, 0, 0, 0, 5])?
            .sid()
            .to_string(),
        "S-1-5"
    );
    // Given a revision 2 SID, a SID with 16 sub-authorities and a truncated one.
    let revision = RequestorSid::parse(&[2, 0, 0, 0, 0, 0, 0, 5]);
    let mut many = vec![1, 16, 0, 0, 0, 0, 0, 5];
    many.extend_from_slice(&[0; 64]);
    let count = RequestorSid::parse(&many);
    let short = RequestorSid::parse(&[1, 2, 0, 0, 0, 0, 0, 5, 1, 0, 0, 0]);
    // When they are parsed.
    // Then each is refused.
    assert!(matches!(revision, Err(PacError::InvalidSidRevision(2))));
    assert!(matches!(
        count,
        Err(PacError::InvalidSidSubAuthorityCount {
            target: "PAC_REQUESTOR",
            max_count: 15,
            actual_count: 16
        })
    ));
    assert!(matches!(
        short,
        Err(PacError::Truncated {
            offset: 12,
            needed: 4,
            remaining: 0
        })
    ));
    Ok(())
}
