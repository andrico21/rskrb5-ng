//! The channel-binding digest.
//!
//! The RFC 4121 section 4.1.1.2 channel-binding digest.
//!
//! The expected digests were computed independently with Python's `hashlib`
//! (`md5(pack('<II', itype, len(iaddr)) + iaddr + pack('<II', atype,
//! len(aaddr)) + aaddr + pack('<I', len(data)) + data)`), the layout MIT
//! hashes in `kg_checksum_channel_bindings` (`util_cksum.c:30-76`).

use rskrb5_ng::{error::Gss, gss::ChannelBindings};

use super::context::TestError;

/// Lowercase hex of `bytes`.
fn hex(bytes: &[u8]) -> String {
    let digits = b"0123456789abcdef";
    bytes.iter().fold(String::new(), |mut out, byte| {
        for nibble in [byte >> 4_u8, byte & 0x0f_u8] {
            if let Some(digit) = digits.get(usize::from(nibble)) {
                out.push(char::from(*digit));
            }
        }
        out
    })
}

/// Addresses and application data hash in RFC 4121 order with little-endian
/// lengths.
#[test]
fn digest_covers_addresses_and_application_data() -> Result<(), TestError> {
    // Given bindings with both addresses and application data,
    let bindings = ChannelBindings::new(b"rskrb5".to_vec())?
        .with_initiator_address(2, vec![127, 0, 0, 1])?
        .with_acceptor_address(2, vec![127, 0, 0, 2])?;
    // when they are digested, then the digest is the independent MD5.
    assert_eq!(hex(&bindings.digest()), "bd409f7fc017567576090c4c29077b88");
    Ok(())
}

/// The TLS channel-binding constructors prefix the RFC 5929 and RFC 9266 labels.
#[test]
fn tls_bindings_carry_their_labels() -> Result<(), TestError> {
    // Given a server certificate hash, the tls-server-end-point bindings digest as expected.
    let end_point = ChannelBindings::tls_server_end_point(&[0xab; 32])?;
    assert_eq!(
        end_point.application_data(),
        [&b"tls-server-end-point:"[..], &[0xab; 32]].concat()
    );
    assert_eq!(hex(&end_point.digest()), "cae6d9ca7531fe8a11f91171b8c9a3ba");
    // Given 32 bytes of TLS exporter output, the tls-exporter bindings digest as expected.
    let exporter: Vec<u8> = (0_u8..32).collect();
    let bound = ChannelBindings::tls_exporter(&exporter)?;
    assert_eq!(hex(&bound.digest()), "232de8d17ccb639000833d0e7def6811");
    Ok(())
}

/// Empty bindings still hash (they are present), so their digest is not the
/// all-zero "absent" value.
#[test]
fn empty_bindings_are_present_not_absent() -> Result<(), TestError> {
    // Given bindings with no addresses and no data, the digest is MD5 of the empty layout.
    let empty = ChannelBindings::new(Vec::new())?;
    assert_eq!(hex(&empty.digest()), "441018525208457705bf09a8ee3c1093");
    assert_ne!(
        empty.digest(),
        [0; 16],
        "present bindings never digest to zeros"
    );
    Ok(())
}

/// Oversized fields are refused before hashing.
#[test]
fn oversized_binding_fields_are_refused() {
    // Given 64 KiB + 1 of application data, it is refused by its length.
    assert!(matches!(
        ChannelBindings::new(vec![0; 0x0001_0001]),
        Err(Gss::BindingTooLong {
            field: _,
            maximum: _,
            actual: _
        })
    ));
    // Given an address longer than 255 bytes, it is refused by its length.
    assert!(matches!(
        ChannelBindings::new(Vec::new())
            .and_then(|bound| bound.with_initiator_address(2, vec![0; 256])),
        Err(Gss::BindingTooLong {
            field: _,
            maximum: _,
            actual: _
        })
    ));
}
