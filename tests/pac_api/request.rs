//! `PA-PAC-REQUEST` (MS-KILE 2.2.2), typed include and exclude.

use core::error::Error;

use rskrb5_ng::{
    error::Pac as PacError,
    pac::{PA_PAC_REQUEST, Request},
};

/// MS-KILE 2.2.2: `KERB-PA-PAC-REQUEST ::= SEQUENCE { include-pac[0] BOOLEAN }`, so the include
/// request is the DER `30 05 a0 03 01 01 ff` and the exclude request ends in `00`.
#[test]
fn the_request_encodes_to_the_ms_kile_der() -> Result<(), Box<dyn Error>> {
    // Given the include and exclude requests.
    // When they are encoded.
    // Then the DER is the MS-KILE one.
    assert_eq!(
        Request::include().encode_der()?,
        [0x30, 0x05, 0xa0, 0x03, 0x01, 0x01, 0xff]
    );
    assert_eq!(
        Request::exclude().encode_der()?,
        [0x30, 0x05, 0xa0, 0x03, 0x01, 0x01, 0x00]
    );
    Ok(())
}

/// The request decodes back and rides in a `PA-DATA` of type 128.
#[test]
fn the_request_round_trips_in_padata() -> Result<(), Box<dyn Error>> {
    // Given the exclude request as padata.
    let padata = Request::exclude().padata()?;
    // When the padata value is decoded.
    let decoded = Request::decode_der(&padata.value)?;
    // Then the type is 128 and the choice survives.
    assert_eq!(padata.r#type, PA_PAC_REQUEST);
    assert_eq!(PA_PAC_REQUEST, 128_i32);
    assert!(!decoded.include_pac());
    assert!(Request::decode_der(&Request::include().encode_der()?)?.include_pac());
    Ok(())
}

/// Malformed, truncated and trailing input is refused.
#[test]
fn malformed_requests_are_refused() {
    // Given a wrong tag, a truncated value, trailing bytes and an empty input.
    for bad in [
        &[0x30, 0x05, 0xa1, 0x03, 0x01, 0x01, 0xff][..],
        &[0x30, 0x05, 0xa0, 0x03, 0x01][..],
        &[0x30, 0x05, 0xa0, 0x03, 0x01, 0x01, 0xff, 0x00][..],
        &[][..],
    ] {
        // When they are decoded.
        // Then each is refused.
        assert!(matches!(
            Request::decode_der(bad),
            Err(PacError::DerDecode(_))
        ));
    }
}
