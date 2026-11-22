//! `PA-PAC-REQUEST` (MS-KILE 2.2.2), typed include and exclude.

use core::error::Error;
use std::time::UNIX_EPOCH;

use rasn::der;
use rskrb5_ng::{
    client::{build_tgt_as_req, options::AsReq, principal::Principal},
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

/// An AS-REQ built with the typed request carries it as padata 128: the outgoing admission accepts
/// a `PA-PAC-REQUEST` that decodes (and refuses one that does not, see the padata inventory test).
#[test]
fn an_as_req_carries_the_typed_pac_request() -> Result<(), Box<dyn Error>> {
    // Given a TGT request whose options carry the exclude request as padata.
    let options = AsReq::new(UNIX_EPOCH, 7).with_padata(vec![Request::exclude().padata()?]);
    // When the AS-REQ is built and decoded again.
    let built = build_tgt_as_req(Principal::user("TEST.PAC", "alice"), options)?;
    let decoded: rasn_kerberos::AsReq = der::decode(built.der())?;
    // Then its padata holds exactly that element.
    let padata = decoded.0.padata.ok_or("the AS-REQ has padata")?;
    let [element] = padata.as_slice() else {
        return Err("exactly one padata element".into());
    };
    assert_eq!(element.r#type, PA_PAC_REQUEST);
    assert!(!Request::decode_der(&element.value)?.include_pac());
    Ok(())
}
