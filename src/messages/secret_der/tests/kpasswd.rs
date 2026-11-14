//! Kpasswd request encoder ownership regressions.

use core::error::Error;

use super::ERASED;
use crate::kadmin::Request;

/// Encoding erases its AP-REQ and KRB-PRIV staging before returning the frame.
#[test]
fn request_encoding_erases_its_staging() -> Result<(), Box<dyn Error>> {
    // Given a request parsed from its wire frame.
    let frame = hex::decode(include_str!("../../../../tests/fixtures/kpasswd-request.hex").trim())?;
    let request = Request::parse(&frame)?;
    let [_, _, _, _, high, low, ..] = frame.as_slice() else {
        return Err("fixture shorter than a request header".into());
    };
    let ap_req_length = usize::from(u16::from_be_bytes([*high, *low]));
    ERASED.with_borrow_mut(Vec::clear);
    // When the real encoder builds the frame.
    let encoded = request.encode()?;
    // Then both encoded parts were erased and the caller's frame is intact.
    assert_eq!(encoded, frame);
    ERASED.with_borrow(|events| {
        assert_eq!(
            events.as_slice(),
            [
                (
                    "kpasswd krb-priv",
                    frame.len().saturating_sub(6).saturating_sub(ap_req_length)
                ),
                ("kpasswd ap-req", ap_req_length),
            ]
        );
    });
    Ok(())
}
