//! The MIG messages of the KCM Mach RPC `call` routine.
//!
//! The routine is MIT 1.22.2 `src/lib/krb5/ccache/kcmrpc.defs` (subsystem
//! `mheim_ipc` 1, the same routine as Heimdal's `heim_ipc.defs`), laid out
//! as `mig` (`bootstrap_cmds`) generates it for a 64-bit little-endian
//! Darwin target with `#pragma pack(4)`:
//!
//! - request (id 1): header, one out-of-line descriptor `requestout`, the
//!   NDR record, `requestinCnt`, `requestin` (at most 2048 bytes, padded to 4),
//!   `requestoutCnt`;
//! - reply (id 101): header, one out-of-line descriptor `replyout`, the NDR
//!   record, `returnvalue`, `replyinCnt`, `replyin` (padded), `replyoutCnt`;
//!   or a simple `mig_reply_error_t` carrying a nonzero `RetCode`.
//!
//! Every field is checked as MIG's `__MIG_check__Reply__call_t` checks it.

use crate::error::Platform;

/// The largest in-band body (`k5_kcm_inband_msg`).
pub(crate) const INBAND_MAX: usize = 2048;
/// The request message id (subsystem base 1, routine 0).
const REQUEST_ID: u32 = 1;
/// The reply message id (request id + 100).
const REPLY_ID: u32 = 101;
/// `MACH_NOTIFY_SEND_ONCE`: the server died holding the reply right.
const SEND_ONCE_NOTIFICATION: u32 = 0x47;
/// `MACH_MSGH_BITS_COMPLEX`.
const COMPLEX: u32 = 0x8000_0000;
/// `MACH_MSG_TYPE_COPY_SEND` (19) remote, `MACH_MSG_TYPE_MAKE_SEND_ONCE` (21) local.
const REQUEST_BITS: u32 = COMPLEX | 0x13 | (0x15 << 8);
/// `MACH_MSG_TYPE_MOVE_SEND_ONCE` (18) remote, no local right.
#[cfg(test)]
const REPLY_BITS: u32 = COMPLEX | 0x12;
/// Descriptor flags: not deallocated, `MACH_MSG_VIRTUAL_COPY`, type
/// `MACH_MSG_OOL_DESCRIPTOR`.
const OOL_FLAGS: u32 = (1 << 8) | (1 << 24);
/// `NDR_record`: little-endian integers, ASCII, IEEE floats.
const NDR: [u8; 8] = [0, 0, 0, 0, 1, 0, 0, 0];
/// Fixed bytes of a request around its in-band body.
const REQUEST_FIXED: usize = 60;
/// Fixed bytes of a reply around its in-band body.
pub(crate) const REPLY_FIXED: usize = 64;
/// The size of `mig_reply_error_t`.
const ERROR_REPLY: usize = 36;
/// The cache type the failures name.
const CACHE_TYPE: &str = "KCM";

const _: () = assert!(
    cfg!(target_endian = "little"),
    "Darwin Mach messages are little-endian"
);

/// An out-of-line region: its address and length.
pub(crate) type Region = (u64, u32);

/// A decoded body: the in-band bytes and the out-of-line region, which is
/// `(0, 0)` when the body is in band.
pub(crate) type Body = (Vec<u8>, Region);

/// The ports of a message header: destination, then reply port.
pub(crate) type Ports = (u32, u32);

/// A malformed-message failure.
const fn malformed(reason: &'static str) -> Platform {
    Platform::MalformedReply {
        cache_type: CACHE_TYPE,
        reason,
    }
}

/// `n` rounded up to a multiple of four (`_WALIGN_`).
const fn padded(length: usize) -> usize {
    length.saturating_add(3) & !3
}

/// Append a little-endian word.
fn word(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

/// A message length as a 32-bit field.
/// # Errors
/// Returns [`Platform::TooLarge`] above `u32::MAX`.
fn length(value: usize) -> Result<u32, Platform> {
    u32::try_from(value).map_err(|_overflow| Platform::TooLarge {
        cache_type: CACHE_TYPE,
        length: value,
    })
}

/// Encode a header, descriptor and NDR record.
fn head(out: &mut Vec<u8>, bits: u32, size: u32, ports: Ports, id: u32, region: Region) {
    let (remote, local) = ports;
    let (address, outband_length) = region;
    for value in [bits, size, remote, local, 0, id, 1] {
        word(out, value);
    }
    out.extend_from_slice(&address.to_le_bytes());
    word(out, OOL_FLAGS);
    word(out, outband_length);
    out.extend_from_slice(&NDR);
}

/// Encode a complex message: header, descriptor, NDR, the return value
/// when given, the in-band count and body, then the out-of-line count.
/// # Errors
/// Returns [`Platform::TooLarge`] for a payload above 4 GiB.
fn message(
    bits: u32,
    ports: Ports,
    id: u32,
    code: Option<i32>,
    body: (&[u8], u64),
) -> Result<Vec<u8>, Platform> {
    let (payload, address) = body;
    let (inband, region) = if payload.len() <= INBAND_MAX {
        (payload, (0, 0))
    } else {
        (&[][..], (address, length(payload.len())?))
    };
    let fixed = if code.is_some() {
        REPLY_FIXED
    } else {
        REQUEST_FIXED
    };
    let size = fixed.saturating_add(padded(inband.len()));
    let mut out = Vec::with_capacity(size);
    head(&mut out, bits, length(size)?, ports, id, region);
    if let Some(value) = code {
        out.extend_from_slice(&value.to_le_bytes());
    }
    word(&mut out, length(inband.len())?);
    out.extend_from_slice(inband);
    out.resize(size.saturating_sub(4), 0);
    word(&mut out, region.1);
    Ok(out)
}

/// Encode a `call` request whose body is `payload`, in band when it fits,
/// else out of line at `address` (which must stay mapped for the call).
/// # Errors
/// Returns [`Platform::TooLarge`] for a payload above 4 GiB.
pub(crate) fn request(ports: Ports, payload: &[u8], address: u64) -> Result<Vec<u8>, Platform> {
    message(REQUEST_BITS, ports, REQUEST_ID, None, (payload, address))
}

#[cfg(test)]
/// Encode a `call` reply (the server side, for the test fixture): `code`,
/// then `payload` in band when it fits, else out of line at `address`.
/// # Errors
/// Returns [`Platform::TooLarge`] for a payload above 4 GiB.
pub(crate) fn reply(
    reply_port: u32,
    code: i32,
    payload: &[u8],
    address: u64,
) -> Result<Vec<u8>, Platform> {
    message(
        REPLY_BITS,
        (reply_port, 0),
        REPLY_ID,
        Some(code),
        (payload, address),
    )
}

/// The little-endian word at `offset`.
/// # Errors
/// Returns [`Platform::MalformedReply`] past the end.
fn read(bytes: &[u8], offset: usize) -> Result<u32, Platform> {
    bytes
        .get(offset..offset.saturating_add(4))
        .and_then(|slice| <[u8; 4]>::try_from(slice).ok())
        .map(u32::from_le_bytes)
        .ok_or_else(|| malformed("message is truncated"))
}

/// Decode the descriptor, counts and body of a complex message whose
/// in-band count sits at `count_at`.
/// # Errors
/// Returns [`Platform::MalformedReply`] for any shape MIG refuses.
fn body(message: &[u8], count_at: usize) -> Result<Body, Platform> {
    let size = usize::try_from(read(message, 4)?).map_err(|_size| malformed("size"))?;
    let fixed = count_at.saturating_add(8);
    if read(message, 24)? != 1 || read(message, 36)? >> 24_u32 != 1 {
        return Err(malformed("descriptor is not one out-of-line region"));
    }
    let count = usize::try_from(read(message, count_at)?).map_err(|_count| malformed("count"))?;
    if count > INBAND_MAX || size != fixed.saturating_add(padded(count)) || size > message.len() {
        return Err(malformed("in-band count disagrees with the size"));
    }
    let start = count_at.saturating_add(4);
    let inband = message
        .get(start..start.saturating_add(count))
        .ok_or_else(|| malformed("in-band body is truncated"))?
        .to_vec();
    let address_bytes = message
        .get(28..36)
        .and_then(|slice| <[u8; 8]>::try_from(slice).ok())
        .ok_or_else(|| malformed("descriptor is truncated"))?;
    let outband = (u64::from_le_bytes(address_bytes), read(message, 40)?);
    if read(message, size.saturating_sub(4))? != outband.1 {
        return Err(malformed("out-of-line count disagrees with its descriptor"));
    }
    Ok((inband, outband))
}

/// Decode a received `call` reply into the server's return value and body.
/// Its `msgh_remote_port` must be null: the server sends no reply right.
/// # Errors
/// Returns [`Platform::MachRpc`] for an error reply or a dead server, and
/// [`Platform::MalformedReply`] for any other shape MIG refuses.
pub(crate) fn decode_reply(message: &[u8]) -> Result<(i32, Body), Platform> {
    let id = read(message, 20)?;
    if id == SEND_ONCE_NOTIFICATION {
        return Err(Platform::MachRpc { code: -308 });
    }
    if id != REPLY_ID || read(message, 8)? != 0 {
        return Err(malformed("reply id or ports"));
    }
    if read(message, 0)? & COMPLEX == 0 {
        let code = i32::from_le_bytes(read(message, 32)?.to_le_bytes());
        let simple = usize::try_from(read(message, 4)?).is_ok_and(|size| size == ERROR_REPLY);
        return Err(if simple && code != 0 {
            Platform::MachRpc { code }
        } else {
            malformed("simple reply without an error")
        });
    }
    let code = i32::from_le_bytes(read(message, 52)?.to_le_bytes());
    Ok((code, body(message, 56)?))
}

#[cfg(test)]
/// Decode a received `call` request into its reply port and body.
///
/// This is the server side, for the test fixture. A received header holds
/// the sender's reply port in `msgh_remote_port`: the kernel swaps the two
/// port fields.
/// # Errors
/// Returns [`Platform::MalformedReply`] for any shape MIG refuses.
pub(crate) fn decode_request(message: &[u8]) -> Result<(u32, Body), Platform> {
    if read(message, 20)? != REQUEST_ID || read(message, 0)? & COMPLEX == 0 {
        return Err(malformed("request id or bits"));
    }
    Ok((read(message, 8)?, body(message, 52)?))
}

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use super::{INBAND_MAX, NDR, Platform, Ports, decode_reply, decode_request, reply, request};

    /// The ports of the test messages.
    const PORTS: Ports = (0x1103, 0x2207);

    /// A sent message as the receiver sees it: the kernel swaps the remote
    /// and local port fields.
    fn delivered(message: &[u8]) -> Vec<u8> {
        let remote = message.get(8..12).unwrap_or_default();
        let local = message.get(12..16).unwrap_or_default();
        let (head, _) = message.split_at_checked(8).unwrap_or_default();
        let tail = message.get(16..).unwrap_or_default();
        [head, local, remote, tail].concat()
    }

    /// An in-band request has MIG's exact layout and decodes back.
    #[test]
    fn inband_request_layout() -> Result<(), Platform> {
        // Given a five-byte KCM request.
        // When it is encoded.
        let message = request(PORTS, &[2, 0, 0, 20, 7], 0)?;
        // Then it is 60 + 8 bytes: header, empty descriptor, NDR, count, body, out count.
        let expected = [
            &[
                0x13, 0x15, 0, 0x80, 68, 0, 0, 0, 3, 0x11, 0, 0, 7, 0x22, 0, 0,
            ][..],
            &[0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0],
            &[0; 8],
            &[0, 1, 0, 1, 0, 0, 0, 0],
            &[0, 0, 0, 0, 1, 0, 0, 0],
            &[5, 0, 0, 0, 2, 0, 0, 20, 7, 0, 0, 0, 0, 0, 0, 0],
        ]
        .concat();
        assert_eq!(message, expected);
        let (port, body) = decode_request(&delivered(&message))?;
        assert_eq!(port, PORTS.1, "the sender's reply port");
        assert_eq!(body, (vec![2_u8, 0, 0, 20, 7], (0_u64, 0_u32)));
        Ok(())
    }

    /// A body above 2048 bytes travels out of line.
    #[test]
    fn large_body_is_out_of_line() -> Result<(), Platform> {
        // Given a body one byte above the in-band bound.
        let payload = vec![1_u8; INBAND_MAX.saturating_add(1)];
        // When requests and replies carry it.
        let message = request(PORTS, &payload, 0x1000)?;
        let answer = reply(9, 0, &payload, 0x2000)?;
        // Then only the descriptor names it and the in-band count is zero.
        assert_eq!(message.len(), 60);
        let (_, body) = decode_request(&delivered(&message))?;
        assert_eq!(body, (Vec::new(), (0x1000_u64, 2049_u32)));
        let (code, reply_body) = decode_reply(&delivered(&answer))?;
        assert_eq!(
            (code, reply_body),
            (0_i32, (Vec::new(), (0x2000_u64, 2049_u32)))
        );
        Ok(())
    }

    /// Replies round-trip; error replies and malformed shapes are refused.
    #[test]
    fn reply_checks() -> Result<(), Platform> {
        // Given a reply with a return value and an in-band body.
        let answer = reply(9, -5, &[1, 2, 3], 0)?;
        // When it and corrupted copies are decoded.
        let decoded = decode_reply(&delivered(&answer))?;
        // Then the checks of `__MIG_check__Reply__call_t` apply.
        assert_eq!(decoded, (-5_i32, (vec![1_u8, 2, 3], (0_u64, 0_u32))));
        assert_eq!(answer.len(), 68);
        let error = |status: i32| {
            [
                &[0_u8, 0, 0, 0, 36, 0, 0, 0][..],
                &[0_u8; 12],
                &[101_u8, 0, 0, 0],
                &NDR,
                &status.to_le_bytes(),
            ]
            .concat()
        };
        assert_eq!(
            decode_reply(&error(-301_i32)),
            Err(Platform::MachRpc { code: -301_i32 })
        );
        assert!(
            decode_reply(&error(0_i32)).is_err(),
            "success in a simple reply"
        );
        for (offset, value) in [
            (20_usize, 102_u8),
            (56, 200),
            (4, 72),
            (24, 2),
            (39, 2),
            (64, 1),
        ] {
            let mut bad = delivered(&answer);
            if let Some(byte) = bad.get_mut(offset) {
                *byte = value;
            }
            assert!(decode_reply(&bad).is_err(), "offset {offset}");
        }
        assert!(
            decode_reply(delivered(&answer).get(..40).unwrap_or_default()).is_err(),
            "truncated"
        );
        assert!(decode_reply(&answer).is_err(), "a reply right in a reply");
        Ok(())
    }
}
