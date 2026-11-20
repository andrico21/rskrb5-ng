//! Reply payload decoders (`cc_kcm.c:495-612`).
//!
//! Every decoder consumes the whole payload: a daemon that appends bytes is
//! malformed, where MIT ignores them (executor decision: security beats
//! leniency).

use core::str;

use super::{Reply, Residual, UUID_LENGTH, Uuid};
use crate::{
    ccache::{Credential, Endian, Principal},
    error::Kcm as Error,
};

/// The version of the principal and credential encodings in KCM payloads.
const FILE_VERSION: u8 = 4;

/// A malformed-reply error for `reply`.
const fn malformed(reply: &Reply, what: &'static str) -> Error {
    Error::MalformedReply {
        opcode: reply.opcode().code(),
        what,
    }
}

/// A bounds-checked reader over a payload.
struct Reader<'payload> {
    /// The unread bytes.
    rest: &'payload [u8],
}

impl<'payload> Reader<'payload> {
    /// The next `count` bytes, if the payload holds them.
    fn take(&mut self, count: usize) -> Option<&'payload [u8]> {
        let (head, tail) = self.rest.split_at_checked(count)?;
        self.rest = tail;
        Some(head)
    }

    /// The next big-endian 32-bit integer.
    fn u32(&mut self) -> Option<u32> {
        let bytes = self.take(4)?;
        <[u8; 4]>::try_from(bytes).ok().map(u32::from_be_bytes)
    }
}

/// A zero-terminated cache name (`kcmreq_get_name`, `cc_kcm.c:495-509`).
///
/// # Errors
///
/// [`Error::MalformedReply`] for a payload that is not the expected shape.
pub(super) fn name(reply: &Reply) -> Result<Residual, Error> {
    let raw = reply
        .payload()
        .strip_suffix(&[0])
        .ok_or_else(|| malformed(reply, "name is not zero-terminated"))?;
    let text = str::from_utf8(raw).map_err(|_utf8| malformed(reply, "name is not UTF-8"))?;
    Residual::new(text).ok_or_else(|| malformed(reply, "name holds a NUL byte or is too long"))
}

/// A UUID list, which is not delimited and so fills the payload
/// (`kcmreq_get_uuid_list`, `cc_kcm.c:512-541`).
///
/// # Errors
///
/// [`Error::MalformedReply`] for a payload that is not the expected shape.
pub(super) fn uuids(reply: &Reply) -> Result<Vec<Uuid>, Error> {
    let (chunks, rest) = reply.payload().as_chunks::<UUID_LENGTH>();
    if !rest.is_empty() {
        return Err(malformed(reply, "UUID list is not a multiple of 16 bytes"));
    }
    Ok(chunks.iter().map(|chunk| Uuid::new(*chunk)).collect())
}

/// A principal; an empty payload is no principal (`cc_kcm.c:933-955`).
///
/// # Errors
///
/// [`Error::MalformedReply`] for a payload that is not the expected shape.
pub(super) fn principal(reply: &Reply) -> Result<Option<Principal>, Error> {
    let payload = reply.payload();
    if payload.is_empty() {
        return Ok(None);
    }
    let mut offset = 0_usize;
    let parsed = Principal::parse(payload, &mut offset, FILE_VERSION, Endian::Big)
        .map_err(|_parse| malformed(reply, "principal does not parse"))?;
    if offset == payload.len() {
        Ok(Some(parsed))
    } else {
        Err(malformed(reply, "bytes after the principal"))
    }
}

/// One credential filling `bytes`.
///
/// # Errors
///
/// [`Error::MalformedReply`] for a payload that is not the expected shape.
fn credential_in(reply: &Reply, bytes: &[u8]) -> Result<Credential, Error> {
    let mut offset = 0_usize;
    let parsed = Credential::parse(bytes, &mut offset, FILE_VERSION, Endian::Big)
        .map_err(|_parse| malformed(reply, "credential does not parse"))?;
    if offset == bytes.len() {
        Ok(parsed)
    } else {
        Err(malformed(reply, "bytes after the credential"))
    }
}

/// The credential of a `GET_CRED_BY_UUID` reply.
///
/// # Errors
///
/// [`Error::MalformedReply`] for a payload that is not the expected shape.
pub(super) fn credential(reply: &Reply) -> Result<Credential, Error> {
    credential_in(reply, reply.payload())
}

/// A counted credential list (`kcmreq_get_cred_list`, `cc_kcm.c:569-612`):
/// the count is bounded by the payload (four bytes per entry at least)
/// before anything is reserved.
///
/// # Errors
///
/// [`Error::MalformedReply`] for a payload that is not the expected shape.
pub(super) fn credentials(reply: &Reply) -> Result<Vec<Credential>, Error> {
    let mut reader = Reader {
        rest: reply.payload(),
    };
    let count = reader
        .u32()
        .and_then(|count| usize::try_from(count).ok())
        .filter(|count| count.saturating_mul(4) <= reader.rest.len())
        .ok_or_else(|| malformed(reply, "credential count exceeds the payload"))?;
    let mut credentials = Vec::with_capacity(count);
    for _ in 0..count {
        let bytes = reader
            .u32()
            .and_then(|length| usize::try_from(length).ok())
            .and_then(|length| reader.take(length))
            .ok_or_else(|| malformed(reply, "credential is truncated"))?;
        credentials.push(credential_in(reply, bytes)?);
    }
    if reader.rest.is_empty() {
        Ok(credentials)
    } else {
        Err(malformed(reply, "bytes after the credential list"))
    }
}

/// The KDC time offset of a `GET_KDC_OFFSET` reply; an empty payload is no
/// offset (the daemon keeps none).
///
/// # Errors
///
/// [`Error::MalformedReply`] for a payload that is not the expected shape.
pub(super) fn kdc_offset(reply: &Reply) -> Result<Option<i32>, Error> {
    match reply.payload() {
        [] => Ok(None),
        payload => <[u8; 4]>::try_from(payload)
            .map(|bytes| Some(i32::from_be_bytes(bytes)))
            .map_err(|_length| malformed(reply, "KDC offset is not four bytes")),
    }
}

/// A reply that carries no payload; MIT ignores one, this client rejects it
/// (executor decision: security beats leniency).
///
/// # Errors
///
/// [`Error::MalformedReply`] for a payload.
pub(super) fn unit(reply: &Reply) -> Result<(), Error> {
    if reply.payload().is_empty() {
        Ok(())
    } else {
        Err(malformed(reply, "unexpected payload"))
    }
}
