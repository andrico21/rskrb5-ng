//! Frame codec of the external-peer adapter protocol.
//!
//! The protocol is documented in the comment block at the top of
//! `scripts/interop/peer-mit/peer/peer.c`; this module mirrors it: a frame is a
//! big-endian `u32` length (1 to 1 MiB) and that many payload bytes; a request
//! payload is one command byte followed by fields, a reply payload one status
//! byte followed by fields; a field is a big-endian `u32` length and its bytes.

use core::time::Duration;
use std::{
    io::{self, Read},
    net::{TcpStream, ToSocketAddrs as _},
};

use super::{Peer, types::PeerError};

/// Largest frame payload either side accepts: 1 MiB.
pub(crate) const MAX_FRAME: usize = 0x10_0000;

/// Most fields of one request.
pub(crate) const MAX_FIELDS: usize = 16;

/// Reply status: success.
pub(crate) const STATUS_OK: u8 = 0;

/// Reply status: `GSS_S_CONTINUE_NEEDED`.
pub(crate) const STATUS_CONTINUE: u8 = 1;

/// Reply status: a GSS error (major, minor, text).
pub(crate) const STATUS_GSS_ERROR: u8 = 2;

/// Reply status: a protocol error (text).
pub(crate) const STATUS_PROTOCOL: u8 = 3;

/// The fields of one reply, consumed front to back.
#[derive(Debug)]
pub(crate) struct Fields {
    /// The fields not yet taken, last field first.
    items: Vec<Vec<u8>>,
}

impl Fields {
    /// Splits the bytes after the status byte into fields.
    ///
    /// # Errors
    ///
    /// Returns [`PeerError::Malformed`] when a length runs past the end.
    pub(crate) fn split(mut rest: &[u8]) -> Result<Self, PeerError> {
        let mut items = Vec::new();
        while !rest.is_empty() {
            let (head, tail) = rest
                .split_at_checked(4)
                .ok_or(PeerError::Malformed("a field length is cut off"))?;
            let length =
                usize::try_from(u32::from_be_bytes(head.try_into().map_err(|_cause| {
                    PeerError::Malformed("a field length is not four bytes")
                })?))
                .map_err(|_cause| {
                    PeerError::Malformed("a field length exceeds the address space")
                })?;
            let (field, after) = tail
                .split_at_checked(length)
                .ok_or(PeerError::Malformed("a field runs past the frame"))?;
            items.push(field.to_vec());
            rest = after;
        }
        items.reverse();
        Ok(Self { items })
    }

    /// Takes the next field.
    ///
    /// # Errors
    ///
    /// Returns [`PeerError::Malformed`] when no field is left.
    pub(crate) fn bytes(&mut self) -> Result<Vec<u8>, PeerError> {
        self.items.pop().ok_or(PeerError::Malformed(
            "the reply has fewer fields than documented",
        ))
    }

    /// Takes the next field as UTF-8 text.
    ///
    /// # Errors
    ///
    /// Returns [`PeerError::Malformed`] when no field is left or it is not UTF-8.
    pub(crate) fn text(&mut self) -> Result<String, PeerError> {
        String::from_utf8(self.bytes()?)
            .map_err(|_cause| PeerError::Malformed("a text field is not UTF-8"))
    }

    /// Takes the next field as a big-endian `u32`.
    ///
    /// # Errors
    ///
    /// Returns [`PeerError::Malformed`] when no field is left or it is not four bytes.
    pub(crate) fn number(&mut self) -> Result<u32, PeerError> {
        let bytes = self.bytes()?;
        Ok(u32::from_be_bytes(bytes.as_slice().try_into().map_err(
            |_cause| PeerError::Malformed("a number field is not four bytes"),
        )?))
    }

    /// Takes the next field as a one-byte flag.
    ///
    /// # Errors
    ///
    /// Returns [`PeerError::Malformed`] when no field is left or it is not `0` or `1`.
    pub(crate) fn flag(&mut self) -> Result<bool, PeerError> {
        match self.bytes()?.as_slice() {
            [0] => Ok(false),
            [1] => Ok(true),
            _ => Err(PeerError::Malformed("a flag field is not 0 or 1")),
        }
    }

    /// How many fields are left.
    pub(crate) const fn remaining(&self) -> usize {
        self.items.len()
    }

    /// Checks that every field was taken.
    ///
    /// # Errors
    ///
    /// Returns [`PeerError::Malformed`] when a field is left over.
    pub(crate) fn finish(mut self) -> Result<(), PeerError> {
        self.items.pop().map_or(Ok(()), |_extra| {
            Err(PeerError::Malformed(
                "the reply has more fields than documented",
            ))
        })
    }
}

/// Encodes a request frame: length, command byte, fields.
///
/// # Errors
///
/// Returns [`PeerError::Limit`] when there are more than 16 fields or the
/// payload exceeds 1 MiB (the adapter would refuse it).
pub(crate) fn encode_request(command: u8, fields: &[&[u8]]) -> Result<Vec<u8>, PeerError> {
    if fields.len() > MAX_FIELDS {
        return Err(PeerError::Limit("more than 16 fields"));
    }
    let mut payload = vec![command];
    for field in fields {
        let length = u32::try_from(field.len())
            .map_err(|_cause| PeerError::Limit("a field exceeds 4 GiB"))?;
        payload.extend_from_slice(&length.to_be_bytes());
        payload.extend_from_slice(field);
    }
    if payload.len() > MAX_FRAME {
        return Err(PeerError::Limit("the payload exceeds 1 MiB"));
    }
    let length = u32::try_from(payload.len())
        .map_err(|_cause| PeerError::Limit("the payload exceeds 4 GiB"))?;
    let mut frame = Vec::with_capacity(payload.len().saturating_add(4));
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

/// Reads one reply frame and returns its status byte and the bytes after it.
///
/// # Errors
///
/// Returns [`PeerError::Io`] when the stream fails or ends early and
/// [`PeerError::Malformed`] when the length is 0 or above 1 MiB.
pub(crate) fn read_reply<R>(stream: &mut R) -> Result<(u8, Vec<u8>), PeerError>
where
    R: Read,
{
    let mut header = [0_u8; 4];
    stream.read_exact(&mut header).map_err(PeerError::Io)?;
    let length = usize::try_from(u32::from_be_bytes(header))
        .map_err(|_cause| PeerError::Malformed("a reply length exceeds the address space"))?;
    if length == 0 || length > MAX_FRAME {
        return Err(PeerError::Malformed(
            "a reply length is outside 1 byte to 1 MiB",
        ));
    }
    let mut payload = vec![0_u8; length];
    stream.read_exact(&mut payload).map_err(PeerError::Io)?;
    let (status, rest) = payload
        .split_first()
        .ok_or(PeerError::Malformed("an empty reply payload"))?;
    Ok((*status, rest.to_vec()))
}

/// Connects to the adapter at `endpoint` (`host:port`) with a ten-second I/O bound.
///
/// # Errors
///
/// Returns [`PeerError::Io`] when no address connects.
pub(crate) fn connect(endpoint: &str) -> Result<Peer<TcpStream>, PeerError> {
    let bound = Duration::from_secs(10);
    let mut last = None;
    for address in endpoint.to_socket_addrs().map_err(PeerError::Io)? {
        match TcpStream::connect_timeout(&address, bound) {
            Ok(stream) => {
                stream
                    .set_read_timeout(Some(bound))
                    .map_err(PeerError::Io)?;
                stream
                    .set_write_timeout(Some(bound))
                    .map_err(PeerError::Io)?;
                return Ok(Peer::new(stream));
            }
            Err(cause) => last = Some(cause),
        }
    }
    Err(PeerError::Io(last.unwrap_or_else(|| {
        io::Error::new(io::ErrorKind::NotFound, "the endpoint has no address")
    })))
}

/// Maps a reply status to `(continue needed, fields)` or to the adapter's error.
///
/// # Errors
///
/// Returns the adapter's [`PeerError::Gss`] or [`PeerError::Protocol`], or
/// [`PeerError::Malformed`] for an unknown status or a cut-off field.
pub(crate) fn map_status(status: u8, rest: &[u8]) -> Result<(bool, Fields), PeerError> {
    match status {
        STATUS_OK => Ok((false, Fields::split(rest)?)),
        STATUS_CONTINUE => Ok((true, Fields::split(rest)?)),
        STATUS_GSS_ERROR => {
            let mut fields = Fields::split(rest)?;
            Err(PeerError::Gss {
                major: fields.number()?,
                minor: fields.number()?,
                text: fields.text()?,
            })
        }
        STATUS_PROTOCOL => Err(PeerError::Protocol(Fields::split(rest)?.text()?)),
        _ => Err(PeerError::Malformed("an unknown status byte")),
    }
}

/// Borrows owned request fields as slices.
pub(crate) fn borrowed(fields: &[Vec<u8>]) -> Vec<&[u8]> {
    fields.iter().map(Vec::as_slice).collect()
}
