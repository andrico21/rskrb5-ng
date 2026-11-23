//! ONC RPC record marking over TCP (RFC 5531 section 11).
//!
//! A record is a sequence of fragments, each led by a four-byte word whose
//! high bit marks the last fragment and whose low 31 bits give its length.
//! Reassembly is bounded: a fragment is refused from its header when it would
//! bring the record past [`MAX_RECORD_SIZE`], and a record past
//! [`MAX_FRAGMENTS`] fragments is refused, so no peer can make the reader
//! allocate more than the bound or loop without end.

use zeroize::Zeroizing;

#[cfg(feature = "tokio")]
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};

use super::{DecodedRecord, MAX_FRAGMENTS, MAX_RECORD_SIZE};
use crate::error::Rpc as Error;

/// The last-fragment bit of a fragment header.
const LAST: u32 = 0x8000_0000;

/// A fragment header: whether it is the last and its length, checked against
/// the bytes the record already holds.
///
/// # Errors
///
/// Returns [`Error::RecordTooLarge`] when the record would pass the bound.
fn fragment(header: [u8; 4], held: usize) -> Result<(bool, usize), Error> {
    let word = u32::from_be_bytes(header);
    let length =
        usize::try_from(word & !LAST).map_err(|_overflow| Error::Malformed("fragment length"))?;
    let total = held
        .checked_add(length)
        .filter(|total| *total <= MAX_RECORD_SIZE);
    if total.is_none() {
        let actual = u64::try_from(held)
            .unwrap_or(u64::MAX)
            .saturating_add(u64::from(word & !LAST));
        return Err(Error::RecordTooLarge {
            maximum: MAX_RECORD_SIZE,
            actual,
        });
    }
    Ok((word & LAST != 0, length))
}

/// The largest fragment: 2^31 - 1 bytes.
const MAX_FRAGMENT: usize = 0x7fff_ffff;

/// Frame `message` as one record: one last fragment, or fragments of
/// [`MAX_FRAGMENT`] bytes for a larger message.
pub(super) fn encode(message: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut record = Zeroizing::new(Vec::with_capacity(message.len().saturating_add(4)));
    let mut chunks = message.chunks(MAX_FRAGMENT).peekable();
    if chunks.peek().is_none() {
        record.extend_from_slice(&LAST.to_be_bytes());
    }
    while let Some(chunk) = chunks.next() {
        let length = u32::try_from(chunk.len()).unwrap_or(u32::MAX) & !LAST;
        let header = if chunks.peek().is_none() { length | LAST } else { length };
        record.extend_from_slice(&header.to_be_bytes());
        record.extend_from_slice(chunk);
    }
    record
}

/// Reassemble the record at the start of `bytes`.
///
/// It returns the message and the bytes consumed, or `None` when `bytes`
/// ends before the last fragment does.
///
/// # Errors
///
/// Returns [`Error::RecordTooLarge`] or [`Error::TooManyFragments`] past the bounds.
pub(super) fn decode(bytes: &[u8]) -> Result<Option<DecodedRecord>, Error> {
    let mut message = Zeroizing::new(Vec::new());
    let mut rest = bytes;
    for _ in 0..MAX_FRAGMENTS {
        let Some((header, tail)) = rest.split_first_chunk::<4>() else {
            return Ok(None);
        };
        let (last, length) = fragment(*header, message.len())?;
        let Some((body, after)) = tail.split_at_checked(length) else {
            return Ok(None);
        };
        message.extend_from_slice(body);
        rest = after;
        if last {
            let consumed = bytes.len().saturating_sub(rest.len());
            return Ok(Some((message, consumed)));
        }
    }
    Err(Error::TooManyFragments(MAX_FRAGMENTS))
}

/// Write `message` as one record.
///
/// # Errors
///
/// Returns [`Error::Io`] when the write fails.
#[cfg(feature = "tokio")]
pub(crate) async fn write<W>(writer: &mut W, message: &[u8]) -> Result<(), Error>
where
    W: AsyncWrite + Unpin,
{
    let record = encode(message);
    writer.write_all(&record).await?;
    writer.flush().await?;
    Ok(())
}

/// Read one record, fragment by fragment, within the bounds.
///
/// # Errors
///
/// Returns [`Error::RecordTooLarge`] or [`Error::TooManyFragments`] past the
/// bounds, before the oversized fragment's body is read, and [`Error::Io`]
/// when the read fails or the stream ends inside the record.
#[cfg(feature = "tokio")]
pub(crate) async fn read<R>(reader: &mut R) -> Result<Zeroizing<Vec<u8>>, Error>
where
    R: AsyncRead + Unpin,
{
    let mut message = Zeroizing::new(Vec::new());
    for _ in 0..MAX_FRAGMENTS {
        let mut header = [0_u8; 4];
        let _header_length = reader.read_exact(&mut header).await?;
        let (last, length) = fragment(header, message.len())?;
        let start = message.len();
        message.resize(start.saturating_add(length), 0);
        let body = message
            .get_mut(start..)
            .ok_or(Error::Malformed("fragment"))?;
        let _body_length = reader.read_exact(body).await?;
        if last {
            return Ok(message);
        }
    }
    Err(Error::TooManyFragments(MAX_FRAGMENTS))
}
