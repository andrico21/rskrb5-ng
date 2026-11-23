//! The test's own XDR (RFC 4506) writer and reader.
//!
//! Written from RFC 4506 sections 4.1-4.10 and MIT 1.22.2's
//! `kadm_rpc_xdr.c`, independently of the crate's codec, so the scenarios
//! compare the crate against a second implementation.

use super::context::{Context as _, TestError};

/// An XDR byte writer.
#[derive(Debug, Default)]
pub(super) struct Writer {
    /// The bytes written.
    bytes: Vec<u8>,
}

impl Writer {
    /// An empty writer.
    pub(super) fn new() -> Self {
        Self::default()
    }

    /// An unsigned 32-bit integer (RFC 4506 section 4.2).
    pub(super) fn u32(mut self, value: u32) -> Self {
        self.bytes.extend_from_slice(&value.to_be_bytes());
        self
    }

    /// A signed 32-bit integer (RFC 4506 section 4.1).
    pub(super) fn i32(mut self, value: i32) -> Self {
        self.bytes.extend_from_slice(&value.to_be_bytes());
        self
    }

    /// Variable-length opaque data (RFC 4506 section 4.10): length, bytes,
    /// zero padding to four.
    pub(super) fn opaque(mut self, value: &[u8]) -> Self {
        let length = u32::try_from(value.len()).unwrap_or(u32::MAX);
        self.bytes.extend_from_slice(&length.to_be_bytes());
        self.bytes.extend_from_slice(value);
        let padding = (4 - value.len() % 4) % 4;
        self.bytes.extend(core::iter::repeat_n(0, padding));
        self
    }

    /// MIT's `xdr_nullstring` (`kadm_rpc_xdr.c:36-87`): 0 for no string, else
    /// the bytes with their terminating NUL.
    pub(super) fn nullstring(self, value: Option<&str>) -> Self {
        match value {
            None => self.u32(0),
            Some(text) => {
                let mut bytes = text.as_bytes().to_vec();
                bytes.push(0);
                self.opaque(&bytes)
            }
        }
    }

    /// Raw bytes, already encoded.
    pub(super) fn raw(mut self, value: &[u8]) -> Self {
        self.bytes.extend_from_slice(value);
        self
    }

    /// The bytes.
    pub(super) fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

/// An XDR byte reader.
#[derive(Debug)]
pub(super) struct Reader<'bytes> {
    /// The bytes not read yet.
    rest: &'bytes [u8],
}

impl<'bytes> Reader<'bytes> {
    /// A reader of `bytes`.
    pub(super) const fn new(bytes: &'bytes [u8]) -> Self {
        Self { rest: bytes }
    }

    /// An unsigned 32-bit integer.
    pub(super) fn u32(&mut self) -> Result<u32, TestError> {
        let (head, rest) = self.rest.split_first_chunk::<4>().context("four bytes")?;
        self.rest = rest;
        Ok(u32::from_be_bytes(*head))
    }

    /// A signed 32-bit integer.
    pub(super) fn i32(&mut self) -> Result<i32, TestError> {
        Ok(i32::from_be_bytes(self.u32()?.to_be_bytes()))
    }

    /// Variable-length opaque data.
    pub(super) fn opaque(&mut self) -> Result<&'bytes [u8], TestError> {
        let length = usize::try_from(self.u32()?)?;
        let padded = length
            .checked_add((4 - length % 4) % 4)
            .context("padded length")?;
        let (value, rest) = self.rest.split_at_checked(padded).context("opaque body")?;
        self.rest = rest;
        value.get(..length).context("opaque value")
    }

    /// The bytes not read yet.
    pub(super) const fn rest(&self) -> &'bytes [u8] {
        self.rest
    }
}
