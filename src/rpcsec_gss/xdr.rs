//! A bounded XDR (RFC 4506) encoder and decoder.
//!
//! Only the forms ONC RPC, `RPCSEC_GSS` and kadm5 use: 32-bit integers,
//! booleans, variable-length opaque data and MIT's NUL-terminated
//! `xdr_nullstring` (`kadm_rpc_xdr.c:36-87`). The decoder checks every
//! length against the bytes that remain and against the caller's bound before
//! it allocates, and every count against the bytes its elements need, so no
//! input can make it allocate more than the input's own size. The forms only
//! kadm5 uses are compiled with `tokio`, which the kadm5 module needs.

use core::iter;

use zeroize::Zeroizing;

use crate::error::Rpc as Error;

/// The zero padding after `length` opaque bytes: up to the next multiple of four.
const fn padding(length: usize) -> usize {
    length.wrapping_neg() & 3
}

/// An XDR writer into a zeroizing buffer (arguments may carry passwords and keys).
pub(crate) struct Encoder {
    /// The bytes written.
    bytes: Zeroizing<Vec<u8>>,
}

impl Encoder {
    /// An empty encoder.
    pub(crate) fn new() -> Self {
        Self {
            bytes: Zeroizing::new(Vec::new()),
        }
    }

    /// An unsigned 32-bit integer (RFC 4506 section 4.2).
    #[must_use]
    pub(crate) fn u32(mut self, value: u32) -> Self {
        self.bytes.extend_from_slice(&value.to_be_bytes());
        self
    }

    #[cfg(feature = "tokio")]
    /// A signed 32-bit integer (RFC 4506 section 4.1).
    #[must_use]
    pub(crate) fn i32(mut self, value: i32) -> Self {
        self.bytes.extend_from_slice(&value.to_be_bytes());
        self
    }

    #[cfg(feature = "tokio")]
    /// A boolean (RFC 4506 section 4.4).
    #[must_use]
    pub(crate) fn bool(self, value: bool) -> Self {
        self.u32(u32::from(value))
    }

    /// Bytes already encoded.
    #[must_use]
    pub(crate) fn raw(mut self, value: &[u8]) -> Self {
        self.bytes.extend_from_slice(value);
        self
    }

    /// Variable-length opaque data (RFC 4506 section 4.10) of at most `maximum` bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::TooLarge`] above `maximum`.
    pub(crate) fn opaque(
        mut self,
        field: &'static str,
        value: &[u8],
        maximum: usize,
    ) -> Result<Self, Error> {
        let length = u32::try_from(value.len())
            .ok()
            .filter(|_| value.len() <= maximum)
            .ok_or(Error::TooLarge {
                field,
                maximum,
                actual: value.len(),
            })?;
        self.bytes.extend_from_slice(&length.to_be_bytes());
        self.bytes.extend_from_slice(value);
        self.bytes
            .extend(iter::repeat_n(0_u8, padding(value.len())));
        Ok(self)
    }

    #[cfg(feature = "tokio")]
    /// MIT's `xdr_nullstring`: 0 for no string, else the bytes and a NUL.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Malformed`] for a string holding a NUL, and
    /// [`Error::TooLarge`] above `maximum` bytes.
    pub(crate) fn nullstring(
        self,
        field: &'static str,
        value: Option<&[u8]>,
        maximum: usize,
    ) -> Result<Self, Error> {
        let Some(text) = value else {
            return Ok(self.u32(0));
        };
        if text.contains(&0) {
            return Err(Error::Malformed("a string holds a NUL"));
        }
        let mut terminated = Zeroizing::new(Vec::with_capacity(text.len().saturating_add(1)));
        terminated.extend_from_slice(text);
        terminated.push(0);
        self.opaque(field, &terminated, maximum.saturating_add(1))
    }

    /// The bytes written.
    pub(crate) fn finish(self) -> Zeroizing<Vec<u8>> {
        self.bytes
    }
}

/// An XDR reader over borrowed bytes.
pub(crate) struct Decoder<'bytes> {
    /// The bytes not read yet.
    rest: &'bytes [u8],
}

impl<'bytes> Decoder<'bytes> {
    /// A decoder of `bytes`.
    pub(crate) const fn new(bytes: &'bytes [u8]) -> Self {
        Self { rest: bytes }
    }

    /// The bytes not read yet.
    pub(crate) const fn rest(&self) -> &'bytes [u8] {
        self.rest
    }

    #[cfg(feature = "tokio")]
    /// How many bytes remain.
    pub(crate) const fn remaining(&self) -> usize {
        self.rest.len()
    }

    /// Fail unless every byte was read.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Malformed`] for trailing bytes.
    pub(crate) const fn end(&self) -> Result<(), Error> {
        if self.rest.is_empty() {
            Ok(())
        } else {
            Err(Error::Malformed("trailing bytes"))
        }
    }

    /// `count` bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Malformed`] when the bytes run out.
    fn take(&mut self, count: usize) -> Result<&'bytes [u8], Error> {
        let (head, tail) = self
            .rest
            .split_at_checked(count)
            .ok_or(Error::Malformed("truncated"))?;
        self.rest = tail;
        Ok(head)
    }

    /// An unsigned 32-bit integer.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Malformed`] when fewer than four bytes remain.
    pub(crate) fn u32(&mut self) -> Result<u32, Error> {
        let (head, tail) = self
            .rest
            .split_first_chunk::<4>()
            .ok_or(Error::Malformed("truncated"))?;
        self.rest = tail;
        Ok(u32::from_be_bytes(*head))
    }

    #[cfg(feature = "tokio")]
    /// A signed 32-bit integer.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Malformed`] when fewer than four bytes remain.
    pub(crate) fn i32(&mut self) -> Result<i32, Error> {
        Ok(i32::from_be_bytes(self.u32()?.to_be_bytes()))
    }

    #[cfg(feature = "tokio")]
    /// A boolean: 0 or 1, nothing else (RFC 4506 section 4.4).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Malformed`] for another value.
    pub(crate) fn bool(&mut self) -> Result<bool, Error> {
        match self.u32()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(Error::Malformed("a boolean is neither 0 nor 1")),
        }
    }

    /// Variable-length opaque data of at most `maximum` bytes, borrowed.
    ///
    /// # Errors
    ///
    /// Returns [`Error::TooLarge`] above `maximum`, [`Error::Malformed`] when
    /// the bytes or their padding are missing or the padding is not zero.
    pub(crate) fn opaque(
        &mut self,
        field: &'static str,
        maximum: usize,
    ) -> Result<&'bytes [u8], Error> {
        let length =
            usize::try_from(self.u32()?).map_err(|_overflow| Error::Malformed("length"))?;
        if length > maximum {
            return Err(Error::TooLarge {
                field,
                maximum,
                actual: length,
            });
        }
        let value = self.take(length)?;
        if self.take(padding(length))?.iter().any(|byte| *byte != 0) {
            return Err(Error::Malformed("non-zero XDR padding"));
        }
        Ok(value)
    }

    #[cfg(feature = "tokio")]
    /// MIT's `xdr_nullstring` of at most `maximum` bytes before its NUL.
    ///
    /// `None` for length 0, else bytes that end with their only NUL
    /// (`kadm_rpc_xdr.c:64-69`).
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Self::opaque`] and [`Error::Malformed`] for a
    /// string without its NUL or with another.
    pub(crate) fn nullstring(
        &mut self,
        field: &'static str,
        maximum: usize,
    ) -> Result<Option<&'bytes [u8]>, Error> {
        let bytes = self.opaque(field, maximum.saturating_add(1))?;
        match bytes.split_last() {
            None => Ok(None),
            Some((0, text)) if !text.contains(&0) => Ok(Some(text)),
            Some(_) => Err(Error::Malformed("a string is not NUL-terminated once")),
        }
    }

    #[cfg(feature = "tokio")]
    /// An array count of at most `maximum` elements.
    ///
    /// Each element takes at least `minimum` bytes; the count is checked
    /// against the bytes that remain before any element is read.
    ///
    /// # Errors
    ///
    /// Returns [`Error::TooLarge`] above `maximum` and [`Error::Malformed`]
    /// when the remaining bytes cannot hold that many elements.
    pub(crate) fn count(
        &mut self,
        field: &'static str,
        maximum: usize,
        minimum: usize,
    ) -> Result<usize, Error> {
        let count = usize::try_from(self.u32()?).map_err(|_overflow| Error::Malformed("count"))?;
        if count > maximum {
            return Err(Error::TooLarge {
                field,
                maximum,
                actual: count,
            });
        }
        if count
            .checked_mul(minimum)
            .is_none_or(|needed| needed > self.remaining())
        {
            return Err(Error::Malformed("a count larger than its bytes"));
        }
        Ok(count)
    }
}
