//! The blocking KCM client: framing over any [`Read`] and [`Write`] stream
//! (`kcmio_call`, `cc_kcm.c:451-480`).
//!
//! # Security
//!
//! The reply length is checked against the limit before any byte of the body
//! is read or allocated. After any failure that can leave the stream out of
//! step with the daemon (a failed or partial write, a failed or oversized
//! read) the client refuses further calls: it never pairs a later request
//! with a stale reply.
//!
//! # Cancel safety
//!
//! Every call is synchronous.

use std::io::{Read, Write};

use zeroize::Zeroizing;

use super::wire::{self, MAX_REPLY_SIZE, Opcode, Reply, calls::Call, shape::Shape};
use crate::error::{Kcm as Error, KcmStage};

/// A KCM connection over one stream.
#[derive(Debug)]
pub struct Client<S> {
    /// The daemon connection.
    stream: S,
    /// The largest reply body accepted.
    limit: usize,
    /// Whether the stream may be out of step with the daemon.
    broken: bool,
}

impl<S: Read + Write> Client<S> {
    /// A client over `stream`, accepting replies up to [`MAX_REPLY_SIZE`].
    #[must_use]
    #[inline]
    pub const fn new(stream: S) -> Self {
        Self {
            stream,
            limit: MAX_REPLY_SIZE,
            broken: false,
        }
    }

    /// Accept replies of at most `limit` bytes; a larger value than
    /// [`MAX_REPLY_SIZE`] is lowered to it.
    #[must_use]
    #[inline]
    pub const fn with_reply_limit(mut self, limit: usize) -> Self {
        self.limit = if limit < MAX_REPLY_SIZE {
            limit
        } else {
            MAX_REPLY_SIZE
        };
        self
    }

    /// The stream, for arming timeouts.
    #[inline]
    pub const fn stream_mut(&mut self) -> &mut S {
        &mut self.stream
    }

    /// Whether an earlier failure made the stream unusable.
    #[must_use]
    #[inline]
    pub const fn is_broken(&self) -> bool {
        self.broken
    }

    /// Send the request of `call` and decode the reply.
    ///
    /// # Errors
    ///
    /// [`Error::Broken`] after an earlier failure, [`Error::RequestTooBig`],
    /// [`Error::Io`] for a failed write or read, [`Error::ReplyTooBig`] for a
    /// reply over the limit, [`Error::Daemon`] for a nonzero status,
    /// [`Error::MalformedReply`] for a reply that does not parse, and
    /// [`Error::OutcomeUnknown`] when a mutating request was sent and its
    /// reply was lost or refused.
    #[inline]
    pub fn call<R>(&mut self, call: &Call<R>) -> Result<R::Output, Error>
    where
        R: Shape,
    {
        if self.broken {
            return Err(Error::Broken);
        }
        let request = call.request();
        let opcode = request.opcode();
        let frame = request.frame()?;
        self.broken = true;
        self.stream
            .write_all(&frame)
            .and_then(|()| self.stream.flush())
            .map_err(|source| Error::Io {
                stage: KcmStage::Write,
                source,
            })?;
        let (code, body) = self.read_frame().map_err(|error| lost(opcode, error))?;
        self.broken = false;
        R::decode(&Reply::from_frame(opcode, code, body)?)
    }

    /// Read one reply frame: its transport status code and body.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] and [`Error::ReplyTooBig`].
    fn read_frame(&mut self) -> Result<(i32, Zeroizing<Vec<u8>>), Error> {
        let mut header = [0_u8; 4];
        self.read_exact(&mut header)?;
        let length = wire::reply_length(header, self.limit)?;
        let mut code = [0_u8; 4];
        self.read_exact(&mut code)?;
        let mut body = Zeroizing::new(vec![0_u8; length]);
        self.read_exact(&mut body)?;
        Ok((i32::from_be_bytes(code), body))
    }

    /// Fill `buffer` from the stream.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] for a failed or short read.
    fn read_exact(&mut self, buffer: &mut [u8]) -> Result<(), Error> {
        self.stream.read_exact(buffer).map_err(|source| Error::Io {
            stage: KcmStage::Read,
            source,
        })
    }
}

/// A read failure of a request that may have changed the daemon's state is an
/// unknown outcome.
pub(super) fn lost(opcode: Opcode, error: Error) -> Error {
    if opcode.mutates() {
        Error::OutcomeUnknown {
            opcode: opcode.code(),
            cause: Box::new(error),
        }
    } else {
        error
    }
}
