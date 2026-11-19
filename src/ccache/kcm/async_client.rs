//! The Tokio KCM client: framing over any [`AsyncRead`] and [`AsyncWrite`]
//! stream, and a connection to the daemon socket that also checks the peer's
//! user id.
//!
//! # Security
//!
//! As for the blocking [`client`](super::client): the reply length is checked
//! before any byte of the body is read or allocated, and the client refuses
//! further calls after any failure that can leave the stream out of step. The
//! peer's user id comes from the operating system (`SO_PEERCRED` or the
//! platform's equivalent) after connecting.
//!
//! # Cancel safety
//!
//! [`Client::call`] is cancel safe in the sense that matters: a call dropped
//! before it finishes leaves the client refusing further calls
//! ([`Error::Broken`]), so a late reply is never paired with a later request.

use core::time::Duration;
use std::{io, path::Path};

use tokio::{
    io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _},
    net::UnixStream,
    time,
};
use zeroize::Zeroizing;

use super::{
    client::{READ, WRITE, lost},
    socket::{self, CONNECT, Trust},
    wire::{self, MAX_REPLY_SIZE, Reply, calls::Call, shape::Shape},
};
use crate::error::{Kcm as Error, KcmRefusal};

/// A KCM connection over one Tokio stream.
#[derive(Debug)]
pub struct Client<S> {
    /// The daemon connection.
    stream: S,
    /// The largest reply body accepted.
    limit: usize,
    /// How long one call may take, if bounded.
    timeout: Option<Duration>,
    /// Whether the stream may be out of step with the daemon.
    broken: bool,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Client<S> {
    /// A client over `stream`, accepting replies up to [`MAX_REPLY_SIZE`],
    /// with no time limit.
    #[must_use]
    #[inline]
    pub const fn new(stream: S) -> Self {
        Self {
            stream,
            limit: MAX_REPLY_SIZE,
            timeout: None,
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

    /// Bound every call, from the first byte sent to the last byte received,
    /// by `timeout`.
    #[must_use]
    #[inline]
    pub const fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Whether an earlier failure or cancelled call made the stream unusable.
    #[must_use]
    #[inline]
    pub const fn is_broken(&self) -> bool {
        self.broken
    }

    /// Send the request of `call` and decode the reply.
    ///
    /// # Errors
    ///
    /// The errors of [`KcmClient::call`](super::client::Client::call); a call
    /// that outlives the time limit fails with a timed-out [`Error::Io`].
    ///
    /// # Cancel safety
    ///
    /// Dropping the future leaves the client refusing further calls
    /// ([`Error::Broken`]); no later request is paired with a stale reply.
    #[inline]
    pub async fn call<R>(&mut self, call: &Call<R>) -> Result<R::Output, Error>
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
        let exchange = exchange(&mut self.stream, &frame, self.limit);
        let outcome = match self.timeout {
            Some(limit) => time::timeout(limit, exchange)
                .await
                .unwrap_or_else(|_elapsed| {
                    Err(Error::Io {
                        stage: READ,
                        source: io::ErrorKind::TimedOut.into(),
                    })
                }),
            None => exchange.await,
        };
        let (code, body) = outcome.map_err(|error| lost(opcode, error))?;
        self.broken = false;
        R::decode(&Reply::from_frame(opcode, code, body)?)
    }
}

/// Send a frame and read one reply frame: its transport status code and body.
///
/// # Errors
///
/// [`Error::Io`] and [`Error::ReplyTooBig`].
///
/// # Cancel safety
///
/// Not cancel safe by itself: a dropped future leaves a partly written request
/// or a partly read reply on the stream, which is why [`Client::call`] marks
/// the client broken before it starts.
async fn exchange<S>(
    stream: &mut S,
    frame: &[u8],
    limit: usize,
) -> Result<(i32, Zeroizing<Vec<u8>>), Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let io_error = |stage| move |source| Error::Io { stage, source };
    stream.write_all(frame).await.map_err(io_error(WRITE))?;
    stream.flush().await.map_err(io_error(WRITE))?;
    let mut header = [0_u8; 4];
    fill(stream, &mut header).await?;
    let length = wire::reply_length(header, limit)?;
    let mut code = [0_u8; 4];
    fill(stream, &mut code).await?;
    let mut body = Zeroizing::new(vec![0_u8; length]);
    fill(stream, &mut body).await?;
    Ok((i32::from_be_bytes(code), body))
}

impl Client<UnixStream> {
    /// Connect to the daemon at `path`: the socket must pass the trust check
    /// of [`socket`] and the connected peer must run as a
    /// trusted user.
    ///
    /// # Errors
    ///
    /// [`Error::NoServer`], [`Error::Untrusted`] and [`Error::Io`].
    ///
    /// # Cancel safety
    ///
    /// Cancel safe: a dropped future leaves no connection behind.
    #[inline]
    pub async fn connect(path: &Path, trust: &Trust) -> Result<Self, Error> {
        socket::validate(path, trust)?;
        let stream = UnixStream::connect(path)
            .await
            .map_err(socket::connect_error)?;
        let peer = stream.peer_cred().map_err(|source| Error::Io {
            stage: CONNECT,
            source,
        })?;
        socket::judge(
            trust,
            peer.uid(),
            KcmRefusal::UntrustedPeer { uid: peer.uid() },
        )?;
        Ok(Self::new(stream))
    }
}

/// Fill `buffer` from the stream.
///
/// # Errors
///
/// [`Error::Io`] for a failed or short read.
///
/// # Cancel safety
///
/// Not cancel safe by itself (a dropped future leaves a partly read reply);
/// see [`exchange`].
async fn fill<S>(stream: &mut S, buffer: &mut [u8]) -> Result<(), Error>
where
    S: AsyncRead + Unpin,
{
    stream
        .read_exact(buffer)
        .await
        .map(|_read| ())
        .map_err(|source| Error::Io {
            stage: READ,
            source,
        })
}
