//! The HTTP/1.1 POST of one KDC-PROXY-MESSAGE over an established TLS stream.
//!
//! The request is `POST /<path> HTTP/1.1` with `Host`, `Content-Type:
//! application/kerberos`, `Content-Length`, `Cache-Control: no-cache`, `Pragma:
//! no-cache` and `Connection: close`, the headers of MIT's `make_proxy_request`
//! (`sendto_kdc.c:633-641`) on HTTP/1.1. Only a `200` response is accepted, and its
//! body is read frame by frame up to the request's `max_response`.

use core::{
    convert::Infallible,
    error::Error as StdError,
    future::poll_fn,
    pin::Pin,
    task::{Context, Poll},
};
use std::io;

use hyper::{
    Method, StatusCode,
    body::{Body, Bytes, Frame, Incoming, SizeHint},
    client::conn::http1,
    header::{self, HeaderValue},
    rt::{Read, ReadBufCursor, Write},
};
use tokio::{
    io::{AsyncRead as _, AsyncWrite as _, ReadBuf},
    net::TcpStream,
};
use tokio_rustls::client::TlsStream;

use crate::{error::KdcProxy as Error, transport::proxy::Request};

/// The bytes read from the TLS stream per poll.
const READ_CHUNK: usize = 8192;

/// The TLS stream seen through hyper's I/O traits, without `unsafe`: a read goes
/// through an initialised stack buffer and is copied into hyper's cursor.
pub(super) struct Io(TlsStream<TcpStream>);

impl Io {
    /// The TLS stream `tls` as hyper I/O.
    pub(super) const fn new(tls: TlsStream<TcpStream>) -> Self {
        Self(tls)
    }
}

impl Read for Io {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut buf: ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        let mut scratch = [0_u8; READ_CHUNK];
        let room = buf.remaining().min(READ_CHUNK);
        let mut read = ReadBuf::new(scratch.get_mut(..room).unwrap_or_default());
        match Pin::new(&mut self.get_mut().0).poll_read(cx, &mut read) {
            Poll::Ready(Ok(())) => {
                buf.put_slice(read.filled());
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Write for Io {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
    }
}

/// The request body: the KDC-PROXY-MESSAGE as one frame.
pub(super) struct Payload(Option<Bytes>);

impl Payload {
    /// A body of the one frame `bytes`.
    pub(super) const fn new(bytes: Bytes) -> Self {
        Self(Some(bytes))
    }
}

impl Body for Payload {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        Poll::Ready(self.get_mut().0.take().map(|bytes| Ok(Frame::data(bytes))))
    }

    fn is_end_stream(&self) -> bool {
        self.0.is_none()
    }

    fn size_hint(&self) -> SizeHint {
        self.0.as_ref().map_or_else(SizeHint::default, |bytes| {
            SizeHint::with_exact(u64::try_from(bytes.len()).unwrap_or(u64::MAX))
        })
    }
}

/// A failure after the request may have reached the proxy.
fn maybe<E>(error: E) -> Error
where
    E: StdError + Send + Sync + 'static,
{
    Error::MaybeDelivered(Box::new(error))
}

/// The body of `response`, refused above `limit` bytes.
///
/// # Errors
///
/// Returns [`Error::Status`] for a status other than `200`, [`Error::TooLarge`]
/// above `limit`, and [`Error::MaybeDelivered`] when the body fails.
///
/// # Cancel safety
///
/// Dropping the future discards the bytes read so far.
async fn body(response: hyper::Response<Incoming>, limit: usize) -> Result<Vec<u8>, Error> {
    if response.status() != StatusCode::OK {
        return Err(Error::Status {
            status: response.status().as_u16(),
        });
    }
    let mut incoming = Box::pin(response.into_body());
    let mut collected = Vec::new();
    while let Some(frame) = poll_fn(|context| incoming.as_mut().poll_frame(context)).await {
        let Ok(data) = frame.map_err(maybe)?.into_data() else {
            continue;
        };
        let total = collected.len().saturating_add(data.len());
        if total > limit {
            return Err(Error::TooLarge {
                actual: total,
                limit,
            });
        }
        collected.extend_from_slice(&data);
    }
    Ok(collected)
}

/// POST `request` over `tls` and return the body of its `200` response.
///
/// # Errors
///
/// Returns [`Error::NotDelivered`] when the HTTP connection cannot be set up,
/// [`Error::InvalidUrl`] when the request line or `Host` header cannot be built,
/// and the errors of `body`; every other failure is [`Error::MaybeDelivered`].
///
/// # Cancel safety
///
/// Dropping the future closes the connection; the request may have been delivered.
pub(super) async fn post(
    tls: TlsStream<TcpStream>,
    request: &Request<'_>,
) -> Result<Vec<u8>, Error> {
    let host =
        HeaderValue::from_str(&request.url.authority()).map_err(|_header| Error::InvalidUrl {
            reason: "the host is not a valid Host header",
        })?;
    let message = hyper::Request::builder()
        .method(Method::POST)
        .uri(format!("/{}", request.url.path()))
        .header(header::HOST, host)
        .header(header::CONTENT_TYPE, "application/kerberos")
        .header(header::CACHE_CONTROL, "no-cache")
        .header(header::PRAGMA, "no-cache")
        .header(header::CONNECTION, "close")
        .body(Payload(Some(Bytes::copy_from_slice(request.body))))
        .map_err(|_request| Error::InvalidUrl {
            reason: "the path is not a valid request target",
        })?;
    let (mut sender, connection) = http1::handshake(Io(tls))
        .await
        .map_err(|error| Error::NotDelivered(Box::new(error)))?;
    let limit = request.max_response;
    let mut exchange = Box::pin(async move {
        let response = sender.send_request(message).await.map_err(maybe)?;
        body(response, limit).await
    });
    let mut driver = Box::pin(connection);
    let mut closed = false;
    poll_fn(|cx| {
        if let Poll::Ready(result) = exchange.as_mut().poll(cx) {
            return Poll::Ready(result);
        }
        if !closed && let Poll::Ready(result) = driver.as_mut().poll(cx) {
            closed = true;
            if let Err(error) = result {
                return Poll::Ready(Err(maybe(error)));
            }
        }
        Poll::Pending
    })
    .await
}
