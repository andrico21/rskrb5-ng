//! The built-in HTTPS [`HttpExchange`] of the `kkdcp-rustls` leaf.
//!
//! The same TLS stack as the KDC proxy transport (rustls with the pure-Rust
//! `RustCrypto` provider, TLS 1.3 or 1.2, hyper's HTTP/1.1 client) sends one
//! request per connection and returns the response whole, whatever its status.
//! [`HttpExchange::connect`] completes the handshake first and reports the
//! verified end-entity certificate as the connection's [`TlsChannel`], so a
//! Negotiate token can be bound to the connection that carries it.
//!
//! # Security
//!
//! `https` only: a cleartext URI is [`Error::UnsupportedScheme`]. There is no
//! certificate bypass and no implicit trust store: the transport trusts only the
//! roots the application configured with `with_pem_roots`, and with none the
//! request fails with [`Error::NoAnchors`] before any connection. A redirect is
//! a response, never followed. The body is bounded to 8 MiB while it is read.
//! A failure before the TLS handshake completed is `NotDelivered`, a later one
//! `MaybeDelivered`. A prepared connection carries one request, to the origin
//! it was opened for, and refuses any other.
//!
//! # Cancel safety
//!
//! Dropping the future closes the connection; the request may have been delivered.

use alloc::sync::Arc;
use core::{error::Error as StdError, future::poll_fn, pin::Pin, task::Poll};

use http_types::{
    Request, Response, Uri,
    header::{CONNECTION, HOST, HeaderValue},
    uri::PathAndQuery,
};
use hyper::{
    body::{Body as _, Bytes, Incoming},
    client::conn::http1,
};
use rustls::{
    ClientConfig, RootCertStore,
    pki_types::ServerName,
    version::{TLS12, TLS13},
};
use tokio::net::TcpStream;
use tokio_rustls::{TlsConnector, client::TlsStream};

use super::{
    RustlsTransport,
    exchange::{Io, Payload},
};
use crate::{
    error::HttpExchange as Error,
    http::{
        origin::Origin,
        wire::{ConnectFuture, ExchangeFuture, HttpExchange, PreparedConnection, TlsChannel},
    },
};

/// The longest response body, in bytes.
const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

impl HttpExchange for RustlsTransport {
    #[inline]
    fn exchange(&self, request: Request<Vec<u8>>) -> ExchangeFuture<'_> {
        Box::pin(async move {
            connect(self, request.uri().clone())
                .await?
                .send(request)
                .await
        })
    }

    #[inline]
    fn connect(&self, uri: &Uri) -> ConnectFuture<'_> {
        Box::pin(connect(self, uri.clone()))
    }
}

/// A failure after the request may have reached the server.
fn maybe<E>(error: E) -> Error
where
    E: StdError + Send + Sync + 'static,
{
    Error::MaybeDelivered(Box::new(error))
}

/// A failure before any byte of the request could have reached the server.
fn not_delivered<E>(error: E) -> Error
where
    E: StdError + Send + Sync + 'static,
{
    Error::NotDelivered(Box::new(error))
}

/// The TLS client configuration: the provider, TLS 1.3 and 1.2, the configured
/// roots and no client certificate.
///
/// # Errors
///
/// Returns [`Error::NoAnchors`] with no root, [`Error::Anchor`] for a root that
/// does not load and [`Error::NotDelivered`] when the provider supports no
/// protocol version.
fn config(transport: &RustlsTransport) -> Result<ClientConfig, Error> {
    if transport.roots.is_empty() {
        return Err(Error::NoAnchors);
    }
    let mut roots = RootCertStore::empty();
    for root in &transport.roots {
        roots.add(root.clone()).map_err(|_refused| Error::Anchor {
            reason: "a configured root does not load",
        })?;
    }
    Ok(
        ClientConfig::builder_with_provider(Arc::new(rustls_rustcrypto::provider()))
            .with_protocol_versions(&[&TLS13, &TLS12])
            .map_err(not_delivered)?
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

/// The response of `response` with its body read up to the limit.
///
/// # Errors
///
/// Returns [`Error::TooLarge`] past 8 MiB and [`Error::MaybeDelivered`] when the
/// body fails.
///
/// # Cancel safety
///
/// Dropping the future discards the bytes read so far.
async fn collect(response: Response<Incoming>) -> Result<Response<Vec<u8>>, Error> {
    let (parts, stream) = response.into_parts();
    let mut incoming = Box::pin(stream);
    let mut body = Vec::new();
    while let Some(frame) = poll_fn(|context| incoming.as_mut().poll_frame(context)).await {
        let Ok(data) = frame.map_err(maybe)?.into_data() else {
            continue;
        };
        if body.len().saturating_add(data.len()) > MAX_RESPONSE_BYTES {
            return Err(Error::TooLarge {
                limit: MAX_RESPONSE_BYTES,
            });
        }
        body.extend_from_slice(&data);
    }
    Ok(Response::from_parts(parts, body))
}

/// Connect to the origin of `uri`, complete and verify the TLS handshake and
/// prepare the connection for one request to that origin.
///
/// # Errors
///
/// Returns the errors of [`config`], [`Error::UnsupportedScheme`] and
/// [`Error::InvalidRequest`] for a URI this exchange refuses,
/// [`Error::NotDelivered`] when the connection or the TLS handshake fails and
/// [`Error::PeerCertificate`] for a peer certificate a [`TlsChannel`] refuses.
///
/// # Cancel safety
///
/// Dropping the future closes the connection; nothing was sent.
async fn connect(transport: &RustlsTransport, uri: Uri) -> Result<PreparedConnection<'_>, Error> {
    match uri.scheme_str() {
        Some(scheme) if scheme.eq_ignore_ascii_case("https") => {}
        Some(scheme) => {
            return Err(Error::UnsupportedScheme {
                scheme: scheme.to_owned(),
            });
        }
        None => {
            return Err(Error::InvalidRequest {
                reason: "the URI is not absolute",
            });
        }
    }
    let config = config(transport)?;
    let origin = Origin::of(&uri).map_err(|_refused| Error::InvalidRequest {
        reason: "the URI has no usable origin",
    })?;
    let authority = uri.authority().ok_or(Error::InvalidRequest {
        reason: "the URI has no authority",
    })?;
    let host = authority.host().trim_matches(['[', ']']).to_owned();
    let port = authority.port_u16().unwrap_or(443);
    let name = ServerName::try_from(host.clone()).map_err(|_refused| Error::InvalidRequest {
        reason: "the host is not a TLS server name",
    })?;
    let host_header =
        HeaderValue::from_str(authority.as_str()).map_err(|_refused| Error::InvalidRequest {
            reason: "the authority is not a valid Host header",
        })?;
    let tcp = TcpStream::connect((host.as_str(), port))
        .await
        .map_err(not_delivered)?;
    let tls = TlsConnector::from(Arc::new(config))
        .connect(name, tcp)
        .await
        .map_err(not_delivered)?;
    let certificate = tls
        .get_ref()
        .1
        .peer_certificates()
        .and_then(<[_]>::first)
        .ok_or(Error::PeerCertificate {
            reason: "the TLS peer presented no certificate",
        })?;
    let channel = TlsChannel::from_end_entity(certificate.to_vec())?;
    Ok(PreparedConnection::new(Some(channel), move |request| {
        Box::pin(send(tls, origin, host_header, request))
    }))
}

/// Send `request` over the verified connection `tls` to `origin` and read the
/// response.
///
/// # Errors
///
/// Returns [`Error::InvalidRequest`] for a request to another origin or with
/// an unusable target, [`Error::NotDelivered`] when the HTTP handshake fails
/// and the errors of [`collect`].
///
/// # Cancel safety
///
/// Dropping the future closes the connection; the request may have been delivered.
async fn send(
    tls: TlsStream<TcpStream>,
    origin: Origin,
    host_header: HeaderValue,
    request: Request<Vec<u8>>,
) -> Result<Response<Vec<u8>>, Error> {
    if Origin::of(request.uri()).ok() != Some(origin) {
        return Err(Error::InvalidRequest {
            reason: "the request is not for the origin of its connection",
        });
    }
    let target = request
        .uri()
        .path_and_query()
        .map_or("/", PathAndQuery::as_str)
        .parse()
        .map_err(|_refused| Error::InvalidRequest {
            reason: "the path is not a valid request target",
        })?;
    let (parts, body) = request.into_parts();
    let mut message = Request::new(Payload::new(Bytes::from(body)));
    *message.method_mut() = parts.method;
    *message.uri_mut() = target;
    *message.headers_mut() = parts.headers;
    let _host = message.headers_mut().entry(HOST).or_insert(host_header);
    drop(
        message
            .headers_mut()
            .insert(CONNECTION, HeaderValue::from_static("close")),
    );
    let (mut sender, connection) = http1::handshake(Io::new(tls))
        .await
        .map_err(not_delivered)?;
    let mut exchange = Box::pin(async move {
        let response = sender.send_request(message).await.map_err(maybe)?;
        collect(response).await
    });
    let mut driver = Box::pin(connection);
    let mut closed = false;
    poll_fn(|cx| {
        if let Poll::Ready(result) = exchange.as_mut().poll(cx) {
            return Poll::Ready(result);
        }
        if !closed && let Poll::Ready(result) = Pin::new(&mut driver).poll(cx) {
            closed = true;
            if let Err(error) = result {
                return Poll::Ready(Err(maybe(error)));
            }
        }
        Poll::Pending
    })
    .await
}
