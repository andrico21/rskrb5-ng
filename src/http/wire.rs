//! The HTTP exchange seam: one request in, one response out.
//!
//! [`HttpExchange`] is the transport of the [`NegotiateHttpClient`]: a trait over
//! `http::Request<Vec<u8>>` and `http::Response<Vec<u8>>`, so an application can
//! send through its own HTTP stack (proxies, pooling, its own TLS). The built-in
//! implementation is `transport::rustls_proxy::RustlsTransport` (the
//! `kkdcp-rustls` leaf).
//!
//! The trait is asynchronous, like the rest of the client: the future is boxed,
//! as [`KdcProxyTransport`] does it, so the trait stays object-safe.
//!
//! [`NegotiateHttpClient`]: super::agent::NegotiateHttpClient
//! [`KdcProxyTransport`]: crate::transport::proxy::KdcProxyTransport
//!
//! # Channel bindings
//!
//! [`HttpExchange::connect`] opens the connection a request will travel on
//! before the request exists, and reports the authenticated TLS peer of that
//! connection as a [`TlsChannel`]. The client builds its Negotiate token with
//! the RFC 5929 `tls-server-end-point` bindings of exactly that connection and
//! sends the request over it with [`PreparedConnection::send`]. The provided
//! `connect` reports no channel and sends through [`HttpExchange::exchange`],
//! so an exchange that does not override it claims no binding.
//!
//! # Security
//!
//! An exchange sends exactly the request it is given and follows no redirect:
//! the client owns redirect decisions, because only it knows which headers hold
//! credentials. It must verify the server's certificate and host name for
//! `https` and bound the response body. A [`TlsChannel`] must describe the peer
//! that the connection's TLS handshake authenticated, and a
//! [`PreparedConnection`] must carry its request on that very connection.

use core::{fmt, future::ready, pin::Pin};

use http_types::{HeaderMap, HeaderValue, Request, Response, Uri};

use crate::{error::HttpExchange as Error, gss::ChannelBindings};

/// RFC 5929 `tls-server-end-point`: the certificate's binding hash.
mod end_point;

/// The future of [`HttpExchange::exchange`]: the response, or the failure.
pub type ExchangeFuture<'request> =
    Pin<Box<dyn Future<Output = Result<Response<Vec<u8>>, Error>> + Send + 'request>>;

/// The future of [`HttpExchange::connect`]: the prepared connection, or the failure.
pub type ConnectFuture<'exchange> =
    Pin<Box<dyn Future<Output = Result<PreparedConnection<'exchange>, Error>> + Send + 'exchange>>;

/// The one-shot send of a [`PreparedConnection`].
type Sender<'exchange> =
    Box<dyn FnOnce(Request<Vec<u8>>) -> ExchangeFuture<'exchange> + Send + 'exchange>;

/// Sends one HTTP request and returns its response.
pub trait HttpExchange: Send + Sync {
    /// Send `request` (its URI is absolute) and return the response, whatever
    /// its status: a `401` or a `302` is a response, not an error.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotDelivered`] or [`Error::MaybeDelivered`] for a failed
    /// exchange, [`Error::TooLarge`] for a body past the exchange's limit and
    /// the other variants of [`Error`] for a request this exchange refuses.
    ///
    /// # Cancel safety
    ///
    /// The caller may drop the future; the request may then have been delivered.
    fn exchange(&self, request: Request<Vec<u8>>) -> ExchangeFuture<'_>;

    /// Open the connection for one request to the origin of `uri` and report
    /// its authenticated TLS peer.
    ///
    /// The provided implementation opens nothing: its connection has no
    /// [`TlsChannel`] and sends through [`Self::exchange`]. An exchange that
    /// can name the certificate of the connection carrying a request
    /// overrides it.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotDelivered`] when the connection or its handshake
    /// fails, [`Error::PeerCertificate`] for a peer certificate that does not
    /// parse, and the refusals of [`Self::exchange`].
    ///
    /// # Cancel safety
    ///
    /// The caller may drop the future: no request has been sent yet.
    #[inline]
    fn connect(&self, _uri: &Uri) -> ConnectFuture<'_> {
        Box::pin(ready(Ok(PreparedConnection::new(None, |request| {
            self.exchange(request)
        }))))
    }
}

/// A connection opened by [`HttpExchange::connect`] for exactly one request.
pub struct PreparedConnection<'exchange> {
    /// The authenticated TLS peer, `None` for a connection without one.
    channel: Option<TlsChannel>,
    /// Sends the request over the connection.
    sender: Sender<'exchange>,
}

impl fmt::Debug for PreparedConnection<'_> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PreparedConnection")
            .field("channel", &self.channel)
            .finish_non_exhaustive()
    }
}

impl<'exchange> PreparedConnection<'exchange> {
    /// A connection whose TLS peer is `channel` (`None` for none) and whose
    /// request `sender` sends over it.
    ///
    /// # Security
    ///
    /// `channel` must be the peer this connection's handshake authenticated,
    /// and `sender` must send on this connection only, to its origin only.
    #[inline]
    #[must_use]
    pub fn new<S>(channel: Option<TlsChannel>, sender: S) -> Self
    where
        S: FnOnce(Request<Vec<u8>>) -> ExchangeFuture<'exchange> + Send + 'exchange,
    {
        Self {
            channel,
            sender: Box::new(sender),
        }
    }

    /// The authenticated TLS peer of this connection, if it has one.
    #[inline]
    #[must_use]
    pub const fn tls_channel(&self) -> Option<&TlsChannel> {
        self.channel.as_ref()
    }

    /// Send `request` over this connection and return the response.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`HttpExchange::exchange`].
    ///
    /// # Cancel safety
    ///
    /// The caller may drop the future; the request may then have been delivered.
    #[inline]
    pub fn send(self, request: Request<Vec<u8>>) -> ExchangeFuture<'exchange> {
        (self.sender)(request)
    }
}

/// The authenticated TLS peer of one connection: the end-entity certificate
/// its handshake verified, and the RFC 5929 `tls-server-end-point` channel
/// bindings derived from it.
#[derive(Clone, Eq, PartialEq)]
pub struct TlsChannel {
    /// The DER end-entity certificate.
    certificate: Vec<u8>,
    /// The `tls-server-end-point` bindings; `None` when RFC 5929 defines none
    /// for the certificate's signature algorithm or this crate cannot hash it.
    server_end_point: Option<ChannelBindings>,
}

impl fmt::Debug for TlsChannel {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsChannel")
            .field("certificate_len", &self.certificate.len())
            .field("server_end_point", &self.server_end_point.is_some())
            .finish()
    }
}

impl TlsChannel {
    /// The longest end-entity certificate accepted, in bytes.
    pub const MAX_CERTIFICATE_BYTES: usize = 64 * 1024;

    /// The channel of a peer that presented the DER end-entity `certificate`.
    ///
    /// The `tls-server-end-point` hash follows RFC 5929 section 4.1: the hash
    /// of the certificate's signature algorithm, SHA-256 when that is MD5 or
    /// SHA-1. SHA-224, SHA-256, SHA-384 and SHA-512 signatures (PKCS #1 v1.5,
    /// ECDSA, DSA, and RSASSA-PSS whose MGF1 hash is its message hash) have
    /// bindings; `EdDSA`, an RSASSA-PSS signature with two hashes and every
    /// other algorithm have none.
    ///
    /// # Errors
    ///
    /// Returns [`Error::PeerCertificate`] for a certificate longer than
    /// [`Self::MAX_CERTIFICATE_BYTES`] or one that is not a DER X.509
    /// certificate.
    #[inline]
    pub fn from_end_entity(certificate: Vec<u8>) -> Result<Self, Error> {
        if certificate.len() > Self::MAX_CERTIFICATE_BYTES {
            return Err(Error::PeerCertificate {
                reason: "the certificate is longer than 64 KiB",
            });
        }
        let server_end_point = end_point::bindings(&certificate)
            .map_err(|reason| Error::PeerCertificate { reason })?;
        Ok(Self {
            certificate,
            server_end_point,
        })
    }

    /// The DER end-entity certificate.
    #[inline]
    #[must_use]
    pub fn certificate(&self) -> &[u8] {
        &self.certificate
    }

    /// The RFC 5929 `tls-server-end-point` channel bindings, when the
    /// certificate's signature algorithm defines them.
    #[inline]
    #[must_use]
    pub const fn server_end_point(&self) -> Option<&ChannelBindings> {
        self.server_end_point.as_ref()
    }
}

/// A cookie jar the client consults for every request and feeds with every
/// response (the `http-client` leaf provides `http::cookies::CookieStore`).
pub trait CookieJar: Send {
    /// The `Cookie` header value for a request to `uri`, if the jar holds any.
    fn cookie_header(&self, uri: &Uri) -> Option<HeaderValue>;

    /// Store the `Set-Cookie` headers of a response to a request for `uri`;
    /// a cookie the jar refuses is dropped.
    fn store(&mut self, uri: &Uri, headers: &HeaderMap);
}
