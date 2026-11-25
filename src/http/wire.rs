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
//! # Security
//!
//! An exchange sends exactly the request it is given and follows no redirect:
//! the client owns redirect decisions, because only it knows which headers hold
//! credentials. It must verify the server's certificate and host name for
//! `https` and bound the response body.

use core::pin::Pin;

use http_types::{HeaderMap, HeaderValue, Request, Response, Uri};

use crate::error::HttpExchange as Error;

/// The future of [`HttpExchange::exchange`]: the response, or the failure.
pub type ExchangeFuture<'request> =
    Pin<Box<dyn Future<Output = Result<Response<Vec<u8>>, Error>> + Send + 'request>>;

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
