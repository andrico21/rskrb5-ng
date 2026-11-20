//! The KDC proxy transport: a caller-implementable trait that POSTs one
//! KDC-PROXY-MESSAGE over HTTPS, and the `https://` URL a realm names.
//!
//! [`client::transport::Tokio`](crate::client::transport::Tokio) sends a request for
//! a realm whose `kdc`, `primary_kdc` or `kpasswd_server` is an `https://` URL
//! through the [`KdcProxyTransport`] set with
//! [`Tokio::with_kdc_proxy`](crate::client::transport::Tokio::with_kdc_proxy), or the
//! built-in rustls transport when the `kkdcp-rustls` feature is compiled in. It frames
//! the request ([`super::kkdcp::encode_request`]), hands it to
//! [`KdcProxyTransport::post`] with the realm's `http_anchors`, and decodes the reply
//! ([`super::kkdcp::decode_reply`]).
//!
//! # Security
//!
//! An implementation must verify the proxy's certificate chain against the request's
//! anchors (or its own configured roots) and the URL's host name, must not follow a
//! redirect, and must bound the response body by [`Request::max_response`]. The
//! proxy only relays: the reply is authenticated by its Kerberos keys as any KDC
//! reply is.

use core::{fmt, net::IpAddr, pin::Pin};

use crate::{
    client::transport::parse_kdc_endpoint, config::section_values::Location,
    error::KdcProxy as Error,
};

/// The longest `https://` URL accepted from a profile, in bytes.
pub const MAX_URL: usize = 2048;
/// The port of a proxy URL that names none (MIT `locate_kdc.c:317`).
pub const DEFAULT_PORT: u16 = 443;
/// The scheme prefix that makes a server entry a proxy URL (MIT compares it
/// case-sensitively, `locate_kdc.c:222`).
const SCHEME: &str = "https://";

/// An `https://host[:port][/path]` KDC proxy URL of the profile (MIT
/// `parse_uri_if_https`, `locate_kdc.c:216-231`).
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct Url {
    /// The host name or IP literal, without brackets.
    host: String,
    /// The port.
    port: u16,
    /// The path after the first `/`, without it.
    path: String,
}

impl fmt::Debug for Url {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Url").field(&self.to_string()).finish()
    }
}

impl fmt::Display for Url {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.host.contains(':') {
            write!(f, "https://[{}]:{}/{}", self.host, self.port, self.path)
        } else {
            write!(f, "https://{}:{}/{}", self.host, self.port, self.path)
        }
    }
}

impl Url {
    /// The proxy URL of a server entry, `None` when the entry does not start with
    /// `https://` (the value is then a `host[:port]` endpoint).
    ///
    /// `value` is trimmed with `str::trim`. After `https://`, the text up to the first
    /// `/` is the host and optional port, read as [`KdcEndpoint::configured`] reads a
    /// server entry, with the default port 443; the rest is the path. This crate
    /// refuses what MIT would put on the wire unchecked: user information (`@`), a
    /// query or fragment in the host part, and a path byte outside visible ASCII
    /// (it would change the HTTP request line).
    ///
    /// [`KdcEndpoint::configured`]: crate::client::transport::KdcEndpoint::configured
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidUrl`] for a URL longer than [`MAX_URL`], with no host,
    /// with user information, a `?` or `#` before the path, a host or port that does
    /// not parse, a zone id in an IP literal, or a path byte that is not visible ASCII
    /// or is `#`.
    #[inline]
    pub fn parse(value: &str) -> Result<Option<Self>, Error> {
        let trimmed = value.trim();
        let Some(rest) = trimmed.strip_prefix(SCHEME) else {
            return Ok(None);
        };
        if trimmed.len() > MAX_URL {
            return Err(invalid("the URL is longer than MAX_URL"));
        }
        let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
        if authority.is_empty() {
            return Err(invalid("the URL names no host"));
        }
        if authority.contains(['@', '?', '#']) {
            return Err(invalid(
                "the host part holds user information, a query or a fragment",
            ));
        }
        if !path
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b'#')
        {
            return Err(invalid(
                "the path holds a byte outside visible ASCII or a fragment",
            ));
        }
        let (host, port) = parse_kdc_endpoint(authority, DEFAULT_PORT)
            .map_err(|_endpoint| invalid("the host or port does not parse"))?;
        if host.contains('%') {
            return Err(invalid("an IP literal carries a zone id"));
        }
        if host.contains(':') && host.parse::<IpAddr>().is_err() {
            return Err(invalid("the host is neither a name nor an IP literal"));
        }
        Ok(Some(Self {
            host,
            port,
            path: path.to_owned(),
        }))
    }

    /// The host name or IP literal, without brackets: the TLS server name.
    #[inline]
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The port.
    #[inline]
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    /// The path after the first `/`, without it; empty for the root.
    #[inline]
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The value of the HTTP `Host` header: the host (in brackets for IPv6) and port.
    #[inline]
    #[must_use]
    pub fn authority(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

/// The error of an invalid proxy URL.
const fn invalid(reason: &'static str) -> Error {
    Error::InvalidUrl { reason }
}

/// One KDC-PROXY-MESSAGE to POST.
#[non_exhaustive]
pub struct Request<'request> {
    /// Where to POST it.
    pub url: &'request Url,
    /// The KDC-PROXY-MESSAGE, sent as `application/kerberos`.
    pub body: &'request [u8],
    /// The realm whose KDC or kpasswd server the proxy reaches.
    pub realm: &'request str,
    /// The realm's `http_anchors` values in profile order; empty when unset.
    pub anchors: &'request [Location],
    /// The longest response body to accept, in bytes.
    pub max_response: usize,
}

impl fmt::Debug for Request<'_> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Request")
            .field("url", self.url)
            .field("body_len", &self.body.len())
            .field("anchors", &self.anchors.len())
            .field("max_response", &self.max_response)
            .finish_non_exhaustive()
    }
}

impl<'request> Request<'request> {
    /// A request for `realm` to `url` with `body`.
    pub(crate) const fn new(
        url: &'request Url,
        body: &'request [u8],
        (realm, anchors): (&'request str, &'request [Location]),
        max_response: usize,
    ) -> Self {
        Self {
            url,
            body,
            realm,
            anchors,
            max_response,
        }
    }
}

/// The future of [`KdcProxyTransport::post`]: the response body, or the failure.
pub type PostFuture<'request> =
    Pin<Box<dyn Future<Output = Result<Vec<u8>, Error>> + Send + 'request>>;

/// Posts one KDC-PROXY-MESSAGE to an MS-KKDCP proxy over HTTPS.
///
/// Implement it to reach the proxy through the application's own HTTPS stack; pass a
/// `&'static` instance to [`Tokio::with_kdc_proxy`]. The built-in implementation is
/// `transport::rustls_transport::RustlsTransport` (feature `kkdcp-rustls`).
///
/// [`Tokio::with_kdc_proxy`]: crate::client::transport::Tokio::with_kdc_proxy
///
/// # Security
///
/// See the module documentation: verify the chain and the host name, follow no
/// redirect, and bound the body. Report a failure before any byte of the request
/// could have reached the proxy as [`Error::NotDelivered`] and a later one as
/// [`Error::MaybeDelivered`]: a password change through the proxy is reported as
/// outcome-unknown unless the failure is definite.
pub trait KdcProxyTransport: Send + Sync + fmt::Debug {
    /// POST `request.body` as `application/kerberos` to `request.url` and return
    /// the body of a `200` response.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotDelivered`] or [`Error::MaybeDelivered`] for a failed
    /// exchange, [`Error::Status`] for any other status, [`Error::TooLarge`] for a
    /// body longer than `request.max_response`, and [`Error::NoAnchors`] or
    /// [`Error::Anchor`] when the trust anchors are missing or do not load.
    ///
    /// # Cancel safety
    ///
    /// The caller drops the future when its timeout ends; the request may then have
    /// been delivered.
    fn post<'request>(&'request self, request: Request<'request>) -> PostFuture<'request>;
}

/// Proxy URL parsing.
#[cfg(test)]
#[path = "proxy/tests.rs"]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests;
