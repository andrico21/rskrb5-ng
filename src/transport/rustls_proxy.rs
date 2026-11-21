//! The built-in KDC proxy transport: HTTPS with rustls and the pure-Rust `RustCrypto`
//! provider (the `kkdcp-rustls` leaf, owner decision D7).
//!
//! `RustlsTransport` connects to the proxy URL's host and port, runs TLS 1.3 or 1.2
//! with SNI, verifies the proxy's certificate chain against the request's
//! `http_anchors` and its own configured roots and the certificate against the URL's
//! host name, POSTs the KDC-PROXY-MESSAGE over HTTP/1.1 and returns the body of a
//! `200` response.
//!
//! # Security
//!
//! There is no certificate bypass and no implicit trust store: with no anchor and no
//! configured root the request fails with `NoAnchors` before any connection is made.
//! A redirect or any other status is refused (`Status`), never followed. The body is
//! bounded by the request's `max_response` while it is read. A failure before the
//! TLS handshake completed is `NotDelivered`; any later one is `MaybeDelivered`, so a
//! password change keeps its outcome-unknown classification.
//!
//! # Cancel safety
//!
//! Dropping a post closes the connection; the request may have been delivered.

#[cfg(feature = "kkdcp-rustls")]
use alloc::sync::Arc;
#[cfg(feature = "kkdcp-rustls")]
use core::fmt;

#[cfg(feature = "kkdcp-rustls")]
use rustls::{
    ClientConfig, RootCertStore,
    pki_types::{CertificateDer, ServerName},
    version::{TLS12, TLS13},
};
#[cfg(feature = "kkdcp-rustls")]
use tokio::net::TcpStream;
#[cfg(feature = "kkdcp-rustls")]
use tokio_rustls::TlsConnector;

use super::proxy::KdcProxyTransport;
#[cfg(feature = "kkdcp-rustls")]
use super::proxy::{PostFuture, Request};
#[cfg(feature = "kkdcp-rustls")]
use crate::error::KdcProxy as Error;

/// Trust anchors: `http_anchors` locations and configured roots.
#[cfg(feature = "kkdcp-rustls")]
mod anchors;
/// The HTTP/1.1 exchange over the TLS stream.
#[cfg(feature = "kkdcp-rustls")]
mod exchange;

/// The built-in KDC proxy transport.
///
/// [`RustlsTransport::new`] trusts only the request's `http_anchors`;
/// [`RustlsTransport::with_pem_roots`] adds roots the application configures. The
/// Tokio transport uses `RustlsTransport::new()` unless another transport is set.
#[cfg(feature = "kkdcp-rustls")]
#[derive(Clone, Default)]
pub struct RustlsTransport {
    /// Roots trusted in addition to the request's anchors.
    roots: Vec<CertificateDer<'static>>,
}

#[cfg(feature = "kkdcp-rustls")]
impl fmt::Debug for RustlsTransport {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RustlsTransport")
            .field("roots", &self.roots.len())
            .finish()
    }
}

/// The transport the Tokio client uses by default.
#[cfg(feature = "kkdcp-rustls")]
static BUILTIN: RustlsTransport = RustlsTransport::new();

#[cfg(feature = "kkdcp-rustls")]
impl RustlsTransport {
    /// A transport that trusts only each request's `http_anchors`.
    #[inline]
    #[must_use]
    pub const fn new() -> Self {
        Self { roots: Vec::new() }
    }

    /// This transport, also trusting every certificate in the PEM text `pem`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Anchor`] when `pem` holds no certificate or a block that
    /// does not parse.
    #[inline]
    pub fn with_pem_roots(mut self, pem: &[u8]) -> Result<Self, Error> {
        self.roots
            .extend(anchors::pem_certificates(pem, "configured roots")?);
        Ok(self)
    }

    /// The TLS client configuration for one request: the provider, TLS 1.3 and 1.2,
    /// the request's anchors and the configured roots, no client certificate.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NoAnchors`] with no anchor at all, [`Error::Anchor`] for an
    /// anchor that does not load, and [`Error::NotDelivered`] when the provider
    /// supports none of the protocol versions.
    fn client_config(&self, request: &Request<'_>) -> Result<ClientConfig, Error> {
        let mut roots = RootCertStore::empty();
        anchors::add(&mut roots, self.roots.iter().cloned(), "configured roots")?;
        for location in request.anchors {
            anchors::load(&mut roots, location)?;
        }
        if roots.is_empty() {
            return Err(Error::NoAnchors {
                realm: request.realm.to_owned(),
            });
        }
        Ok(
            ClientConfig::builder_with_provider(Arc::new(rustls_rustcrypto::provider()))
                .with_protocol_versions(&[&TLS13, &TLS12])
                .map_err(|error| Error::NotDelivered(Box::new(error)))?
                .with_root_certificates(roots)
                .with_no_client_auth(),
        )
    }

    /// Connect, verify and POST `request`.
    ///
    /// # Errors
    ///
    /// Returns the errors of `client_config`, [`Error::InvalidUrl`] for a host that
    /// is not a TLS server name, [`Error::NotDelivered`] when the connection or the
    /// TLS handshake (certificate verification included) fails, and the errors of
    /// the HTTP exchange.
    ///
    /// # Cancel safety
    ///
    /// Dropping the future closes the connection; the request may have been
    /// delivered.
    async fn post_once(&self, request: Request<'_>) -> Result<Vec<u8>, Error> {
        let config = self.client_config(&request)?;
        let name = ServerName::try_from(request.url.host().to_owned()).map_err(|_name| {
            Error::InvalidUrl {
                reason: "the host is not a TLS server name",
            }
        })?;
        let tcp = TcpStream::connect((request.url.host(), request.url.port()))
            .await
            .map_err(|error| Error::NotDelivered(Box::new(error)))?;
        let tls = TlsConnector::from(Arc::new(config))
            .connect(name, tcp)
            .await
            .map_err(|error| Error::NotDelivered(Box::new(error)))?;
        exchange::post(tls, &request).await
    }
}

#[cfg(feature = "kkdcp-rustls")]
impl KdcProxyTransport for RustlsTransport {
    #[inline]
    fn post<'request>(&'request self, request: Request<'request>) -> PostFuture<'request> {
        Box::pin(self.post_once(request))
    }
}

/// The built-in transport, when the `kkdcp-rustls` feature compiles it in.
#[cfg(feature = "kkdcp-rustls")]
pub(crate) const BUILTIN_PROXY: Option<&'static dyn KdcProxyTransport> = Some(&BUILTIN);

/// No built-in transport without the `kkdcp-rustls` feature.
#[cfg(not(feature = "kkdcp-rustls"))]
pub(crate) const BUILTIN_PROXY: Option<&'static dyn KdcProxyTransport> = None;
