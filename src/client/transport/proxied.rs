//! MS-KKDCP endpoints: a request through the KDC proxy transport.
//!
//! The request is framed for the realm ([`kkdcp::encode_request`]), posted with the
//! realm's `http_anchors` under the transport timeout, and the reply's Kerberos
//! message is taken out of its KDC-PROXY-MESSAGE ([`kkdcp::decode_reply`]).

use core::{fmt, ptr};

use super::{Config, Error, Tokio};
use crate::{
    config::section_values::{Location, Value},
    error::KdcProxy,
    transport::{
        kkdcp,
        proxy::{KdcProxyTransport, Request, Url},
        rustls_proxy,
    },
};

/// A `'static` KDC proxy transport; two handles are equal when they name the same
/// transport, so [`Tokio`] keeps its `Eq`.
#[derive(Clone, Copy)]
pub(super) struct Handle(&'static dyn KdcProxyTransport);

impl Handle {
    /// A handle on `transport`.
    pub(super) const fn new(transport: &'static dyn KdcProxyTransport) -> Self {
        Self(transport)
    }

    /// The built-in transport, when the `kkdcp-rustls` feature compiles one in.
    pub(super) const fn builtin() -> Option<Self> {
        match rustls_proxy::BUILTIN_PROXY {
            Some(transport) => Some(Self(transport)),
            None => None,
        }
    }
}

impl PartialEq for Handle {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        ptr::addr_eq(self.0, other.0)
    }
}

impl Eq for Handle {}

impl fmt::Debug for Handle {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self.0, f)
    }
}

/// The realm's `http_anchors` values in profile order (MIT `setup_tls`,
/// `sendto_kdc.c:1236-1243`); none when the relation is unset.
fn anchors(config: &Config, realm: &str) -> Vec<Location> {
    match config
        .realm(realm)
        .and_then(|entry| entry.relations.get("http_anchors"))
    {
        Some(Value::Locations(locations)) => locations.clone(),
        Some(Value::Boolean(_) | Value::Text(_) | Value::List(_) | Value::Choice(_)) | None => {
            Vec::new()
        }
    }
}

/// Whether a proxy failure proves that no byte of the request reached the proxy.
const fn definite(error: &KdcProxy) -> bool {
    matches!(
        error,
        KdcProxy::Unavailable { url: _ }
            | KdcProxy::InvalidUrl { reason: _ }
            | KdcProxy::NoAnchors { realm: _ }
            | KdcProxy::Anchor {
                anchor: _,
                reason: _
            }
            | KdcProxy::NotDelivered(_)
    )
}

/// A framed request, ready to post.
struct Prepared {
    /// The transport to post through.
    proxy: Handle,
    /// The KDC-PROXY-MESSAGE.
    body: zeroize::Zeroizing<Vec<u8>>,
    /// The realm's anchors.
    anchors: Vec<Location>,
}

/// Frame `request` for `realm`; nothing is sent.
///
/// # Errors
///
/// Returns [`KdcProxy::Unavailable`] when no proxy transport is set, and the errors
/// of [`kkdcp::encode_request`].
fn prepare(
    transport: &Tokio,
    (config, realm): (&Config, &str),
    url: &Url,
    request: &[u8],
) -> Result<Prepared, Error> {
    let Some(proxy) = transport.proxy else {
        return Err(KdcProxy::Unavailable {
            url: url.to_string(),
        }
        .into());
    };
    Ok(Prepared {
        proxy,
        body: kkdcp::encode_request(request, realm)?,
        anchors: anchors(config, realm),
    })
}

/// Post a prepared request for `realm` to the proxy at `url` and return its body.
///
/// # Errors
///
/// Returns [`Error::TransportTimeout`] when the transport timeout or the request
/// budget ends first, and the transport's failure.
///
/// # Cancel safety
///
/// Dropping the future abandons the request, which may have been delivered.
async fn post(
    transport: &Tokio,
    prepared: &Prepared,
    (realm, url): (&str, &Url),
) -> Result<Vec<u8>, Error> {
    let posted = prepared.proxy.0.post(
        Request::new(url, &prepared.body)
            .with_realm(realm)
            .with_anchors(&prepared.anchors)
            .with_max_response(kkdcp::MAX_MESSAGE),
    );
    transport
        .with_transport_timeout(async { Ok(posted.await?) })
        .await
}

/// The Kerberos message of a proxy's body, within the TCP response limit.
///
/// # Errors
///
/// Returns the errors of [`kkdcp::decode_reply`], and [`KdcProxy::TooLarge`] for a
/// message longer than the transport's TCP response limit.
fn reply(transport: &Tokio, body: &[u8]) -> Result<Vec<u8>, Error> {
    let message = kkdcp::decode_reply(body)?;
    if message.len() > transport.tcp_response_limit {
        return Err(KdcProxy::TooLarge {
            actual: message.len(),
            limit: transport.tcp_response_limit,
        }
        .into());
    }
    Ok(message)
}

/// Send a KDC request through the proxy at `url`.
///
/// # Errors
///
/// Returns the errors of `prepare`, `post` and `reply`.
///
/// # Cancel safety
///
/// cancel-safe: a KDC request changes no client state and can be sent again.
pub(super) async fn send(
    transport: &Tokio,
    destination: (&Config, &str),
    url: &Url,
    request: &[u8],
) -> Result<Vec<u8>, Error> {
    let prepared = prepare(transport, destination, url, request)?;
    let body = post(transport, &prepared, (destination.1, url)).await?;
    reply(transport, &body)
}

/// Send a kpasswd request through the proxy at `url`, keeping the outcome-unknown
/// classification: only a failure that proves the request never reached the proxy
/// is definite.
///
/// # Errors
///
/// Returns the errors of `prepare` and a definite proxy failure as they are, and
/// [`Error::KpasswdOutcomeUnknown`]
/// for every other failure, timeouts and malformed replies included.
///
/// # Cancel safety
///
/// NOT cancel-safe: a cancelled request may already have changed the password.
pub(super) async fn send_password(
    transport: &Tokio,
    destination: (&Config, &str),
    url: &Url,
    request: &[u8],
) -> Result<Vec<u8>, Error> {
    let prepared = prepare(transport, destination, url, request)?;
    match post(transport, &prepared, (destination.1, url)).await {
        Ok(body) => {
            reply(transport, &body).map_err(|error| Error::KpasswdOutcomeUnknown(Box::new(error)))
        }
        Err(Error::KdcProxy(error)) if definite(&error) => Err(Error::KdcProxy(error)),
        Err(error) => Err(Error::KpasswdOutcomeUnknown(Box::new(error))),
    }
}
