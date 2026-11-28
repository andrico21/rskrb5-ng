//! The process-wide transport seam: a replacement for the daemon socket.
//!
//! MIT 1.22.2 reaches a KCM daemon through `kcmio_call` (`cc_kcm.c:451-480`),
//! which is the Unix-socket exchange everywhere except macOS, where the same
//! requests go to a Mach service (`kcmio_mach_call`, `cc_kcm.c:90-300`).
//! [`install_transport`] makes the built-in `KCM` store (the one
//! [`Store::default`](super::Store) and the name dispatch of
//! [`file_store`](crate::ccache::file_store) reach) use such a transport
//! instead of the socket. A [`Store`](super::Store) made for a socket path
//! keeps using that socket.
//!
//! The Mach service is a setting (`kcm_mach_service`), so a transport for it
//! cannot be one process-wide value: [`install_transport_factory`] installs a
//! [`TransportFactory`] that makes the transport for the service name of the
//! configuration a store is built from
//! ([`Store::from_libdefaults`](super::Store::from_libdefaults)). An installed
//! transport precedes the factory and the configured socket; a transport that
//! reports [`Error::NoServer`] hands its request to the configured socket, as
//! MIT falls back from Mach to the socket (`kcmio_connect`, `cc_kcm.c:436-438`).
//!
//! # Security
//!
//! An installed transport is trusted code: it sees every request, including
//! the session keys and tickets of `STORE` and `REPLACE`, and decides who
//! answers. Installation is process-wide and the first one wins, so a library
//! cannot replace the transport an application chose; the application
//! installs its transport before any other code can reach the store. A reply
//! over [`wire::MAX_REPLY_SIZE`](super::wire::MAX_REPLY_SIZE) is refused and
//! the rest is parsed like a socket reply, but the transport has allocated
//! the reply by then: one that reads from a socket must bound its own reads.
//! A request is refused past
//! [`wire::MAX_REQUEST_SIZE`](super::wire::MAX_REQUEST_SIZE).
//!
//! # Cancel safety
//!
//! [`KcmTransport::call`] is synchronous, so a call is never cancelled half
//! way; an implementation that blocks must bound its own wait.

use alloc::sync::Arc;
use core::fmt;
use std::sync::OnceLock;

use zeroize::Zeroizing;

use super::{
    client::lost,
    wire::{MAX_REPLY_SIZE, MAX_REQUEST_SIZE, Reply, calls::Call, shape::Shape},
};
use crate::error::Kcm as Error;

/// How the built-in `KCM` store reaches a daemon when not by its socket
/// (MIT `kcmio_call`).
///
/// `request` is the complete request exactly as MIT marshals it: the protocol
/// version, the opcode and the parameters, without the four-byte length frame
/// of the socket. The reply is the complete reply: the daemon's status code
/// (four big-endian bytes) followed by the payload. The Unix-socket transport
/// adds and strips its own framing, so an implementation never sees it.
///
/// # Security
///
/// Requests and replies carry session keys and tickets: do not log them and
/// erase copies after use.
///
/// # Cancel safety
///
/// The method is synchronous.
pub trait KcmTransport: fmt::Debug + Send + Sync {
    /// Send `request` to the daemon and return its reply.
    ///
    /// # Errors
    ///
    /// [`Error::NoServer`] when no daemon is reachable, [`Error::Untrusted`]
    /// when the daemon fails an ownership check, [`Error::Daemon`] when the
    /// transport itself reports a failure code, and [`Error::Io`] or another
    /// variant for any other failure. A failure other than these three on a
    /// request that changes the daemon is reported as
    /// [`Error::OutcomeUnknown`].
    fn call(&self, request: &[u8]) -> Result<Vec<u8>, Error>;
}

/// How a configuration's `kcm_mach_service` becomes a [`KcmTransport`].
///
/// An application (or the platform companion crate) installs one with
/// [`install_transport_factory`]; a store built from a configuration asks it
/// for the transport of that configuration's service, so two configurations
/// naming two services reach two services.
///
/// # Security
///
/// The transport it returns is trusted code: see [`KcmTransport`]. The factory
/// decides who answers for a service name.
///
/// # Cancel safety
///
/// The method is synchronous.
pub trait TransportFactory: fmt::Debug + Send + Sync {
    /// The transport that reaches the service `service` (never `-` or empty:
    /// those disable the service and never reach a factory).
    ///
    /// Creating the transport does not contact the service.
    ///
    /// # Errors
    ///
    /// [`Error::NoServer`] when the factory cannot serve this name at all; any
    /// other error is returned to the caller of the store's constructor.
    fn transport(&self, service: &str) -> Result<Arc<dyn KcmTransport>, Error>;
}

/// The installed transport, if any.
static INSTALLED: OnceLock<Arc<dyn KcmTransport>> = OnceLock::new();

/// The installed transport factory, if any.
static FACTORY: OnceLock<Arc<dyn TransportFactory>> = OnceLock::new();

/// Make `transport` the one the built-in `KCM` store uses, for the whole
/// process. The first installation wins.
///
/// # Errors
///
/// [`Error::TransportInstalled`] when a transport is installed already
/// (including this one).
#[inline]
pub fn install_transport(transport: Arc<dyn KcmTransport>) -> Result<(), Error> {
    INSTALLED
        .set(transport)
        .map_err(|_refused| Error::TransportInstalled)
}

/// Make `factory` the one that serves the `kcm_mach_service` of every
/// configured `KCM` store, for the whole process. The first installation wins.
///
/// # Errors
///
/// [`Error::TransportInstalled`] when a factory is installed already
/// (including this one).
#[inline]
pub fn install_transport_factory(factory: Arc<dyn TransportFactory>) -> Result<(), Error> {
    FACTORY
        .set(factory)
        .map_err(|_refused| Error::TransportInstalled)
}

/// The installed transport factory.
pub(super) fn factory() -> Option<&'static Arc<dyn TransportFactory>> {
    FACTORY.get()
}

/// The installed transport.
pub(super) fn installed() -> Option<&'static Arc<dyn KcmTransport>> {
    INSTALLED.get()
}

/// Send `call` through `transport` and decode the reply.
///
/// # Errors
///
/// [`Error::RequestTooBig`], the errors of the transport, [`Error::ReplyTooBig`]
/// and the errors of decoding the reply.
pub(super) fn exchange<S>(transport: &dyn KcmTransport, call: &Call<S>) -> Result<S::Output, Error>
where
    S: Shape,
{
    let request = call.request();
    let opcode = request.opcode();
    let bytes = request.as_bytes();
    if bytes.len() > MAX_REQUEST_SIZE {
        return Err(Error::RequestTooBig {
            length: bytes.len(),
        });
    }
    let reply = Zeroizing::new(transport.call(bytes).map_err(|error| {
        if matches!(
            error,
            Error::NoServer | Error::Untrusted(_) | Error::Daemon { opcode: _, code: _ }
        ) {
            error
        } else {
            lost(opcode, error)
        }
    })?);
    if reply.len() > MAX_REPLY_SIZE {
        return Err(Error::ReplyTooBig {
            length: u32::try_from(reply.len()).unwrap_or(u32::MAX),
            limit: MAX_REPLY_SIZE,
        });
    }
    S::decode(&Reply::from_frame(opcode, 0, reply)?)
}
