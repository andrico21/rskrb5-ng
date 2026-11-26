//! A shared connection to the daemon with MIT's one reconnect (`cache_call`,
//! `cc_kcm.c:670-680`, and the `EPIPE` retry of `kcmio_unix_socket_write`,
//! `cc_kcm.c:345-380`).

use alloc::sync::Arc;
use core::{fmt, time::Duration};
use std::{
    io,
    path::{Path, PathBuf},
    sync::{Mutex, PoisonError},
};

use super::{
    client::Client,
    seam::{self, KcmTransport},
    socket::{self, Deadline, Trust},
    wire::{calls::Call, shape::Shape},
};
use crate::error::{Kcm as Error, KcmStage};

/// How the daemon is reached.
#[derive(Clone, Debug)]
pub(super) struct Endpoint {
    /// The socket path (`kcm_socket`); `None` when the socket is disabled
    /// (`kcm_socket = -`).
    path: Option<PathBuf>,
    /// Which users may own the socket.
    trust: Trust,
    /// How long one call may take.
    timeout: Duration,
}

impl Endpoint {
    /// The daemon at `path`, trusting root and this process's user, with the
    /// default time limit.
    pub(super) const fn new(path: PathBuf, timeout: Duration) -> Self {
        Self {
            path: Some(path),
            trust: Trust::new(),
            timeout,
        }
    }

    /// No daemon socket: every connection attempt reports
    /// [`Error::NoServer`].
    pub(super) const fn disabled(timeout: Duration) -> Self {
        Self {
            path: None,
            trust: Trust::new(),
            timeout,
        }
    }

    /// The socket path, `None` when the socket is disabled.
    pub(super) fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// How long one call may take.
    pub(super) const fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Which users may own the socket.
    pub(super) const fn trust(&self) -> &Trust {
        &self.trust
    }

    /// The same endpoint with another time limit.
    pub(super) const fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// The same endpoint trusting `trust`.
    pub(super) fn with_trust(mut self, trust: Trust) -> Self {
        self.trust = trust;
        self
    }
}

/// Which transports stand before the socket.
#[derive(Clone, Debug)]
pub(super) struct Route {
    /// Whether the process-wide installed [`seam`] transport replaces
    /// everything else.
    built_in: bool,
    /// The transport of the configured Mach service, tried before the socket.
    mach: Option<Arc<dyn KcmTransport>>,
}

impl Route {
    /// The route of the built-in store: the installed transport, else the
    /// socket.
    pub(super) const fn built_in() -> Self {
        Self {
            built_in: true,
            mach: None,
        }
    }

    /// The route of a configured store: the installed transport, else the
    /// transport of the configured Mach service when there is one, else the
    /// socket.
    pub(super) const fn configured(mach: Option<Arc<dyn KcmTransport>>) -> Self {
        Self {
            built_in: true,
            mach,
        }
    }

    /// The route of a store for one socket: the socket only.
    pub(super) const fn socket_only() -> Self {
        Self {
            built_in: false,
            mach: None,
        }
    }

    /// Whether any transport other than the socket may serve a call.
    pub(super) fn has_transport(&self) -> bool {
        (self.built_in && seam::installed().is_some()) || self.mach.is_some()
    }
}

/// The connection of a store and its handles: connected on first use, dropped
/// after any failure that leaves it out of step, and shared by all calls
/// (one call at a time).
pub(super) struct Session {
    /// How to connect.
    endpoint: Endpoint,
    /// Which transports precede the socket.
    route: Route,
    /// The live connection, if any.
    link: Mutex<Option<Client<Deadline>>>,
}

impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session")
            .field("endpoint", &self.endpoint)
            .finish_non_exhaustive()
    }
}

impl Session {
    /// A session that has not connected yet.
    pub(super) const fn new(endpoint: Endpoint, route: Route) -> Self {
        Self {
            endpoint,
            route,
            link: Mutex::new(None),
        }
    }

    /// Which transports precede the socket.
    pub(super) const fn route(&self) -> &Route {
        &self.route
    }

    /// How the daemon is reached.
    pub(super) const fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// Send `call` through the installed transport, else through the
    /// transport of the configured Mach service, else over the socket,
    /// reconnecting once when the daemon closed an idle connection (a write
    /// that fails with a broken pipe).
    ///
    /// A Mach transport that reports [`Error::NoServer`] never received the
    /// request, so the socket gets it (MIT `kcmio_connect`, `cc_kcm.c:436-438`);
    /// any other failure of a transport is final, so that a request that may
    /// have been delivered is never sent again.
    ///
    /// # Errors
    ///
    /// The errors of [`Client::call`] and of connecting, or of the transport.
    pub(super) fn call<S>(&self, call: &Call<S>) -> Result<S::Output, Error>
    where
        S: Shape,
    {
        if self.route.built_in
            && let Some(installed) = seam::installed()
        {
            return seam::exchange(&**installed, call);
        }
        if let Some(mach) = &self.route.mach {
            match seam::exchange(&**mach, call) {
                Err(Error::NoServer) => {}
                other => return other,
            }
        }
        self.exchange(
            &mut self.link.lock().unwrap_or_else(PoisonError::into_inner),
            call,
        )
    }

    /// [`Self::call`] with the connection slot locked.
    ///
    /// # Errors
    ///
    /// The errors of [`Self::call`].
    fn exchange<S>(
        &self,
        link: &mut Option<Client<Deadline>>,
        call: &Call<S>,
    ) -> Result<S::Output, Error>
    where
        S: Shape,
    {
        let Some(path) = self.endpoint.path() else {
            return Err(Error::NoServer);
        };
        let mut reconnected = false;
        loop {
            if link.as_ref().is_none_or(Client::is_broken) {
                let socket = socket::connect(path, self.endpoint.trust())?;
                *link = Some(Client::new(socket));
            }
            let Some(client) = link.as_mut() else {
                return Err(Error::Broken);
            };
            client.stream_mut().arm(self.endpoint.timeout());
            return match client.call(call) {
                Err(Error::Io {
                    stage: KcmStage::Write,
                    source,
                }) if source.kind() == io::ErrorKind::BrokenPipe && !reconnected => {
                    reconnected = true;
                    *link = None;
                    continue;
                }
                other => other,
            };
        }
    }
}
