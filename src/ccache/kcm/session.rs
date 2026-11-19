//! A shared connection to the daemon with MIT's one reconnect (`cache_call`,
//! `cc_kcm.c:670-680`, and the `EPIPE` retry of `kcmio_unix_socket_write`,
//! `cc_kcm.c:345-380`).

use core::{fmt, time::Duration};
use std::{
    io,
    path::{Path, PathBuf},
    sync::{Mutex, PoisonError},
};

use super::{
    client::Client,
    socket::{self, Deadline, Trust},
    wire::{calls::Call, shape::Shape},
};
use crate::error::{Kcm as Error, KcmStage};

/// How the daemon is reached.
#[derive(Clone, Debug)]
pub(super) struct Endpoint {
    /// The socket path (`kcm_socket`).
    path: PathBuf,
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
            path,
            trust: Trust::new(),
            timeout,
        }
    }

    /// The socket path.
    pub(super) fn path(&self) -> &Path {
        &self.path
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

/// The connection of a store and its handles: connected on first use, dropped
/// after any failure that leaves it out of step, and shared by all calls
/// (one call at a time).
pub(super) struct Session {
    /// How to connect.
    endpoint: Endpoint,
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
    pub(super) const fn new(endpoint: Endpoint) -> Self {
        Self {
            endpoint,
            link: Mutex::new(None),
        }
    }

    /// How the daemon is reached.
    pub(super) const fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// Send `call`, reconnecting once when the daemon closed an idle
    /// connection (a write that fails with a broken pipe).
    ///
    /// # Errors
    ///
    /// The errors of [`Client::call`] and of connecting.
    pub(super) fn call<S>(&self, call: &Call<S>) -> Result<S::Output, Error>
    where
        S: Shape,
    {
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
        let mut reconnected = false;
        loop {
            if link.as_ref().is_none_or(Client::is_broken) {
                let socket = socket::connect(self.endpoint.path(), self.endpoint.trust())?;
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
