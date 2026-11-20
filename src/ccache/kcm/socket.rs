//! The Unix socket of the KCM daemon: trust checks, connecting and deadlines
//! (`kcmio_unix_socket_connect`, `cc_kcm.c:301-342`).
//!
//! # Security
//!
//! MIT connects to whatever the path holds. This client first requires the
//! path to be a socket (not a symbolic link) owned by root, by this process's
//! effective user, or by a user the caller named: another user cannot put a
//! socket where a daemon is expected and be handed tickets. Where the OS
//! exposes the peer's credentials (the Tokio client), the connected peer must
//! meet the same rule. On a platform where this process's effective user
//! cannot be read, only root and the named users are trusted.

use core::time::Duration;
use std::{
    fs, io,
    os::unix::{
        fs::{FileTypeExt as _, MetadataExt as _},
        net::UnixStream,
    },
    path::Path,
    time::Instant,
};

use crate::{
    error::{Kcm as Error, KcmRefusal, KcmStage},
    file_name,
};

/// The stage of a failed connect.
pub(super) const CONNECT: KcmStage = KcmStage::Connect;

/// Which users may own the daemon socket or run the daemon: root, this
/// process's effective user, and the users named here.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Trust {
    /// The extra trusted user ids.
    uids: Vec<u32>,
}

impl Trust {
    /// Root and this process's effective user.
    #[must_use]
    #[inline]
    pub const fn new() -> Self {
        Self { uids: Vec::new() }
    }

    /// Also trust the user `uid` (for example the service account of a
    /// daemon that runs as another user).
    #[must_use]
    #[inline]
    pub fn with_uid(mut self, uid: u32) -> Self {
        self.uids.push(uid);
        self
    }

    /// Whether `uid` may own the socket or run the daemon.
    pub(super) fn allows(&self, uid: u32) -> bool {
        uid == 0
            || self.uids.contains(&uid)
            || file_name::process_identity().is_ok_and(|(_real, effective)| effective == uid)
    }
}

/// Check the socket file at `path` before connecting.
///
/// # Errors
///
/// [`Error::NoServer`] when nothing is there, [`Error::Untrusted`] for a
/// symbolic link, a file that is not a socket or an untrusted owner, and
/// [`Error::Io`] for any other failure to inspect the path.
pub(super) fn validate(path: &Path, trust: &Trust) -> Result<(), Error> {
    let metadata = fs::symlink_metadata(path).map_err(connect_error)?;
    let kind = metadata.file_type();
    let wrong_kind = if kind.is_symlink() {
        Some(KcmRefusal::Symlink)
    } else if !kind.is_socket() {
        Some(KcmRefusal::NotASocket)
    } else {
        None
    };
    if let Some(refusal) = wrong_kind {
        return Err(Error::Untrusted(refusal));
    }
    judge(
        trust,
        metadata.uid(),
        KcmRefusal::UntrustedOwner {
            uid: metadata.uid(),
        },
    )
}

/// Accept `uid` when `trust` allows it, else refuse with `untrusted` (or with
/// [`KcmRefusal::IdentityUnavailable`] when this process's own user is unknown).
///
/// # Errors
///
/// [`Error::Untrusted`].
pub(super) fn judge(trust: &Trust, uid: u32, untrusted: KcmRefusal) -> Result<(), Error> {
    if trust.allows(uid) {
        return Ok(());
    }
    let refusal = if file_name::process_identity().is_err() {
        KcmRefusal::IdentityUnavailable
    } else {
        untrusted
    };
    Err(Error::Untrusted(refusal))
}

/// The error of a failed connect: a missing socket is no server (MIT maps
/// `ENOENT` to `KRB5_KCM_NO_SERVER`, `cc_kcm.c:332`).
pub(super) fn connect_error(source: io::Error) -> Error {
    if source.kind() == io::ErrorKind::NotFound {
        Error::NoServer
    } else {
        Error::Io {
            stage: CONNECT,
            source,
        }
    }
}

/// Connect to the daemon at `path` once its socket passes [`validate`].
///
/// # Errors
///
/// The errors of [`validate`] and [`Error::Io`] when connecting fails.
pub(super) fn connect(path: &Path, trust: &Trust) -> Result<Deadline, Error> {
    validate(path, trust)?;
    let stream = UnixStream::connect(path).map_err(connect_error)?;
    Ok(Deadline {
        stream,
        deadline: None,
    })
}

/// A socket whose every read and write is bounded by one deadline, so that a
/// peer that sends a byte at a time cannot extend a call forever.
#[derive(Debug)]
pub(super) struct Deadline {
    /// The connection.
    stream: UnixStream,
    /// When the current call must be finished.
    deadline: Option<Instant>,
}

impl Deadline {
    /// Give the next call `budget` from now.
    pub(super) fn arm(&mut self, budget: Duration) {
        self.deadline = Instant::now().checked_add(budget);
    }

    /// The time left, or a timeout error when none is.
    ///
    /// # Errors
    ///
    /// [`io::ErrorKind::TimedOut`] once the deadline has passed.
    fn remaining(&self) -> io::Result<Option<Duration>> {
        self.deadline.map_or(Ok(None), |end| {
            let left = end.saturating_duration_since(Instant::now());
            if left.is_zero() {
                Err(io::ErrorKind::TimedOut.into())
            } else {
                Ok(Some(left))
            }
        })
    }
}

/// macOS refuses to set a socket timeout with `EINVAL` once the peer has
/// closed the connection; the read or write that follows cannot block then,
/// and reports the closed peer itself.
///
/// # Errors
///
/// Any other failure of `result`.
fn tolerate_closed_peer(result: io::Result<()>) -> io::Result<()> {
    match result {
        Err(error) if error.kind() == io::ErrorKind::InvalidInput => Ok(()),
        other => other,
    }
}

/// An expired socket timeout reads as `WouldBlock` on Unix; call it a timeout.
fn timed_out(error: io::Error) -> io::Error {
    if error.kind() == io::ErrorKind::WouldBlock {
        io::ErrorKind::TimedOut.into()
    } else {
        error
    }
}

impl io::Read for Deadline {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let left = self.remaining()?;
        tolerate_closed_peer(self.stream.set_read_timeout(left))?;
        self.stream.read(buf).map_err(timed_out)
    }
}

impl io::Write for Deadline {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let left = self.remaining()?;
        tolerate_closed_peer(self.stream.set_write_timeout(left))?;
        self.stream.write(buf).map_err(timed_out)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests;
