//! Replay stores: the evidence an acceptor keeps to refuse a second presentation.
//!
//! A [`Store`] decides whether one authenticator was seen before. Three
//! stores ship: [`MemoryReplayStore`] (bounded, in process), [`File2ReplayStore`]
//! (MIT `file2` and `dfl` compatible, shared by every process that opens the
//! same file under an exclusive file lock) and [`NoneReplayStore`] (MIT `none`,
//! only by deliberate opt-out). [`RcacheName`] parses the MIT cache names
//! (`dfl:`, `file2:<path>`, `none:`, plus `memory:`) and `default_rcache_name`.
//!
//! # Security
//!
//! Every store fails closed: an I/O error, a full file, a corrupt or truncated
//! file or a poisoned lock is a typed [`crate::error::Replay`], never an
//! accepted authenticator. No store evicts evidence that is still live.
//! Retention covers three times the validator's clock skew (the window in which
//! a future-dated or rolled-back clock sample could still accept the
//! authenticator), where MIT's `file2` keeps one skew; a record is overwritten
//! only after that.
//!
//! # Scoping and restart
//!
//! Evidence is scoped by the store, not by the service: every acceptor that
//! opens the same file shares one set of records, whichever service principal
//! it accepts for (the tag is the checksum of the authenticator ciphertext).
//! A [`File2ReplayStore`] survives a restart of the process and of the machine,
//! because every record is synced before the authenticator is accepted; a
//! [`MemoryReplayStore`] does not, so an acceptor that must refuse replays
//! across restarts needs a file store. [`NoneReplayStore`] keeps nothing.

#[cfg(feature = "messages")]
use alloc::sync::Arc;
#[cfg(feature = "messages")]
use core::{fmt::Debug, time::Duration};
#[cfg(feature = "messages")]
use std::{
    io,
    path::{Path, PathBuf},
    time::SystemTime,
};

use crate::error::Replay as Error;
#[cfg(feature = "messages")]
use crate::service::{Principal, SharedReplayCache};

#[cfg(feature = "messages")]
mod dfl;
#[cfg(feature = "messages")]
mod evidence;
#[cfg(feature = "messages")]
mod file2;
#[cfg(feature = "messages")]
mod files;
#[cfg(feature = "messages")]
mod memory;
mod name;
#[cfg(feature = "messages")]
mod none;
#[cfg(feature = "messages")]
mod siphash;
#[cfg(feature = "messages")]
mod table;

pub use name::RcacheName;

/// Length in bytes of a replay tag (MIT `TAG_LEN`, `rc_file2.c:42`).
#[cfg(feature = "messages")]
pub const TAG_LEN: usize = 12;

/// The tag MIT derives from an authenticator's ciphertext.
///
/// It is the checksum part (`rc_base.c:k5_rc_tag_from_ciphertext`,
/// `rc_file2.c:211-218`), truncated or right-padded with zero bytes to
/// [`TAG_LEN`] bytes.
#[cfg(feature = "messages")]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub struct Tag {
    /// The twelve tag bytes.
    bytes: [u8; TAG_LEN],
}

/// The RFC 4120 section 3.2.3 identity of one authenticator.
#[cfg(feature = "messages")]
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Presentation {
    /// The accepting service.
    pub service: Principal,
    /// The authenticator's client.
    pub client: Principal,
    /// The authenticator's `ctime`, in seconds since the Unix epoch.
    pub ctime_seconds: i64,
    /// The authenticator's `cusec`.
    pub cusec: u32,
}

/// Everything a store may use to recognise one presented authenticator.
///
/// The memory store keys on the [`Presentation`] and the digest; the file
/// stores keep only the MIT [`Tag`], as MIT's format has no other field.
#[cfg(feature = "messages")]
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Evidence {
    /// The MIT replay tag of the authenticator ciphertext.
    pub tag: Tag,
    /// SHA-256 of the authenticator ciphertext.
    pub digest: [u8; 32],
    /// The RFC 4120 replay key.
    pub presentation: Presentation,
    /// The validation time of this presentation.
    pub presented_at: SystemTime,
    /// The validator's accepted clock skew.
    pub skew: Duration,
}

/// The outcome of recording one presentation.
#[cfg(feature = "messages")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Admission {
    /// First presentation: the evidence is now recorded.
    Fresh,
    /// The evidence was already recorded: refuse the authenticator.
    Replayed,
}

/// A replay store shared by every validator that holds it.
///
/// # Security
///
/// `admit` is atomic: of concurrent presentations of one authenticator, in this
/// process or (for file stores) another, exactly one returns
/// [`Admission::Fresh`]. An error means freshness is unproven; the caller must
/// refuse the authenticator.
#[cfg(feature = "messages")]
pub trait Store: Debug + Send + Sync {
    /// Record one presentation, or report it as a replay.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] when the evidence cannot be proven fresh: policy,
    /// capacity, I/O or corruption.
    fn admit(&self, evidence: &Evidence) -> Result<Admission, Error>;

    /// Check that this store's retention covers a validator's clock skew.
    ///
    /// # Errors
    ///
    /// Returns [`Error::SkewExceeded`] for a skew beyond the store's ceiling.
    #[inline]
    fn ensure_skew(&self, _requested: Duration) -> Result<(), Error> {
        Ok(())
    }
}

/// The in-process store: bounded, never evicting live evidence.
///
/// A clone shares the same evidence.
#[cfg(feature = "messages")]
#[derive(Clone, Debug, Default)]
pub struct MemoryReplayStore {
    /// The shared cache behind every clone.
    cache: SharedReplayCache,
}

/// MIT `none`: no replay protection at all.
///
/// # Security
///
/// Accepts every presentation. Use only to opt out deliberately, for example
/// behind a front end that already refuses replays.
#[cfg(feature = "messages")]
#[derive(Clone, Copy, Debug, Default)]
#[non_exhaustive]
pub struct NoneReplayStore;

/// A persistent store in the MIT `file2` format (MIT 1.22.2 `rc_file2.c`).
///
/// Every access takes an exclusive file lock ([`std::fs::File::lock`]), so any
/// number of processes, MIT's own libraries included, can share one file.
#[cfg(feature = "messages")]
#[derive(Clone, Debug)]
pub struct File2ReplayStore {
    /// The cache file.
    path: PathBuf,
    /// The files the file is opened through.
    files: Arc<dyn FileSystem>,
    /// Upper bound on the file size; a full file refuses new evidence.
    maximum_bytes: u64,
    /// Whether the owner and symlink checks of MIT's `dfl` type apply.
    private_file: bool,
}

/// How a cache file is opened, locked, read and written.
///
/// The operating-system implementation is [`OsFileSystem`]; tests inject faults
/// through their own implementation.
#[cfg(feature = "messages")]
pub trait FileSystem: Debug + Send + Sync {
    /// Open the file, creating it owner-only when absent, and take an
    /// exclusive lock that the returned handle releases when dropped.
    ///
    /// # Errors
    ///
    /// Returns the I/O error of opening or locking.
    fn open_locked(&self, path: &Path, private_file: bool) -> io::Result<Box<dyn OpenFile>>;
}

/// One open, exclusively locked cache file.
#[cfg(feature = "messages")]
pub trait OpenFile {
    /// The file length in bytes.
    ///
    /// # Errors
    ///
    /// Returns the I/O error of the query.
    fn size(&mut self) -> io::Result<u64>;

    /// Read up to `buffer.len()` bytes at `offset`; fewer only at end of file.
    ///
    /// # Errors
    ///
    /// Returns the I/O error of the read.
    fn read_at(&mut self, offset: u64, buffer: &mut [u8]) -> io::Result<usize>;

    /// Write all of `data` at `offset`, extending the file when needed.
    ///
    /// # Errors
    ///
    /// Returns the I/O error of the write, such as a full disk.
    fn write_at(&mut self, offset: u64, data: &[u8]) -> io::Result<()>;

    /// Make every written byte durable.
    ///
    /// # Errors
    ///
    /// Returns the I/O error of the sync.
    fn sync(&mut self) -> io::Result<()>;
}

/// The operating-system [`FileSystem`]: a regular file with `File::lock`.
#[cfg(feature = "messages")]
#[derive(Clone, Copy, Debug, Default)]
#[non_exhaustive]
pub struct OsFileSystem;
