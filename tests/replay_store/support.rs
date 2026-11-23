//! Shared test material: evidence builders, a temporary directory and a fault-injecting file system.

use alloc::sync::Arc;
use core::time::Duration;
use std::{
    fs, io,
    path::{Path, PathBuf},
    process,
    sync::{
        Mutex,
        atomic::{AtomicU32, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

use rskrb5_ng::{
    replay::{Evidence, FileSystem, OpenFile, Presentation, Tag},
    service::Principal,
};
use sha2::{Digest as _, Sha256};

use crate::context::{Context as _, TestError};

/// The retention of three times a 900 s skew, as the layout model uses.
pub(super) const SKEW: Duration = Duration::from_secs(900);

/// The tag the reference model derives for index `index`.
pub(super) fn tag_of(index: u32) -> Tag {
    let digest = Sha256::digest(format!("rskrb5-ng replay tag {index}"));
    Tag::from_checksum(digest.as_slice())
}

/// Evidence for tag `index` presented at `seconds` since the Unix epoch.
pub(super) fn evidence(index: u32, seconds: u64) -> Result<Evidence, TestError> {
    let at = UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds))
        .context("time is representable")?;
    let service = Principal::new("EXAMPLE.TEST".to_owned(), 1, vec!["HTTP".to_owned()]);
    let client = Principal::new("EXAMPLE.TEST".to_owned(), 1, vec![format!("user{index}")]);
    let presentation = Presentation::new(service, client, i64::try_from(seconds)?, index);
    let digest: [u8; 32] = Sha256::digest(index.to_be_bytes()).into();
    Ok(Evidence::new(tag_of(index), digest, presentation).with_window(at, SKEW))
}

/// A temporary directory removed on drop.
pub(super) struct TempDir {
    /// The directory.
    path: PathBuf,
}

impl TempDir {
    /// Create a fresh directory named for `label`.
    pub(super) fn new(label: &str) -> Result<Self, TestError> {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let number = NEXT.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let path = std::env::temp_dir().join(format!(
            "rskrb5-replay-{label}-{}-{nanos}-{number}",
            process::id()
        ));
        fs::create_dir_all(&path).context("temporary directory is created")?;
        Ok(Self { path })
    }

    /// The directory.
    pub(super) fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _removed: Result<(), io::Error> = fs::remove_dir_all(&self.path);
    }
}

/// One fault the in-memory file system injects, once.
#[derive(Clone, Copy, Debug)]
pub(super) enum Fault {
    /// Opening fails.
    Open(io::ErrorKind),
    /// The next read fails.
    Read(io::ErrorKind),
    /// The next write fails before writing anything (a full disk).
    Write(io::ErrorKind),
    /// The next write stores this many bytes, then fails (a crash mid-write).
    Torn(u8),
    /// The next sync fails after the write succeeded (a crash before the sync).
    Sync(io::ErrorKind),
}

/// File bytes and the fault still to inject.
#[derive(Debug, Default)]
struct State {
    /// The file contents.
    bytes: Vec<u8>,
    /// The pending fault.
    fault: Option<Fault>,
}

/// An in-memory [`FileSystem`] with fault injection; clones share one file.
#[derive(Clone, Debug, Default)]
pub(super) struct MemoryFs {
    /// The shared file.
    state: Arc<Mutex<State>>,
}

impl MemoryFs {
    /// A file system whose file already holds `bytes`.
    pub(super) fn with_bytes(bytes: &[u8]) -> Self {
        Self {
            state: Arc::new(Mutex::new(State {
                bytes: bytes.to_vec(),
                fault: None,
            })),
        }
    }

    /// Inject `fault` into the next matching operation.
    pub(super) fn inject(&self, fault: Fault) -> Result<(), TestError> {
        self.state
            .lock()
            .map_err(|_poisoned| "state lock")?
            .fault = Some(fault);
        Ok(())
    }

    /// A copy of the file contents.
    pub(super) fn bytes(&self) -> Result<Vec<u8>, TestError> {
        Ok(self
            .state
            .lock()
            .map_err(|_poisoned| "state lock")?
            .bytes
            .clone())
    }
}

/// The open handle of a [`MemoryFs`].
struct Handle {
    /// The shared file.
    state: Arc<Mutex<State>>,
}

/// Locks the state, mapping poisoning to an I/O error.
fn locked(state: &Mutex<State>) -> io::Result<std::sync::MutexGuard<'_, State>> {
    state.lock().map_err(|_poisoned| io::Error::other("state lock"))
}

impl FileSystem for MemoryFs {
    fn open_locked(&self, _path: &Path, _private: bool) -> io::Result<Box<dyn OpenFile>> {
        let mut state = locked(&self.state)?;
        if let Some(Fault::Open(kind)) = state.fault.take_if(|fault| matches!(fault, Fault::Open(_)))
        {
            return Err(io::Error::from(kind));
        }
        Ok(Box::new(Handle {
            state: Arc::clone(&self.state),
        }))
    }
}

impl OpenFile for Handle {
    fn size(&mut self) -> io::Result<u64> {
        Ok(u64::try_from(locked(&self.state)?.bytes.len()).unwrap_or(u64::MAX))
    }

    fn read_at(&mut self, offset: u64, buffer: &mut [u8]) -> io::Result<usize> {
        let mut state = locked(&self.state)?;
        if let Some(Fault::Read(kind)) = state.fault.take_if(|fault| matches!(fault, Fault::Read(_)))
        {
            return Err(io::Error::from(kind));
        }
        let start = usize::try_from(offset).unwrap_or(usize::MAX);
        let available = state.bytes.get(start..).unwrap_or_default();
        let count = available.len().min(buffer.len());
        if let (Some(target), Some(source)) = (buffer.get_mut(..count), available.get(..count)) {
            target.copy_from_slice(source);
        }
        Ok(count)
    }

    fn write_at(&mut self, offset: u64, data: &[u8]) -> io::Result<()> {
        let mut state = locked(&self.state)?;
        let start = usize::try_from(offset).unwrap_or(usize::MAX);
        let mut keep = data.len();
        let mut failure = None;
        match state.fault {
            Some(Fault::Write(kind)) => {
                state.fault = None;
                return Err(io::Error::from(kind));
            }
            Some(Fault::Torn(bytes)) => {
                state.fault = None;
                keep = usize::from(bytes).min(data.len());
                failure = Some(io::Error::other("torn write"));
            }
            Some(Fault::Open(_) | Fault::Read(_) | Fault::Sync(_)) | None => {}
        }
        let end = start.checked_add(keep).ok_or_else(|| io::Error::other("offset"))?;
        if state.bytes.len() < end {
            state.bytes.resize(end, 0);
        }
        if let (Some(target), Some(source)) = (state.bytes.get_mut(start..end), data.get(..keep)) {
            target.copy_from_slice(source);
        }
        failure.map_or(Ok(()), Err)
    }

    fn sync(&mut self) -> io::Result<()> {
        let mut state = locked(&self.state)?;
        if let Some(Fault::Sync(kind)) = state.fault.take_if(|fault| matches!(fault, Fault::Sync(_)))
        {
            return Err(io::Error::from(kind));
        }
        Ok(())
    }
}
