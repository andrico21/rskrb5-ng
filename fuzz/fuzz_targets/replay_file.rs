//! Fuzz the replay-cache file reader and the replay-cache names.
//!
//! The first input byte selects the entry point. Mode 0 treats the rest as the
//! bytes of an existing MIT `file2` cache file (a seed, hash tables, records,
//! possibly truncated or hostile) and presents two tags to a store over it:
//! the store must answer `Ok` or a typed error, never panic, never accept the
//! same tag twice in a row, and never lose a record it just wrote. Mode 1
//! parses the rest as a cache name (`dfl:`, `file2:<path>`, `none:`, `memory:`).

#![no_main]

use std::{
    io,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, UNIX_EPOCH},
};

use libfuzzer_sys::fuzz_target;
use rskrb5_ng::{
    replay::{
        Admission, Evidence, File2ReplayStore, FileSystem, OpenFile, Presentation, RcacheName,
        Store, Tag,
    },
    service::Principal,
};

/// A file system whose one file holds the fuzzed bytes.
#[derive(Debug)]
struct Fuzzed {
    /// The shared file contents.
    bytes: Arc<Mutex<Vec<u8>>>,
}

/// The open handle.
struct Handle {
    /// The shared file contents.
    bytes: Arc<Mutex<Vec<u8>>>,
}

impl FileSystem for Fuzzed {
    fn open_locked(&self, _path: &Path, _private: bool) -> io::Result<Box<dyn OpenFile>> {
        Ok(Box::new(Handle {
            bytes: Arc::clone(&self.bytes),
        }))
    }
}

impl OpenFile for Handle {
    fn size(&mut self) -> io::Result<u64> {
        let bytes = self.bytes.lock().map_err(|_| io::Error::other("lock"))?;
        Ok(u64::try_from(bytes.len()).unwrap_or(u64::MAX))
    }

    fn read_at(&mut self, offset: u64, buffer: &mut [u8]) -> io::Result<usize> {
        let bytes = self.bytes.lock().map_err(|_| io::Error::other("lock"))?;
        let start = usize::try_from(offset).unwrap_or(usize::MAX);
        let available = bytes.get(start..).unwrap_or_default();
        let count = available.len().min(buffer.len());
        if let (Some(target), Some(source)) = (buffer.get_mut(..count), available.get(..count)) {
            target.copy_from_slice(source);
        }
        Ok(count)
    }

    fn write_at(&mut self, offset: u64, data: &[u8]) -> io::Result<()> {
        let mut bytes = self.bytes.lock().map_err(|_| io::Error::other("lock"))?;
        let start = usize::try_from(offset).map_err(|_| io::Error::other("offset"))?;
        let end = start
            .checked_add(data.len())
            .filter(|end| *end <= 0x0100_0000)
            .ok_or_else(|| io::Error::other("too large"))?;
        if bytes.len() < end {
            bytes.resize(end, 0);
        }
        if let Some(target) = bytes.get_mut(start..end) {
            target.copy_from_slice(data);
        }
        Ok(())
    }

    fn sync(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Evidence for `tag` presented at a fixed time.
fn evidence(tag: &[u8]) -> Evidence {
    let service = Principal::new("R".to_owned(), 1, vec!["s".to_owned()]);
    let client = Principal::new("R".to_owned(), 1, vec!["c".to_owned()]);
    Evidence::new(
        Tag::from_checksum(tag),
        [0; 32],
        Presentation::new(service, client, 0, 0),
    )
    .with_window(
        UNIX_EPOCH + Duration::from_secs(1_800_000_000),
        Duration::from_secs(300),
    )
}

/// Present two tags to a store over `file`.
///
/// # Panics
///
/// Panics when a tag the store just accepted is accepted again.
fn file_mode(file: &[u8]) {
    let bytes = Arc::new(Mutex::new(file.to_vec()));
    let store = File2ReplayStore::new(PathBuf::from("fuzz"))
        .with_file_system(Arc::new(Fuzzed { bytes }))
        .with_maximum_bytes(0x0010_0000);
    for tag in [&b"fuzz tag one"[..], &b"fuzz tag two"[..]] {
        if let Ok(Admission::Fresh) = store.admit(&evidence(tag)) {
            assert!(
                !matches!(store.admit(&evidence(tag)), Ok(Admission::Fresh)),
                "a fresh tag was accepted twice"
            );
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((selector, input)) = data.split_first() else {
        return;
    };
    match selector & 1 {
        0 => file_mode(input),
        _ => {
            if let Ok(text) = core::str::from_utf8(input) {
                drop(RcacheName::parse(text));
            }
        }
    }
});
