//! Fuzz the `DIR` collection readers on arbitrary files.
//!
//! The first input byte selects a split point of the rest: the bytes before
//! it become the collection's `primary` pointer file and the bytes after it
//! become the `tkt` cache file. The `DIR` store then enumerates the
//! collection, resolves its primary cache and loads every cache it lists, and
//! the `FILE` store loads the same cache file. None may panic or allocate from
//! an unbounded field; the pointer read is bounded at one 63-byte line.

#![no_main]

use std::{
    env, fs,
    path::{Path, PathBuf},
    process,
    sync::OnceLock,
};

use libfuzzer_sys::fuzz_target;
use rskrb5_ng::ccache::{CacheVersion, CredentialStore as _, DirStore, FileStore};

/// The private scratch collection of this fuzzing process.
fn collection() -> &'static Path {
    static DIRECTORY: OnceLock<PathBuf> = OnceLock::new();
    DIRECTORY.get_or_init(|| {
        let directory = env::temp_dir().join(format!("rskrb5-fuzz-collection-{}", process::id()));
        drop(fs::create_dir_all(&directory));
        directory
    })
}

fuzz_target!(|data: &[u8]| {
    let Some((&selector, rest)) = data.split_first() else {
        return;
    };
    let (pointer, cache) = rest.split_at(usize::from(selector).min(rest.len()));
    let directory = collection();
    let cache_path = directory.join("tkt");
    if fs::write(directory.join("primary"), pointer).is_err()
        || fs::write(&cache_path, cache).is_err()
    {
        return;
    }
    let store = DirStore::new(CacheVersion::V4);
    if let Ok(collection) = store.collection(&directory.to_string_lossy()) {
        if let Ok(caches) = collection.caches() {
            for listed in caches {
                drop(listed.load());
            }
        }
        if let Ok(primary) = collection.primary() {
            drop(primary.load());
        }
    }
    if let Ok(file) = FileStore::default().resolve(&cache_path.to_string_lossy()) {
        drop(file.load());
    }
});
