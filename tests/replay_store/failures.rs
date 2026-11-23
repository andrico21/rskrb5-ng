//! Fail-closed behaviour: I/O errors, a full disk, a crash, corruption and a full file.

use alloc::sync::Arc;
use core::time::Duration;
use std::{io::ErrorKind, path::PathBuf, time::UNIX_EPOCH};

use rskrb5_ng::{
    error::Replay as Error,
    replay::{Admission, Evidence, File2ReplayStore, MemoryReplayStore, Presentation, Store},
    service::Principal,
};

use crate::context::TestError;
use super::{
    support::{Fault, MemoryFs, SKEW, evidence, tag_of},
};

/// A store on a fresh in-memory file.
fn fresh() -> (File2ReplayStore, MemoryFs) {
    over(MemoryFs::default())
}

/// A store over the given in-memory file.
fn over(files: MemoryFs) -> (File2ReplayStore, MemoryFs) {
    let store = File2ReplayStore::new(PathBuf::from("memory"))
        .with_file_system(Arc::new(files.clone()));
    (store, files)
}

/// Pins that a failed open is a typed error and records nothing.
#[test]
fn an_open_failure_is_a_typed_error() -> Result<(), TestError> {
    let (store, files) = fresh();
    files.inject(Fault::Open(ErrorKind::PermissionDenied))?;

    let outcome = store.admit(&evidence(1, 1_000_000)?);

    assert!(matches!(outcome, Err(Error::Io { operation: "open", .. })), "{outcome:?}");
    assert_eq!(store.admit(&evidence(1, 1_000_000)?)?, Admission::Fresh);
    Ok(())
}

/// Pins that a failed read is a typed error, never an acceptance.
#[test]
fn a_read_failure_is_a_typed_error() -> Result<(), TestError> {
    let (store, files) = fresh();
    assert_eq!(store.admit(&evidence(1, 1_000_000)?)?, Admission::Fresh);
    files.inject(Fault::Read(ErrorKind::InvalidData))?;

    let outcome = store.admit(&evidence(1, 1_000_000)?);

    assert!(matches!(outcome, Err(Error::Io { operation: "read", .. })), "{outcome:?}");
    Ok(())
}

/// Pins that a full disk refuses the authenticator and records nothing.
#[test]
fn a_full_disk_refuses_the_authenticator() -> Result<(), TestError> {
    let (store, files) = fresh();
    files.inject(Fault::Write(ErrorKind::StorageFull))?;

    let outcome = store.admit(&evidence(7, 1_000_000)?);

    assert!(matches!(outcome, Err(Error::Io { operation: "write", .. })), "{outcome:?}");
    assert_eq!(store.admit(&evidence(7, 1_000_000)?)?, Admission::Fresh);
    Ok(())
}

/// Pins that a crash between the write and the sync refuses the request, and the persisted record still stops a replay.
#[test]
fn a_crash_between_write_and_sync_never_admits_twice() -> Result<(), TestError> {
    let (store, files) = fresh();
    files.inject(Fault::Sync(ErrorKind::Other))?;

    let outcome = store.admit(&evidence(9, 1_000_000)?);

    assert!(matches!(outcome, Err(Error::Io { operation: "sync", .. })), "{outcome:?}");
    let restarted = File2ReplayStore::new(PathBuf::from("memory"))
        .with_file_system(Arc::new(files.clone()));
    assert_eq!(restarted.admit(&evidence(9, 1_000_000)?)?, Admission::Replayed);
    Ok(())
}

/// Pins that a torn record fails closed on the next open instead of being trusted or overwritten.
#[test]
fn a_torn_record_fails_closed_on_the_next_use() -> Result<(), TestError> {
    let (store, files) = over(MemoryFs::with_bytes(&[0_u8; 16]));
    files.inject(Fault::Torn(7))?;
    let first = store.admit(&evidence(3, 1_000_000)?);
    assert!(matches!(first, Err(Error::Io { operation: "write", .. })), "{first:?}");

    let second = store.admit(&evidence(4, 1_000_000)?);

    assert!(matches!(second, Err(Error::Corrupt { .. })), "{second:?}");
    Ok(())
}

/// Pins that a file shorter than the hash seed is corrupt.
#[test]
fn a_file_shorter_than_the_seed_is_corrupt() -> Result<(), TestError> {
    let (store, _files) = over(MemoryFs::with_bytes(&[1, 2, 3, 4, 5]));

    let outcome = store.admit(&evidence(1, 1_000_000)?);

    assert!(matches!(outcome, Err(Error::Corrupt { .. })), "{outcome:?}");
    Ok(())
}

/// Pins that a file ending inside a record is corrupt.
#[test]
fn a_file_ending_inside_a_record_is_corrupt() -> Result<(), TestError> {
    let (store, _files) = over(MemoryFs::with_bytes(&[0_u8; 16 + 16 + 9]));

    let outcome = store.admit(&evidence(1, 1_000_000)?);

    assert!(matches!(outcome, Err(Error::Corrupt { .. })), "{outcome:?}");
    Ok(())
}

/// Pins that a presentation time that has no 32-bit timestamp is refused.
#[test]
fn an_unrepresentable_time_is_refused() -> Result<(), TestError> {
    let (store, _files) = fresh();
    let service = Principal::new("R".to_owned(), 1, vec!["s".to_owned()]);
    let client = Principal::new("R".to_owned(), 1, vec!["c".to_owned()]);
    for seconds in [0_u64, u64::from(u32::MAX) + 1] {
        let at = UNIX_EPOCH
            .checked_add(Duration::from_secs(seconds))
            .ok_or("representable")?;
        let presentation = Presentation::new(service.clone(), client.clone(), 0, 0);
        let candidate = Evidence::new(tag_of(0), [0; 32], presentation).with_window(at, SKEW);

        let outcome = store.admit(&candidate);

        assert!(matches!(outcome, Err(Error::TimeOutOfRange)), "{seconds}: {outcome:?}");
    }
    Ok(())
}

/// Pins that a file that cannot grow refuses new evidence and never evicts live evidence.
#[test]
fn a_full_file_refuses_new_evidence_and_keeps_the_old() -> Result<(), TestError> {
    let (store, _files) = fresh();
    let store = store.with_maximum_bytes(16 + 1023 * 16);
    let mut admitted = 0_u32;
    let mut refused = None;

    for index in 0..4000_u32 {
        match store.admit(&evidence(index, 1_000_000)?) {
            Ok(Admission::Fresh) => admitted += 1,
            Ok(Admission::Replayed) => return Err("distinct tags never collide".into()),
            Err(error) => {
                refused = Some((index, error));
                break;
            }
            Ok(_) => return Err("unknown admission".into()),
        }
    }

    let (index, error) = refused.ok_or("the file never filled")?;
    assert!(matches!(error, Error::FileFull { maximum_bytes: 16400 }), "{error:?}");
    assert_eq!(admitted, index);
    assert!(admitted > 500, "a table of 1023 slots filled after only {admitted}");
    for kept in 0..admitted {
        assert_eq!(store.admit(&evidence(kept, 1_000_000)?)?, Admission::Replayed);
    }
    Ok(())
}

/// Pins that a full memory store refuses new evidence instead of evicting.
#[test]
fn a_full_memory_store_refuses_and_never_evicts() -> Result<(), TestError> {
    let store = MemoryReplayStore::with_limits(SKEW, 2);
    let mut live = Vec::new();
    for index in 0..8_u32 {
        match store.admit(&evidence(index, 1_000_000)?) {
            Ok(Admission::Fresh) => live.push(index),
            Ok(Admission::Replayed) => return Err("distinct evidence is never a replay".into()),
            Err(Error::Capacity { .. }) => {}
            Err(other) => return Err(other.into()),
            Ok(_) => return Err("unknown admission".into()),
        }
    }

    assert!(!live.is_empty() && live.len() <= 2, "{live:?}");
    for index in live {
        assert_eq!(store.admit(&evidence(index, 1_000_000)?)?, Admission::Replayed);
    }
    Ok(())
}
