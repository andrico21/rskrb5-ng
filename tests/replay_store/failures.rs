//! Fail-closed behaviour: I/O errors, a full disk, a crash, corruption and a full file.

use alloc::sync::Arc;
use core::time::Duration;
use std::{io::ErrorKind, path::PathBuf, time::UNIX_EPOCH};

use rskrb5_ng::{
    error::Replay as Error,
    replay::{Admission, Evidence, File2ReplayStore, MemoryReplayStore, Presentation, Store as _},
    service::Principal,
};

use super::support::{Fault, MemoryFs, SKEW, evidence, evidence_with_skew, tag_of};
use crate::context::TestError;

/// A store on a fresh in-memory file.
fn fresh() -> (File2ReplayStore, MemoryFs) {
    over(MemoryFs::default())
}

/// A store over the given in-memory file.
fn over(files: MemoryFs) -> (File2ReplayStore, MemoryFs) {
    let store =
        File2ReplayStore::new(PathBuf::from("memory")).with_file_system(Arc::new(files.clone()));
    (store, files)
}

/// Pins that a failed open is a typed error and records nothing.
#[test]
fn an_open_failure_is_a_typed_error() -> Result<(), TestError> {
    let (store, files) = fresh();
    files.inject(Fault::Open(ErrorKind::PermissionDenied))?;

    let outcome = store.admit(&evidence(1, 1_000_000)?);

    assert!(
        matches!(
            outcome,
            Err(Error::Io {
                operation: "open",
                path: _,
                source: _
            })
        ),
        "{outcome:?}"
    );
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

    assert!(
        matches!(
            outcome,
            Err(Error::Io {
                operation: "read",
                path: _,
                source: _
            })
        ),
        "{outcome:?}"
    );
    Ok(())
}

/// Pins that a full disk refuses the authenticator and records nothing.
#[test]
fn a_full_disk_refuses_the_authenticator() -> Result<(), TestError> {
    let (store, files) = fresh();
    files.inject(Fault::Write(ErrorKind::StorageFull))?;

    let outcome = store.admit(&evidence(7, 1_000_000)?);

    assert!(
        matches!(
            outcome,
            Err(Error::Io {
                operation: "write",
                path: _,
                source: _
            })
        ),
        "{outcome:?}"
    );
    assert_eq!(store.admit(&evidence(7, 1_000_000)?)?, Admission::Fresh);
    Ok(())
}

/// Pins that a crash between the write and the sync refuses the request, and the persisted record still stops a replay.
#[test]
fn a_crash_between_write_and_sync_never_admits_twice() -> Result<(), TestError> {
    let (store, files) = fresh();
    files.inject(Fault::Sync(ErrorKind::Other))?;

    let outcome = store.admit(&evidence(9, 1_000_000)?);

    assert!(
        matches!(
            outcome,
            Err(Error::Io {
                operation: "sync",
                path: _,
                source: _
            })
        ),
        "{outcome:?}"
    );
    let restarted =
        File2ReplayStore::new(PathBuf::from("memory")).with_file_system(Arc::new(files));
    assert_eq!(
        restarted.admit(&evidence(9, 1_000_000)?)?,
        Admission::Replayed
    );
    Ok(())
}

/// Pins that a torn record fails closed on the next open instead of being trusted or overwritten.
#[test]
fn a_torn_record_fails_closed_on_the_next_use() -> Result<(), TestError> {
    let (store, files) = over(MemoryFs::with_bytes(&[0_u8; 16]));
    files.inject(Fault::Torn(7))?;
    let first = store.admit(&evidence(3, 1_000_000)?);
    assert!(
        matches!(
            first,
            Err(Error::Io {
                operation: "write",
                path: _,
                source: _
            })
        ),
        "{first:?}"
    );

    let second = store.admit(&evidence(4, 1_000_000)?);

    assert!(
        matches!(second, Err(Error::Corrupt { path: _, reason: _ })),
        "{second:?}"
    );
    Ok(())
}

/// Pins that a file shorter than the hash seed is corrupt.
#[test]
fn a_file_shorter_than_the_seed_is_corrupt() -> Result<(), TestError> {
    let (store, _files) = over(MemoryFs::with_bytes(&[1, 2, 3, 4, 5]));

    let outcome = store.admit(&evidence(1, 1_000_000)?);

    assert!(
        matches!(outcome, Err(Error::Corrupt { path: _, reason: _ })),
        "{outcome:?}"
    );
    Ok(())
}

/// Pins that a file ending inside a record is corrupt.
#[test]
fn a_file_ending_inside_a_record_is_corrupt() -> Result<(), TestError> {
    let (store, _files) = over(MemoryFs::with_bytes(&[0_u8; 16 + 16 + 9]));

    let outcome = store.admit(&evidence(1, 1_000_000)?);

    assert!(
        matches!(outcome, Err(Error::Corrupt { path: _, reason: _ })),
        "{outcome:?}"
    );
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
        let presentation = Presentation::new(service.clone(), client.clone(), 0, 0_u32);
        let candidate = Evidence::new(tag_of(0), [0; 32], presentation).with_window(at, SKEW);

        let outcome = store.admit(&candidate);

        assert!(
            matches!(outcome, Err(Error::TimeOutOfRange)),
            "{seconds}: {outcome:?}"
        );
    }
    Ok(())
}

/// Fill the first table of the file `files` until it refuses and check what holds for EVERY hash seed.
///
/// The seed of a new file is random, so the slot placement and the index of the first refused tag
/// differ from run to run (a 2-slot bucket can fill after only a few tags). The checks therefore
/// name no count: the refusal is `FileFull` with the exact bound, `admitted` equals the index of
/// the refused tag, the first tag was admitted, and every admitted tag is still a replay.
fn assert_a_full_file_refuses_and_keeps_the_old(files: MemoryFs) -> Result<(), TestError> {
    let (unbounded, _files) = over(files);
    let store = unbounded.with_maximum_bytes(16 + 1023 * 16);
    let first_table_end = 16 + 1023 * 16_u64;
    let mut admitted = 0_u32;
    let mut refused = None;

    for index in 0..4000_u32 {
        match store.admit(&evidence(index, 1_000_000)?) {
            Ok(Admission::Fresh) => admitted = admitted.saturating_add(1),
            Ok(Admission::Replayed) => return Err("distinct tags never collide".into()),
            Err(error) => {
                refused = Some((index, error));
                break;
            }
            Ok(_) => return Err("unknown admission".into()),
        }
    }

    let (index, error) = refused.ok_or("the file never filled")?;
    assert!(
        matches!(error, Error::FileFull { maximum_bytes } if maximum_bytes == first_table_end),
        "{error:?}"
    );
    assert_eq!(admitted, index);
    assert!(admitted >= 1, "an empty file refused its first tag");
    for kept in 0..admitted {
        assert_eq!(
            store.admit(&evidence(kept, 1_000_000)?)?,
            Admission::Replayed
        );
    }
    Ok(())
}

/// Pins that a file that cannot grow refuses new evidence and never evicts live evidence.
#[test]
fn a_full_file_refuses_new_evidence_and_keeps_the_old() -> Result<(), TestError> {
    assert_a_full_file_refuses_and_keeps_the_old(MemoryFs::default())
}

/// Pins the same refusal for 64 fixed hash seeds, so the placement is reproducible and the
/// invariants are checked for many different first-refusal indexes on every run.
#[test]
fn a_full_file_refuses_and_keeps_the_old_for_every_seed() -> Result<(), TestError> {
    for number in 0..64_u32 {
        let seed: Vec<u8> = tag_of(number)
            .as_bytes()
            .iter()
            .copied()
            .chain(number.to_be_bytes())
            .collect();
        assert_eq!(seed.len(), 16);
        assert_a_full_file_refuses_and_keeps_the_old(MemoryFs::with_bytes(&seed))?;
    }
    Ok(())
}

/// Pins that a file that cannot grow recycles an EXPIRED slot (never a live one): once the retention
/// has passed, a new tag is admitted into the first table instead of being refused as full.
#[test]
fn an_expired_slot_is_reused_when_the_file_cannot_grow() -> Result<(), TestError> {
    let (unbounded, _files) = fresh();
    let store = unbounded.with_maximum_bytes(16 + 1023 * 16);
    let mut first_refused = None;
    for index in 0..4000_u32 {
        match store.admit(&evidence(index, 1_000_000)?) {
            Ok(Admission::Fresh) => {}
            Ok(Admission::Replayed) => return Err("distinct tags never collide".into()),
            Err(Error::FileFull { maximum_bytes: _ }) => {
                first_refused = Some(index);
                break;
            }
            Err(other) => return Err(other.into()),
            Ok(_) => return Err("unknown admission".into()),
        }
    }
    let refused = first_refused.ok_or("the file never filled")?;
    let live_at = 1_000_000 + 3 * 900;
    let expired_at = live_at + 1;

    let while_live = store.admit(&evidence(refused, live_at)?);
    let after = store.admit(&evidence(refused, expired_at)?)?;

    assert!(
        matches!(while_live, Err(Error::FileFull { maximum_bytes: _ })),
        "evidence is live for three skews: {while_live:?}"
    );
    assert_eq!(after, Admission::Fresh);
    assert_eq!(
        store.admit(&evidence(refused, expired_at)?)?,
        Admission::Replayed
    );
    Ok(())
}

/// Pins that an enormous retention never makes live evidence look expired: with a window that
/// overflows the 32-bit timestamp, a full file still refuses a new tag instead of recycling a slot.
#[test]
fn an_enormous_retention_never_expires_live_evidence() -> Result<(), TestError> {
    let (unbounded, _files) = fresh();
    let store = unbounded.with_maximum_bytes(16 + 1023 * 16);
    let window = Duration::from_secs(u64::from(u32::MAX));
    let mut full_at = None;
    for index in 0..4000_u32 {
        match store.admit(&evidence_with_skew(index, 1_000_000, window)?) {
            Ok(Admission::Fresh) => {}
            Ok(Admission::Replayed) => return Err("distinct tags never collide".into()),
            Err(Error::FileFull { maximum_bytes: _ }) => {
                full_at = Some(index);
                break;
            }
            Err(other) => return Err(other.into()),
            Ok(_) => return Err("unknown admission".into()),
        }
    }
    let first_refused = full_at.ok_or("the file never filled")?;

    let later = store.admit(&evidence_with_skew(first_refused, 1_000_010, window)?);

    assert!(
        matches!(later, Err(Error::FileFull { maximum_bytes: _ })),
        "live evidence was recycled: {later:?}"
    );
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
            Err(Error::Capacity { capacity: _ }) => {}
            Err(other) => return Err(other.into()),
            Ok(_) => return Err("unknown admission".into()),
        }
    }

    assert!(!live.is_empty() && live.len() <= 2, "{live:?}");
    for index in live {
        assert_eq!(
            store.admit(&evidence(index, 1_000_000)?)?,
            Admission::Replayed
        );
    }
    Ok(())
}
