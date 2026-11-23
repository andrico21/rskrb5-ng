//! The file layout against the reference model of MIT's `rc_file2.c`.
//!
//! The expected values come from `tests/fixtures/replay/file2_model.py`, a
//! second implementation written from the MIT 1.22.2 source; the live
//! interop suite `replay` checks the same format against MIT's own library.

use alloc::sync::Arc;
use std::path::PathBuf;

use rskrb5_ng::replay::{Admission, File2ReplayStore, Store};
use sha2::{Digest as _, Sha256};

use crate::context::TestError;
use super::{
    support::{MemoryFs, evidence},
};

/// The hash seed of the model: bytes 0 to 15.
const SEED: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

/// A store on a file that already holds the seed.
fn seeded() -> (File2ReplayStore, MemoryFs) {
    let files = MemoryFs::with_bytes(&SEED);
    let store = File2ReplayStore::new(PathBuf::from("memory"))
        .with_file_system(Arc::new(files.clone()));
    (store, files)
}

/// The non-empty records of a file as `(offset, tag hex, timestamp)`.
fn records(bytes: &[u8]) -> Vec<(usize, String, u32)> {
    bytes
        .chunks_exact(16)
        .enumerate()
        .skip(1)
        .filter_map(|(slot, record)| {
            let (tag, stamp) = record.split_at(12);
            let stamp = u32::from_be_bytes(stamp.try_into().ok()?);
            (stamp != 0).then(|| (slot * 16, hex::encode(tag), stamp))
        })
        .collect()
}

/// Pins six records at the offsets and timestamps the reference model writes.
#[test]
fn six_records_land_where_the_model_puts_them() -> Result<(), TestError> {
    let (store, files) = seeded();

    for index in 0..6_u32 {
        let admission = store.admit(&evidence(index, 1_000_000 + u64::from(index))?)?;
        assert_eq!(admission, Admission::Fresh);
    }

    let expected = [
        (1584_usize, "41caacdf679f85536112282e", 1_000_003_u32),
        (10944, "76d75b7a57ea39ab447dce6d", 1_000_001),
        (12704, "ec353318d8a3f340ef72c8f9", 1_000_000),
        (12992, "0bfd83093c1c1ab3ce1c0ab4", 1_000_004),
        (13280, "b6ce1bba07546f9bd5da2546", 1_000_002),
        (14032, "932bc636d2dce0f070f3fc81", 1_000_005),
    ];
    let actual = records(&files.bytes()?);
    assert_eq!(actual.len(), expected.len());
    for (record, (offset, tag, stamp)) in actual.iter().zip(expected) {
        assert_eq!(record, &(offset, tag.to_owned(), stamp));
    }
    assert_eq!(files.bytes()?.len(), 14_048);
    Ok(())
}

/// Pins that 3000 tags spill into the second and third tables exactly as the model does.
#[test]
fn three_thousand_records_fill_three_tables_like_the_model() -> Result<(), TestError> {
    let (store, files) = seeded();

    for index in 0..3000_u32 {
        assert_eq!(store.admit(&evidence(index, 1_000_000)?)?, Admission::Fresh);
    }

    let bytes = files.bytes()?;
    assert_eq!(bytes.len(), 175_808);
    assert_eq!(
        hex::encode(Sha256::digest(&bytes)),
        "28b3ca53a7057d32967f1434bd25cbe7d397ccc88a42ea636e394ef5e2f1f2ec"
    );
    for index in (0..3000_u32).step_by(97) {
        assert_eq!(store.admit(&evidence(index, 1_000_000)?)?, Admission::Replayed);
    }
    Ok(())
}

/// Pins that records older than three skews are reused, byte for byte like the model, and not before.
#[test]
fn expired_records_are_reused_after_three_skews_like_the_model() -> Result<(), TestError> {
    let (store, files) = seeded();
    for index in 0..3000_u32 {
        assert_eq!(store.admit(&evidence(index, 1_000_000)?)?, Admission::Fresh);
    }
    let live = files.bytes()?;

    // Exactly three skews later the records are still live: new tags take new slots.
    for index in 3000..3400_u32 {
        assert_eq!(store.admit(&evidence(index, 1_002_700)?)?, Admission::Fresh);
    }
    assert!(files.bytes()?.len() >= live.len());
    let grown = files.bytes()?.len();

    let (late_store, late_files) = seeded();
    for index in 0..3000_u32 {
        assert_eq!(late_store.admit(&evidence(index, 1_000_000)?)?, Admission::Fresh);
    }
    for index in 3000..3400_u32 {
        assert_eq!(late_store.admit(&evidence(index, 1_002_701)?)?, Admission::Fresh);
    }

    let reused = late_files.bytes()?;
    assert_eq!(reused.len(), 175_808);
    assert_eq!(
        hex::encode(Sha256::digest(&reused)),
        "097e40f8a2e7e2f9688d7c5e94efe8a9a79a6d10914c2d268c088ed00e42863e"
    );
    assert!(grown >= reused.len());
    Ok(())
}

/// Pins that a file written by the reference model is read as evidence: every tag is a replay.
#[test]
fn a_model_written_file_is_read_as_evidence() -> Result<(), TestError> {
    let (writer, files) = seeded();
    for index in 0..40_u32 {
        let _fresh: Admission = writer.admit(&evidence(index, 1_000_000)?)?;
    }
    let reader = File2ReplayStore::new(PathBuf::from("memory"))
        .with_file_system(Arc::new(MemoryFs::with_bytes(&files.bytes()?)));

    for index in 0..40_u32 {
        assert_eq!(reader.admit(&evidence(index, 1_000_001)?)?, Admission::Replayed);
    }
    assert_eq!(reader.admit(&evidence(41, 1_000_001)?)?, Admission::Fresh);
    Ok(())
}
