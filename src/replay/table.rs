//! The MIT `file2` hash-table walk (MIT 1.22.2 `rc_file2.c:46-198`).

use std::{io, path::Path};

use super::{Admission, Error, OpenFile, TAG_LEN, Tag, siphash::siphash24};

/// Length of the `SipHash` seed at the start of the file (`K5_HASH_SEED_LEN`).
const SEED_LEN: usize = 16;
/// Bytes per record: the tag and a big-endian 32-bit timestamp.
const RECORD_LEN: u64 = 16;
/// Slots of the first table (`FIRST_TABLE_RECORDS`).
const FIRST_TABLE_RECORDS: u64 = 1023;

/// One hash table of the file: its byte offset and slot count.
#[derive(Clone, Copy)]
struct Table {
    /// Byte offset of the first slot.
    offset: u64,
    /// Number of slots.
    records: u64,
}

/// A parsed record: the tag and its timestamp (zero means never written).
#[derive(Clone, Copy)]
struct Record {
    /// The tag bytes.
    tag: [u8; TAG_LEN],
    /// Seconds since the Unix epoch, zero for an empty slot.
    stamp: u32,
}

/// The inputs of one store operation.
pub(super) struct Run<'run> {
    /// The tag of the presented authenticator.
    tag: &'run Tag,
    /// The cache file, for error messages.
    path: &'run Path,
    /// The presentation time as a 32-bit Unix timestamp.
    now: u32,
    /// Seconds a record stays live after it was written.
    retention: u32,
    /// The file-size bound.
    maximum_bytes: u64,
}

impl<'run> Run<'run> {
    /// An operation on `tag` in the file at `path`.
    pub(super) const fn new(tag: &'run Tag, path: &'run Path) -> Self {
        Self {
            tag,
            path,
            now: 0,
            retention: 0,
            maximum_bytes: 0,
        }
    }

    /// Set the presentation time and the live-record retention, in seconds.
    pub(super) const fn at(mut self, now: u32, retention: u32) -> Self {
        self.now = now;
        self.retention = retention;
        self
    }

    /// Set the file-size bound.
    pub(super) const fn bounded(mut self, maximum_bytes: u64) -> Self {
        self.maximum_bytes = maximum_bytes;
        self
    }

    /// Check and store the tag in an open, locked file (`rc_file2.c:store`).
    ///
    /// # Errors
    ///
    /// Returns an I/O, corruption or capacity error; none admits the tag.
    pub(super) fn store(&self, file: &mut dyn OpenFile) -> Result<Admission, Error> {
        store(file, self)
    }
}

/// The table after `previous`; `None` before the first table starts the walk.
/// `None` is returned when the table would exceed `maximum_bytes`.
fn next_table(previous: Option<Table>, maximum_bytes: u64) -> Option<Table> {
    let table = match previous {
        None => Table {
            offset: u64::try_from(SEED_LEN).ok()?,
            records: FIRST_TABLE_RECORDS,
        },
        Some(table) if table.offset == u64::try_from(SEED_LEN).ok()? => Table {
            offset: table
                .offset
                .checked_add(table.records.checked_mul(RECORD_LEN)?)?,
            records: FIRST_TABLE_RECORDS.checked_add(1)?.checked_mul(2)?,
        },
        Some(table) => Table {
            offset: table
                .offset
                .checked_add(table.records.checked_mul(RECORD_LEN)?)?,
            records: table.records.checked_mul(2)?,
        },
    };
    let end = table
        .offset
        .checked_add(table.records.checked_mul(RECORD_LEN)?)?;
    (end <= maximum_bytes).then_some(table)
}

/// Whether `stamp` is older than `retention` seconds at `now`, in the wrapping
/// 32-bit arithmetic of MIT's `ts_after(now, ts_incr(stamp, skew))`.
const fn expired(stamp: u32, now: u32, retention: u32) -> bool {
    now > stamp.wrapping_add(retention)
}

/// Parse up to two records read at one offset.
fn parse(buffer: &[u8; 32], read: usize) -> (usize, Option<Record>, Option<Record>) {
    let record_len = 16_usize;
    let at = |index: usize| -> Option<Record> {
        let start = index.checked_mul(record_len)?;
        let chunk = buffer.get(start..start.checked_add(record_len)?)?;
        let (tag_bytes, stamp_bytes) = chunk.split_at(TAG_LEN);
        let mut tag = [0_u8; TAG_LEN];
        tag.copy_from_slice(tag_bytes);
        let mut stamp = [0_u8; 4];
        stamp.copy_from_slice(stamp_bytes);
        Some(Record {
            tag,
            stamp: u32::from_be_bytes(stamp),
        })
    };
    let count = read.checked_div(record_len).unwrap_or(0).min(2);
    (
        count,
        if count >= 1 { at(0) } else { None },
        if count >= 2 { at(1) } else { None },
    )
}

/// A typed corruption error for this file.
fn corrupt(path: &Path, reason: &'static str) -> Error {
    Error::Corrupt {
        path: path.to_path_buf(),
        reason,
    }
}

/// An I/O error for this file.
fn io_error(path: &Path, operation: &'static str, source: io::Error) -> Error {
    Error::Io {
        operation,
        path: path.to_path_buf(),
        source,
    }
}

/// Check the file length and read or create the seed.
///
/// # Errors
///
/// Returns an I/O error, or a corruption error for a file shorter than the
/// seed or ending inside a record.
fn seed(file: &mut dyn OpenFile, run: &Run<'_>) -> Result<[u8; SEED_LEN], Error> {
    let length = file
        .size()
        .map_err(|source| io_error(run.path, "stat", source))?;
    let mut seed_bytes = [0_u8; SEED_LEN];
    if length == 0 {
        getrandom::fill(&mut seed_bytes)
            .map_err(|source| io_error(run.path, "seed", io::Error::other(source)))?;
        file.write_at(0, &seed_bytes)
            .map_err(|source| io_error(run.path, "write", source))?;
        return Ok(seed_bytes);
    }
    let header = u64::try_from(SEED_LEN).unwrap_or(16);
    if length < header {
        return Err(corrupt(run.path, "the file is shorter than the hash seed"));
    }
    if length.saturating_sub(header).checked_rem(RECORD_LEN) != Some(0) {
        return Err(corrupt(run.path, "the file ends inside a record"));
    }
    let read = file
        .read_at(0, &mut seed_bytes)
        .map_err(|source| io_error(run.path, "read", source))?;
    if read != SEED_LEN {
        return Err(corrupt(run.path, "the hash seed cannot be read"));
    }
    Ok(seed_bytes)
}

/// The table walk behind [`Run::store`].
///
/// # Errors
///
/// Returns an I/O, corruption or capacity error; none admits the tag.
fn store(file: &mut dyn OpenFile, run: &Run<'_>) -> Result<Admission, Error> {
    let mut seed_bytes = seed(file, run)?;
    let mut table: Option<Table> = None;
    let mut available: Option<u64> = None;
    loop {
        let current = next_table(table, run.maximum_bytes).ok_or(Error::FileFull {
            maximum_bytes: run.maximum_bytes,
        })?;
        table = Some(current);
        let index = siphash24(run.tag.as_bytes(), &seed_bytes)
            .checked_rem(current.records)
            .unwrap_or(0);
        let offset = index
            .checked_mul(RECORD_LEN)
            .and_then(|relative| current.offset.checked_add(relative))
            .ok_or(Error::FileFull {
                maximum_bytes: run.maximum_bytes,
            })?;
        let mut buffer = [0_u8; 32];
        let read = file
            .read_at(offset, &mut buffer)
            .map_err(|source| io_error(run.path, "read", source))?;
        let (count, first, second) = parse(&buffer, read);
        let matches = |record: Option<Record>| {
            record.is_some_and(|slot| slot.stamp != 0 && slot.tag == *run.tag.as_bytes())
        };
        if matches(first) || matches(second) {
            return Ok(Admission::Replayed);
        }
        let free = |record: Option<Record>| {
            record.is_none_or(|slot| slot.stamp == 0 || expired(slot.stamp, run.now, run.retention))
        };
        if available.is_none() {
            available = if free(first) {
                Some(offset)
            } else if count == 1 || free(second) {
                offset.checked_add(RECORD_LEN)
            } else {
                None
            };
        }
        let open_end = count < 2
            || first.is_some_and(|slot| slot.stamp == 0)
            || second.is_some_and(|slot| slot.stamp == 0);
        if open_end {
            let target = available.ok_or_else(|| corrupt(run.path, "no slot is available"))?;
            let mut record = [0_u8; 16];
            let (tag_part, stamp_part) = record.split_at_mut(TAG_LEN);
            tag_part.copy_from_slice(run.tag.as_bytes());
            stamp_part.copy_from_slice(&run.now.to_be_bytes());
            file.write_at(target, &record)
                .map_err(|source| io_error(run.path, "write", source))?;
            file.sync()
                .map_err(|source| io_error(run.path, "sync", source))?;
            return Ok(Admission::Fresh);
        }
        let head = seed_bytes.first_mut().ok_or_else(|| corrupt(run.path, "no seed"))?;
        *head = head.wrapping_add(1);
    }
}
