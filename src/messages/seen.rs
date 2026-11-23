//! The bounded memory of messages an [`super::AuthContext`] has seen (MIT `memrcache`).

use core::time::Duration;
use std::{collections::HashMap, time::SystemTime};

use crate::error::AuthMessage as Error;

/// Message tags with the time their evidence expires.
#[derive(Clone, Debug)]
pub(super) struct Seen {
    /// Expiry by tag.
    entries: HashMap<Vec<u8>, SystemTime>,
    /// The bound on live entries.
    capacity: usize,
}

impl Seen {
    /// An empty memory of at most `capacity` live tags.
    pub(super) fn new(capacity: usize) -> Self {
        Self {
            entries: HashMap::new(),
            capacity,
        }
    }

    /// Record `tag` seen at `now`, live for `retention`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Replay`] for a live tag and [`Error::ReplayMemoryFull`]
    /// when only live tags fill the memory; no live tag is ever evicted.
    pub(super) fn record(
        &mut self,
        tag: &[u8],
        now: SystemTime,
        retention: Duration,
    ) -> Result<(), Error> {
        self.entries.retain(|_tag, expiry| *expiry >= now);
        if self.entries.contains_key(tag) {
            return Err(Error::Replay);
        }
        if self.entries.len() >= self.capacity {
            return Err(Error::ReplayMemoryFull {
                capacity: self.capacity,
            });
        }
        let expiry = now.checked_add(retention).ok_or(Error::TimeOutOfRange)?;
        let _previous: Option<SystemTime> = self.entries.insert(tag.to_vec(), expiry);
        Ok(())
    }
}
