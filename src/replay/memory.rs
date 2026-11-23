//! The in-process store.

use core::time::Duration;

use super::{Admission, Error, Evidence, MemoryReplayStore, Store};
use crate::service::{ReplayCache, SharedReplayCache};

impl MemoryReplayStore {
    /// An empty store with the default skew ceiling and capacity (65,536).
    #[must_use]
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    /// An empty store bounded to `capacity` live records and validators whose
    /// skew is at most `max_clock_skew`. A full store refuses new evidence
    /// with [`Error::Capacity`]; it never evicts live evidence.
    #[must_use]
    #[inline]
    pub fn with_limits(max_clock_skew: Duration, capacity: usize) -> Self {
        Self {
            cache: SharedReplayCache::from_cache(ReplayCache::with_limits(
                max_clock_skew,
                capacity,
            )),
        }
    }
}

impl Store for MemoryReplayStore {
    #[inline]
    fn admit(&self, evidence: &Evidence) -> Result<Admission, Error> {
        self.cache.admit(evidence)
    }

    #[inline]
    fn ensure_skew(&self, requested: Duration) -> Result<(), Error> {
        Store::ensure_skew(&self.cache, requested)
    }
}
