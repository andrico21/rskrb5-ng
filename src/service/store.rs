//! The in-memory caches as [`Store`]s, and the legacy error mapping.

use core::time::Duration;

use super::{Error, Principal, ReplayKey, SharedReplayCache};
use crate::{
    error::Replay,
    replay::{Admission, Evidence, Store},
};

/// Map a store error onto the service error: the four errors the in-memory
/// cache has always returned keep their variants, the rest travel as
/// [`Error::Store`].
pub(super) fn legacy(error: Replay) -> Error {
    match &error {
        Replay::Poisoned => Error::ReplayCachePoisoned,
        Replay::ClockRollback => Error::ReplayCacheClockRollback,
        Replay::Capacity { capacity } => Error::ReplayCacheCapacityExceeded {
            capacity: *capacity,
        },
        Replay::SkewExceeded { maximum, requested } => Error::ReplayCacheSkewExceeded {
            maximum: *maximum,
            requested: *requested,
        },
        Replay::InvalidName
        | Replay::UnsupportedType { name_type: _ }
        | Replay::EmptyPath
        | Replay::IdentityUnavailable
        | Replay::Io {
            operation: _,
            path: _,
            source: _,
        }
        | Replay::Corrupt { path: _, reason: _ }
        | Replay::UnsafeFile { path: _, reason: _ }
        | Replay::FileFull { maximum_bytes: _ }
        | Replay::TimeOutOfRange => Error::ReplayStore(error),
    }
}

impl Store for SharedReplayCache {
    #[inline]
    fn admit(&self, evidence: &Evidence) -> Result<Admission, Replay> {
        let key = ReplayKey {
            service: Principal {
                name_type: 0,
                ..evidence.presentation.service.clone()
            },
            client: Principal {
                name_type: 0,
                ..evidence.presentation.client.clone()
            },
            ctime_seconds: evidence.presentation.ctime_seconds,
            cusec: evidence.presentation.cusec,
        };
        let mut cache = self.inner.lock().map_err(|_poisoned| Replay::Poisoned)?;
        let fresh = cache.insert(key, evidence.digest, evidence.presented_at, evidence.skew)?;
        Ok(if fresh {
            Admission::Fresh
        } else {
            Admission::Replayed
        })
    }

    #[inline]
    fn ensure_skew(&self, requested: Duration) -> Result<(), Replay> {
        let cache = self.inner.lock().map_err(|_poisoned| Replay::Poisoned)?;
        cache.ensure_skew(requested)
    }
}
