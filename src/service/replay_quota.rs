//! Bounded admission shares for authenticated client identities.

use super::{HashMap, Principal};
use crate::error::Replay as Error;

/// Counts use realm and components only: name types are advisory.
#[derive(Debug)]
pub(super) struct PrincipalQuota {
    /// Maximum records for one client.
    limit: usize,
    /// Live records by realm and components.
    counts: HashMap<(String, Vec<String>), usize>,
}

impl PrincipalQuota {
    /// Start empty with the default one-eighth share.
    pub(super) fn new(capacity: usize) -> Self {
        Self {
            limit: capacity.checked_div(8).unwrap_or(0).max(1).min(capacity),
            counts: HashMap::new(),
        }
    }

    /// Reserve one record for this client.
    ///
    /// # Errors
    ///
    /// Returns a capacity error when the client's share is full.
    pub(super) fn admit(&mut self, principal: &Principal) -> Result<(), Error> {
        if self.limit == 0 {
            return Err(Error::Capacity { capacity: 0 });
        }
        let count = self
            .counts
            .entry((principal.realm.clone(), principal.components.clone()))
            .or_default();
        if *count >= self.limit {
            return Err(Error::Capacity {
                capacity: self.limit,
            });
        }
        *count = count.saturating_add(1);
        Ok(())
    }

    /// Release one expired client's record.
    pub(super) fn remove(&mut self, principal: &Principal) {
        let identity = (principal.realm.clone(), principal.components.clone());
        if let Some(count) = self.counts.get_mut(&identity) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                let _: Option<usize> = self.counts.remove(&identity);
            }
        }
    }

    /// Forget counts with the corresponding replay evidence.
    pub(super) fn clear(&mut self) {
        self.counts.clear();
    }
    /// Clamp a configured share without evicting any live evidence.
    pub(super) fn set_limit(&mut self, capacity: usize, total: usize) {
        let maximum = if total > 1 {
            total.saturating_sub(1)
        } else {
            total
        };
        self.limit = capacity.min(maximum);
    }
}
