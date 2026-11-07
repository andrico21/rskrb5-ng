//! Local replay-cache admission and maintenance.

#[cfg(test)]
use super::replay_tests;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod policy_tests;
use super::{
    Arc, DEFAULT_MAX_CLOCK_SKEW, DigestRecord, Duration, Error, HashMap, ReplayCache, ReplayKey,
    SystemTime,
};

impl Default for ReplayCache {
    #[inline]
    fn default() -> Self {
        Self::with_limits(DEFAULT_MAX_CLOCK_SKEW, 0x0001_0000)
    }
}

impl ReplayCache {
    /// Check that retention covers the requested validation window.
    ///
    /// # Errors
    ///
    /// Returns a skew policy error for an incompatible window.
    pub(super) fn ensure_skew(&self, requested: Duration) -> Result<(), Error> {
        if requested > self.max_clock_skew {
            return Err(Error::ReplayCacheSkewExceeded {
                maximum: self.max_clock_skew,
                requested,
            });
        }
        Ok(())
    }

    /// Configure an unused owned cache without discarding evidence.
    ///
    /// # Errors
    ///
    /// Returns a skew policy error for an increase after admission has begun.
    pub(super) fn configure_owned_skew(&mut self, requested: Duration) -> Result<(), Error> {
        if self.watermark.is_some() {
            self.ensure_skew(requested)?;
        } else {
            self.max_clock_skew = self.max_clock_skew.max(requested);
        }
        Ok(())
    }
    /// Set the maximum live records per authenticated client realm and components.
    ///
    /// Defaults to one eighth of total capacity (at least one for nonempty caches).
    /// Values are clamped below total capacity when it is at least two; zero
    /// refuses new records. Existing evidence is retained even if over the new
    /// limit. A capacity of one cannot reserve room for another client. Multiple
    /// colluding principals may still exhaust the global bound.
    #[must_use]
    #[inline]
    pub fn with_principal_capacity(mut self, capacity: usize) -> Self {
        self.principal_quota.set_limit(capacity, self.capacity);
        self
    }

    /// Create an empty cache with immutable skew and live-entry admission limits.
    ///
    /// Validators exceeding `max_clock_skew` are rejected on admission. Zero
    /// capacity rejects all new records. Expiry retains three times the skew
    /// from the last-seen watermark, covering future authenticators and rollback.
    /// Backward clock samples up to this skew are tolerated without lowering
    /// the high-water mark; larger rollbacks fail closed.
    #[must_use]
    #[inline]
    pub fn with_limits(max_clock_skew: Duration, capacity: usize) -> Self {
        Self {
            max_clock_skew,
            capacity,
            principal_quota: super::replay_quota::PrincipalQuota::new(capacity),
            watermark: None,
            entries: HashMap::new(),
            authenticators: HashMap::new(),
            expiry: super::BTreeSet::new(),
        }
    }

    #[must_use]
    /// Create an empty replay cache.
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    /// Remove all cached replay entries.
    ///
    /// # Security
    ///
    /// This reopens replay protection for previously accepted authenticators.
    /// Use [`Self::prune_expired`] for invariant-preserving maintenance instead.
    #[inline]
    pub fn clear(&mut self) {
        self.entries.clear();
        self.authenticators.clear();
        self.expiry.clear();
        self.principal_quota.clear();
        self.assert_paired();
    }

    #[must_use]
    /// Number of cached RFC 4120 replay entries, excluding the digest index.
    #[inline]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    /// Whether the RFC 4120 replay entries are empty, excluding the digest index.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Remove entries last seen more than `max_age` ago.
    ///
    /// Entries are aged by the watermark at which they were last seen, not by
    /// the clock sample of their presentation.
    ///
    /// # Security
    ///
    /// Arbitrary ages reopen replay protection by discarding live evidence.
    /// Prefer [`Self::prune_expired`].
    #[inline]
    pub fn force_clear_older_than(&mut self, max_age: Duration) -> usize {
        self.force_clear_older_than_at(max_age, SystemTime::now())
    }

    /// Remove entries last seen more than `max_age` before `now`.
    ///
    /// Entries are aged by the watermark at which they were last seen, not by
    /// the clock sample of their presentation. A replay key and its
    /// authenticator digest are removed together.
    ///
    /// # Security
    ///
    /// Arbitrary ages or future clock samples can reopen replay protection.
    /// Prefer [`Self::prune_expired_at`].
    #[inline]
    pub fn force_clear_older_than_at(&mut self, max_age: Duration, now: SystemTime) -> usize {
        let before = self.entries.len();
        while let Some(&(last_seen, digest)) = self.expiry.first() {
            #[cfg(test)]
            policy_tests::DIGEST_VISITS.with(|visits| visits.set(visits.get().saturating_add(1)));
            if now
                .duration_since(last_seen)
                .map_or(true, |age| age <= max_age)
            {
                break;
            }
            let _: Option<(SystemTime, [u8; 32])> = self.expiry.pop_first();
            if let Some(record) = self.authenticators.remove(&digest) {
                self.principal_quota.remove(&record.key.client);
                #[cfg(test)]
                replay_tests::KEY_INDEX_VISITS
                    .with(|visits| visits.set(visits.get().saturating_add(1)));
                let _: Option<[u8; 32]> = self.entries.remove(&*record.key);
            }
            self.assert_paired();
        }
        self.assert_paired();
        before.saturating_sub(self.entries.len())
    }

    /// Remove only records outside the automatic retention window.
    #[inline]
    pub fn prune_expired(&mut self) -> usize {
        self.prune_expired_at(SystemTime::now())
    }

    /// Safely expire records at the lesser of `now` and the admission watermark.
    ///
    /// Maintenance cannot advance the watermark or shorten three-skew retention.
    #[inline]
    pub fn prune_expired_at(&mut self, now: SystemTime) -> usize {
        self.watermark.map_or(0, |watermark| {
            self.force_clear_older_than_at(
                self.max_clock_skew.saturating_mul(3),
                now.min(watermark),
            )
        })
    }

    /// Record one presentation, or report it as a replay.
    ///
    /// Returns `false` when either the RFC 4120 replay key or authenticator digest
    /// was already seen, refreshing every matched key and digest pair together;
    /// `true` once both are recorded.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ReplayCacheSkewExceeded`], [`Error::ReplayCacheClockRollback`]
    /// or [`Error::ReplayCacheCapacityExceeded`] when cache policy rejects admission.
    pub(super) fn insert(
        &mut self,
        key: ReplayKey,
        authenticator_digest: [u8; 32],
        presented_at: SystemTime,
        validator_skew: Duration,
    ) -> Result<bool, Error> {
        if validator_skew > self.max_clock_skew {
            return Err(Error::ReplayCacheSkewExceeded {
                maximum: self.max_clock_skew,
                requested: validator_skew,
            });
        }
        if self.watermark.is_some_and(|latest| {
            latest
                .duration_since(presented_at)
                .is_ok_and(|rollback| rollback > self.max_clock_skew)
        }) {
            return Err(Error::ReplayCacheClockRollback);
        }
        let latest = self
            .watermark
            .map_or(presented_at, |time| time.max(presented_at));
        self.watermark = Some(latest);
        // For first presentation P, c <= P+s. A tolerated sample T >= W-s
        // can accept c only if c >= T-s, hence P >= W-3s. Keep equality live.
        let retention = self.max_clock_skew.saturating_mul(3);
        let _: usize = self.force_clear_older_than_at(retention, latest);
        // A key hit refreshes the digest admitted with it, and a digest hit
        // refreshes its own record, so a pair never ages apart.
        let paired = self.entries.get(&key).copied();
        let mut replay = paired.is_some();
        for digest in paired.into_iter().chain([authenticator_digest]) {
            if let Some(record) = self.authenticators.get_mut(&digest) {
                let _: bool = self.expiry.remove(&(record.last_seen, digest));
                record.last_seen = latest;
                let _: bool = self.expiry.insert((latest, digest));
                replay = true;
            }
            self.assert_paired();
        }
        if replay {
            return Ok(false);
        }
        if self.entries.len() >= self.capacity {
            return Err(Error::ReplayCacheCapacityExceeded {
                capacity: self.capacity,
            });
        }
        // Both lookups above missed, so neither insert replaces an entry and
        // the new key and digest pair one to one.
        self.principal_quota.admit(&key.client)?;
        let shared_key = Arc::new(key);
        let _: Option<[u8; 32]> = self
            .entries
            .insert(Arc::clone(&shared_key), authenticator_digest);
        drop(self.authenticators.insert(
            authenticator_digest,
            DigestRecord {
                last_seen: latest,
                key: shared_key,
            },
        ));
        let _: bool = self.expiry.insert((latest, authenticator_digest));
        self.assert_paired();
        Ok(true)
    }

    /// Diagnose broken pairing without scanning live records.
    fn assert_paired(&self) {
        debug_assert_eq!(
            self.entries.len(),
            self.authenticators.len(),
            "replay key/digest pairing"
        );
        debug_assert_eq!(
            self.entries.len(),
            self.expiry.len(),
            "replay expiry pairing"
        );
    }
}
