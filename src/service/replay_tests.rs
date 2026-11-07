//! Replay-cache regressions: the digest-indexed purge against the earlier
//! key-scanning purge, and the purge's key-index work.

use core::{cell::Cell, num::TryFromIntError, time::Duration};
use std::{
    collections::HashMap,
    panic::{catch_unwind, resume_unwind},
    time::{SystemTime, UNIX_EPOCH},
};

use super::{Error, Principal, ReplayCache, ReplayKey};
#[cfg(feature = "tower")]
use crate::keytab::Keytab;
use crate::pac::AD_WIN2K_PAC;

/// Shared maintenance reports poisoned admission locks instead of fabricated counts.
#[test]
fn shared_pruning_preserves_lock_errors() -> Result<(), Error> {
    let shared = super::SharedReplayCache::new();
    assert_eq!(shared.prune_expired_at(at(0))?, 0);
    let owned = shared.clone();
    let poisoned = catch_unwind(move || -> Result<(), ()> {
        let _guard = owned.inner.lock().map_err(|_poisoned| ())?;
        resume_unwind(Box::new("poisoned fixture"))
    });
    assert!(poisoned.is_err(), "fixture poisons the shared lock");
    assert!(matches!(
        shared.prune_expired(),
        Err(Error::ReplayCachePoisoned)
    ));
    assert!(matches!(
        shared.prune_expired_at(at(0)),
        Err(Error::ReplayCachePoisoned)
    ));
    Ok(())
}

/// Ticket boundary skew includes equality in both temporal directions.
#[test]
fn ticket_skew_boundaries_are_inclusive() {
    assert!(!super::starts_after_skew(at(4), at(0), SWEEP_SKEW));
    assert!(!super::expired_after_skew(at(4), at(0), SWEEP_SKEW));
}

/// A PAC is not a supported mandatory authenticator authorization element.
#[test]
fn mandatory_authenticator_pac_is_rejected() {
    let data = vec![rasn_kerberos::AuthorizationDataValue {
        r#type: AD_WIN2K_PAC,
        data: vec![].into(),
    }];
    let mut remaining = 8;
    assert!(matches!(
        super::validate_authorization_elements(
            &data,
            super::AuthorizationScope {
                critical: true,
                ticket: false,
                depth: 0
            },
            &mut remaining
        ),
        Err(Error::UnsupportedAuthorizationData { kind: _ })
    ));
}

/// Whole-second pre-epoch values remain whole seconds when split for replay keys.
#[test]
fn replay_time_preserves_pre_epoch_whole_seconds() -> Result<(), Error> {
    assert_eq!(
        super::unix_timestamp_parts(UNIX_EPOCH - Duration::from_secs(1))?,
        (-1, 0)
    );
    Ok(())
}

/// Configured per-client shares retain room for other identities at capacity boundaries.
#[test]
fn principal_share_boundaries_are_enforced() -> Result<(), Error> {
    for (total, requested, accepted) in
        [(1_usize, 1_usize, 1_usize), (2, 2, 1), (3, 3, 2), (8, 2, 2)]
    {
        let mut cache =
            ReplayCache::with_limits(SWEEP_SKEW, total).with_principal_capacity(requested);
        for id in 0..accepted {
            assert!(cache.insert(
                key(
                    "host",
                    1,
                    i64::try_from(id).map_err(|error| Error::Decode {
                        target: "fixture",
                        message: error.to_string()
                    })?,
                    0
                ),
                digest(u64::try_from(id).map_err(|error| Error::Decode {
                    target: "fixture",
                    message: error.to_string()
                })?),
                at(0),
                SWEEP_SKEW
            )?);
        }
        assert!(matches!(
            cache.insert(key("host", 1, 99, 0), digest(99), at(0), SWEEP_SKEW),
            Err(Error::ReplayCacheCapacityExceeded { capacity: _ })
        ));
    }
    Ok(())
}

/// Expiring one of a client's records frees one slot of its share, not the whole share.
#[test]
fn partial_expiry_keeps_the_remaining_share_counted() -> Result<(), Error> {
    let mut cache = ReplayCache::with_limits(SWEEP_SKEW, 16).with_principal_capacity(2);
    assert!(cache.insert(key("host", 1, 0, 0), digest(0), at(0), SWEEP_SKEW)?);
    assert!(cache.insert(key("host", 1, 1, 0), digest(1), at(4), SWEEP_SKEW)?);
    assert_eq!(
        cache.force_clear_older_than_at(Duration::from_secs(1), at(4)),
        1
    );
    assert!(cache.insert(key("host", 1, 2, 0), digest(2), at(4), SWEEP_SKEW)?);
    assert!(matches!(
        cache.insert(key("host", 1, 3, 0), digest(3), at(4), SWEEP_SKEW),
        Err(Error::ReplayCacheCapacityExceeded { capacity: 2 })
    ));
    Ok(())
}

/// Force clearing removes all old evidence and reports its exact count through shared clones.
#[test]
fn force_clear_reports_removed_pairs() -> Result<(), Error> {
    let mut local = ReplayCache::with_limits(SWEEP_SKEW, 16).with_principal_capacity(8);
    for id in 0_i64..2 {
        assert!(local.insert(
            key("host", 1, id, 0),
            digest(id.unsigned_abs()),
            at(0),
            SWEEP_SKEW
        )?);
    }
    assert_eq!(local.force_clear_older_than(Duration::ZERO), 2);
    for id in 0_i64..2 {
        assert!(local.insert(
            key("host", 1, id, 0),
            digest(id.unsigned_abs()),
            at(0),
            SWEEP_SKEW
        )?);
    }
    let shared = super::SharedReplayCache::from_cache(local);
    assert!(
        !shared.is_empty()?,
        "shared cache retains admitted evidence"
    );
    assert_eq!(shared.force_clear_older_than(Duration::ZERO)?, 2);
    assert!(shared.is_empty()?, "force clear discards both records");
    assert_eq!(shared.force_clear_older_than(Duration::ZERO)?, 0);
    Ok(())
}

/// Shared clear updates every clone's admission evidence.
#[test]
fn shared_clear_discards_live_evidence() -> Result<(), Error> {
    let mut local = ReplayCache::with_limits(SWEEP_SKEW, 16);
    assert!(local.insert(key("host", 1, 1, 0), digest(1), at(0), SWEEP_SKEW)?);
    let shared = super::SharedReplayCache::from_cache(local);
    let other = shared.clone();
    shared.clear()?;
    assert!(other.is_empty()?, "clear applies across shared handles");
    Ok(())
}

/// HTTP's checked attachment path exposes and uses the supplied shared replay cache.
#[cfg(feature = "tower")]
#[test]
fn checked_attachment_keeps_shared_cache() -> Result<(), Error> {
    let keytab = Keytab::parse(&[5, 2]).map_err(|error| Error::Decode {
        target: "Keytab fixture",
        message: error.to_string(),
    })?;
    let mut validator = super::Validator::new(&keytab);
    validator.attach_replay_cache(super::SharedReplayCache::new());
    assert!(
        validator.shared_replay_cache().is_some(),
        "checked attachment retains shared state"
    );
    Ok(())
}

std::thread_local! {
    /// Key-index records visited by purges on this test thread.
    pub(super) static KEY_INDEX_VISITS: Cell<usize> = const { Cell::new(0) };
}

/// The cache skew of the differential sweep.
const SWEEP_SKEW: Duration = Duration::from_secs(2);

/// One admission result, comparable across the two implementations.
#[derive(Debug, Eq, PartialEq)]
enum Outcome {
    /// A new key and digest pair was recorded.
    Admitted,
    /// The key or the digest was already live.
    Replay,
    /// The validator skew exceeds the cache ceiling.
    SkewExceeded {
        /// The cache ceiling.
        maximum: Duration,
        /// The validator skew.
        requested: Duration,
    },
    /// The sample lies more than the skew behind the watermark.
    Rollback,
    /// The cache is full.
    CapacityExceeded {
        /// The live-record limit.
        capacity: usize,
    },
    /// An error the replay cache never returns.
    Unexpected(String),
}

impl Outcome {
    /// Classify the cache's admission result.
    fn of(result: Result<bool, Error>) -> Self {
        match result {
            Ok(true) => Self::Admitted,
            Ok(false) => Self::Replay,
            Err(Error::ReplayCacheSkewExceeded { maximum, requested }) => {
                Self::SkewExceeded { maximum, requested }
            }
            Err(Error::ReplayCacheClockRollback) => Self::Rollback,
            Err(Error::ReplayCacheCapacityExceeded { capacity }) => {
                Self::CapacityExceeded { capacity }
            }
            Err(other) => Self::Unexpected(other.to_string()),
        }
    }
}

/// The replay cache before digest records held their keys: the purge found a
/// key's expiry by probing the digest index once per live key.
struct Reference {
    /// Immutable skew ceiling.
    max_clock_skew: Duration,
    /// Maximum live records.
    capacity: usize,
    /// Highest admission time.
    watermark: Option<SystemTime>,
    /// Replay keys, each with the digest admitted with it.
    entries: HashMap<ReplayKey, [u8; 32]>,
    /// Digests, each with the pair's last-seen watermark.
    authenticators: HashMap<[u8; 32], SystemTime>,
}

impl Reference {
    /// An empty reference cache with the given limits.
    fn with_limits(max_clock_skew: Duration, capacity: usize) -> Self {
        Self {
            max_clock_skew,
            capacity,
            watermark: None,
            entries: HashMap::new(),
            authenticators: HashMap::new(),
        }
    }

    /// Remove every record.
    fn clear(&mut self) {
        self.entries.clear();
        self.authenticators.clear();
    }

    /// Remove pairs last seen more than `max_age` before `now`.
    fn clear_older_than_at(&mut self, max_age: Duration, now: SystemTime) -> usize {
        let before = self.entries.len();
        self.authenticators.retain(|_, last_seen| {
            now.duration_since(*last_seen)
                .map_or(true, |age| age <= max_age)
        });
        let authenticators = &self.authenticators;
        self.entries
            .retain(|_, digest| authenticators.contains_key(digest));
        before.saturating_sub(self.entries.len())
    }

    /// Record one presentation, or report it as a replay.
    fn insert(
        &mut self,
        key: ReplayKey,
        authenticator_digest: [u8; 32],
        presented_at: SystemTime,
        validator_skew: Duration,
    ) -> Outcome {
        if validator_skew > self.max_clock_skew {
            return Outcome::SkewExceeded {
                maximum: self.max_clock_skew,
                requested: validator_skew,
            };
        }
        if self.watermark.is_some_and(|latest| {
            latest
                .duration_since(presented_at)
                .is_ok_and(|rollback| rollback > self.max_clock_skew)
        }) {
            return Outcome::Rollback;
        }
        let latest = self
            .watermark
            .map_or(presented_at, |time| time.max(presented_at));
        self.watermark = Some(latest);
        let retention = self.max_clock_skew.saturating_mul(3);
        let _: usize = self.clear_older_than_at(retention, latest);
        let paired = self.entries.get(&key).copied();
        let mut replay = paired.is_some();
        for digest in paired.into_iter().chain([authenticator_digest]) {
            if let Some(seen) = self.authenticators.get_mut(&digest) {
                *seen = latest;
                replay = true;
            }
        }
        if replay {
            return Outcome::Replay;
        }
        if self.entries.len() >= self.capacity {
            return Outcome::CapacityExceeded {
                capacity: self.capacity,
            };
        }
        let principal_capacity = self
            .capacity
            .checked_div(8)
            .unwrap_or(0)
            .max(1)
            .min(self.capacity);
        if self
            .entries
            .keys()
            .filter(|existing| {
                existing.client.realm == key.client.realm
                    && existing.client.components == key.client.components
            })
            .count()
            >= principal_capacity
        {
            return Outcome::CapacityExceeded {
                capacity: principal_capacity,
            };
        }
        let _: Option<[u8; 32]> = self.entries.insert(key, authenticator_digest);
        let _: Option<SystemTime> = self.authenticators.insert(authenticator_digest, latest);
        Outcome::Admitted
    }
}

/// Deterministic xorshift generator, so a failing sweep replays exactly.
struct Rng(u64);

impl Rng {
    /// The next pseudo-random word.
    fn next_word(&mut self) -> u64 {
        self.0 ^= self.0.wrapping_shl(13);
        self.0 ^= self.0.wrapping_shr(7);
        self.0 ^= self.0.wrapping_shl(17);
        self.0
    }

    /// A pseudo-random value in `0..bound`, or 0 for a zero bound.
    fn below(&mut self, bound: u64) -> u64 {
        self.next_word().checked_rem(bound).unwrap_or(0)
    }
}

/// A sweep time: `half_seconds` half-second steps after a fixed epoch.
fn at(half_seconds: u64) -> SystemTime {
    UNIX_EPOCH
        .checked_add(Duration::from_secs(1_700_000_000))
        .and_then(|base| base.checked_add(Duration::from_millis(half_seconds.saturating_mul(500))))
        .unwrap_or(UNIX_EPOCH)
}

/// A replay key from small identity pools, so keys collide often.
fn key(service: &str, client: u64, ctime_seconds: i64, cusec: u32) -> ReplayKey {
    ReplayKey {
        service: Principal::new(
            "EXAMPLE.COM".to_owned(),
            0,
            vec!["HTTP".to_owned(), service.to_owned()],
        ),
        client: Principal::new("EXAMPLE.COM".to_owned(), 0, vec![format!("user{client}")]),
        ctime_seconds,
        cusec,
    }
}

/// A distinct digest for `id`.
fn digest(id: u64) -> [u8; 32] {
    let mut bytes = [0_u8; 32];
    for (byte, value) in bytes.iter_mut().zip(id.to_le_bytes()) {
        *byte = value;
    }
    bytes
}

/// Outcome classes the sweep must reach, so it cannot pass vacuously.
#[derive(Default)]
struct Coverage {
    /// New pairs recorded.
    admitted: usize,
    /// Replays reported.
    replay: usize,
    /// Rollbacks rejected.
    rollback: usize,
    /// Full-cache rejections.
    capacity: usize,
    /// Wider-skew rejections.
    skew: usize,
    /// Pairs removed by explicit purges.
    purged: usize,
    /// Operations compared.
    operations: usize,
}

impl Coverage {
    /// Count one admission outcome.
    fn record(&mut self, outcome: &Outcome) {
        let class = match *outcome {
            Outcome::Admitted => &mut self.admitted,
            Outcome::Replay => &mut self.replay,
            Outcome::Rollback => &mut self.rollback,
            Outcome::CapacityExceeded { capacity: _ } => &mut self.capacity,
            Outcome::SkewExceeded {
                maximum: _,
                requested: _,
            } => &mut self.skew,
            Outcome::Unexpected(_) => return,
        };
        *class = class.saturating_add(1);
    }
}

/// Run one seeded operation sequence on both caches, comparing every step.
fn sweep_one(seed: u64, coverage: &mut Coverage) -> Result<(), TryFromIntError> {
    let mut rng = Rng(seed.wrapping_mul(0x2545_F491_4F6C_DD1D) | 1);
    let capacity = usize::try_from(rng.below(7))?;
    let mut cache = ReplayCache::with_limits(SWEEP_SKEW, capacity);
    let mut reference = Reference::with_limits(SWEEP_SKEW, capacity);
    // Half-second clock, started far enough in to step back past the skew.
    let mut clock = 1_000_u64;
    for step in 0..150_u64 {
        clock = match rng.below(12) {
            // Back by up to five seconds: within, at and beyond the skew.
            0 | 1 => clock.saturating_sub(rng.below(11)),
            // Forward by up to 30 seconds, past the six-second retention.
            2 => clock.saturating_add(rng.below(61)),
            _ => clock.saturating_add(rng.below(3)),
        };
        let now = at(clock);
        let ctime = i64::try_from(clock.checked_div(2).unwrap_or(0))?;
        match rng.below(16) {
            0 => {
                cache.clear();
                reference.clear();
            }
            1..=2 => {
                let max_age = Duration::from_millis(rng.below(15).saturating_mul(500));
                let purge_at = at(clock.saturating_add(rng.below(9)).saturating_sub(4));
                let removed = cache.force_clear_older_than_at(max_age, purge_at);
                assert_eq!(
                    removed,
                    reference.clear_older_than_at(max_age, purge_at),
                    "seed {seed} step {step}: purge count"
                );
                coverage.purged = coverage.purged.saturating_add(removed);
            }
            _ => {
                let validator_skew = match rng.below(20) {
                    0 => SWEEP_SKEW.saturating_add(Duration::from_secs(1)),
                    1 => Duration::from_secs(1),
                    _ => SWEEP_SKEW,
                };
                let service = if rng.below(3) == 0 { "alias" } else { "www" };
                let offset = i64::try_from(rng.below(5))?.saturating_sub(2);
                let presented = key(
                    service,
                    rng.below(4),
                    ctime.saturating_add(offset),
                    u32::try_from(rng.below(2))?,
                );
                let presented_digest = digest(rng.below(8));
                let outcome = Outcome::of(cache.insert(
                    presented.clone(),
                    presented_digest,
                    now,
                    validator_skew,
                ));
                assert_eq!(
                    outcome,
                    reference.insert(presented, presented_digest, now, validator_skew),
                    "seed {seed} step {step}: admission"
                );
                coverage.record(&outcome);
            }
        }
        coverage.operations = coverage.operations.saturating_add(1);
        assert_eq!(
            cache.len(),
            reference.entries.len(),
            "seed {seed} step {step}: keys"
        );
        assert_eq!(
            cache.authenticators.len(),
            reference.authenticators.len(),
            "seed {seed} step {step}: digests"
        );
        assert_eq!(
            cache.watermark, reference.watermark,
            "seed {seed} step {step}: watermark"
        );
        assert_eq!(
            cache.is_empty(),
            reference.entries.is_empty(),
            "seed {seed} step {step}"
        );
    }
    Ok(())
}

/// Admission, replay, rollback and purge sequences give the same results,
/// key count, digest count and watermark as the key-scanning purge.
#[test]
fn replay_purge_matches_key_scanning_reference() -> Result<(), TryFromIntError> {
    let mut coverage = Coverage::default();
    for seed in 1..=3_000_u64 {
        sweep_one(seed, &mut coverage)?;
    }
    assert_eq!(coverage.operations, 450_000, "every step compared");
    for (class, count) in [
        ("admitted", coverage.admitted),
        ("replay", coverage.replay),
        ("rollback", coverage.rollback),
        ("capacity", coverage.capacity),
        ("skew", coverage.skew),
        ("purged", coverage.purged),
    ] {
        assert!(count > 100, "sweep reached {class} only {count} times");
    }
    Ok(())
}

/// A purge touches the key index only for the pairs it removes, so admission
/// under the shared lock does not probe every live key.
#[test]
fn replay_purge_visits_key_index_only_for_expired_pairs() -> Result<(), Error> {
    // Given 4,096 live pairs admitted at the same time.
    let skew = Duration::from_secs(300);
    let mut cache = ReplayCache::with_limits(skew, 8_192);
    for id in 0..4_096_u64 {
        assert!(cache.insert(key("www", id, 0, 0), digest(id), at(0), skew)?);
    }

    // When a new pair and a replay arrive one second later.
    KEY_INDEX_VISITS.set(0);
    assert!(cache.insert(key("www", 4_096, 1, 0), digest(4_096), at(2), skew)?);
    assert!(!cache.insert(key("www", 0, 0, 0), digest(0), at(2), skew)?);

    // Then neither purge visited a key.
    assert_eq!(KEY_INDEX_VISITS.get(), 0, "purge with nothing expired");

    // When the first 4,096 pairs fall out of the 900-second window, except
    // the refreshed replay.
    assert!(cache.insert(key("www", 4_097, 902, 0), digest(4_097), at(1_802), skew)?);

    // Then the purge visited exactly the 4,095 keys it removed.
    assert_eq!(KEY_INDEX_VISITS.get(), 4_095, "purge of expired pairs");
    assert_eq!(cache.len(), 3);
    assert_eq!(cache.authenticators.len(), 3);

    // When an explicit purge removes every pair seen before the latest.
    KEY_INDEX_VISITS.set(0);
    let removed = cache.force_clear_older_than_at(Duration::ZERO, at(1_802));

    // Then it visited one key per removed pair.
    assert_eq!(removed, 2);
    assert_eq!(KEY_INDEX_VISITS.get(), removed, "explicit purge");
    assert_eq!(cache.len(), 1);
    assert_eq!(cache.authenticators.len(), 1);
    Ok(())
}
