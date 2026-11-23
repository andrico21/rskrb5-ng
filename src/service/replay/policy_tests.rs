//! Capacity and skew contract regression tests.

use core::cell::Cell;
use std::panic::catch_unwind;

use super::{Arc, Duration, Error, ReplayCache, ReplayKey, SystemTime};
use crate::service::Principal;

std::thread_local! {
    /// Expiry records examined on this test thread.
    pub(super) static DIGEST_VISITS: Cell<usize> = const { Cell::new(0) };
}

/// A privately injected orphan is diagnosed rather than silently ignored.
#[test]
#[cfg(debug_assertions)]
fn orphan_trips_pairing_invariant() -> Result<(), Error> {
    // Given a cache holding one correctly paired admission.
    let skew = Duration::from_secs(300);
    let mut cache = ReplayCache::with_limits(skew, 8);
    assert!(cache.insert(key(2), [2; 32], SystemTime::UNIX_EPOCH, skew)?);
    // When a key without a digest record is injected privately.
    let _: Option<[u8; 32]> = cache.entries.insert(Arc::new(key(1)), [1; 32]);
    // Then the paired-index assertion trips.
    let outcome = catch_unwind(|| cache.assert_paired());
    assert!(outcome.is_err(), "orphan must trip paired-index assertion");
    Ok(())
}

/// Distinct clients keep the capacity test independent of principal quotas.
fn key(id: u32) -> ReplayKey {
    ReplayKey {
        service: Principal::new("REALM".into(), 0, vec!["service".into()]),
        client: Principal::new("REALM".into(), 0, vec![id.to_string()]),
        ctime_seconds: 0,
        cusec: id,
    }
}

/// The documented default and custom admission limit both hold.
#[test]
fn capacity_default_and_custom_limit_are_enforced() -> Result<(), Error> {
    // Given a deliberately small cache.
    assert_eq!(ReplayCache::default().capacity, 0x0001_0000);
    let skew = Duration::from_secs(300);
    let mut cache = ReplayCache::with_limits(skew, 1);
    assert!(cache.insert(key(1), [1; 32], SystemTime::UNIX_EPOCH, skew)?);
    // When another principal presents a distinct authenticator.
    let outcome = cache.insert(key(2), [2; 32], SystemTime::UNIX_EPOCH, skew);
    // Then no live evidence is evicted to admit it.
    assert!(matches!(
        outcome,
        Err(Error::Capacity { capacity: 1 })
    ));
    assert!(!cache.insert(key(1), [1; 32], SystemTime::UNIX_EPOCH, skew)?);
    Ok(())
}

/// A wider cache accepts a narrower validator.
#[test]
fn skew_900_accepts_validator_300() -> Result<(), Error> {
    // Given a 900-second cache.
    let mut cache = ReplayCache::with_limits(Duration::from_mins(15), 8);
    // When a 300-second validator admits a fresh authenticator.
    let admitted = cache.insert(
        key(1),
        [1; 32],
        SystemTime::UNIX_EPOCH,
        Duration::from_secs(300),
    )?;
    // Then the ceiling is compatible.
    assert!(admitted);
    Ok(())
}

/// A narrower cache refuses a wider validator.
#[test]
fn skew_300_rejects_validator_301() -> Result<(), Error> {
    // Given a 300-second cache that admits a validator at its own skew.
    let mut cache = ReplayCache::with_limits(Duration::from_secs(300), 8);
    assert!(cache.insert(
        key(2),
        [2; 32],
        SystemTime::UNIX_EPOCH,
        Duration::from_secs(300),
    )?);
    // When a 301-second validator requests admission.
    let outcome = cache.insert(
        key(1),
        [1; 32],
        SystemTime::UNIX_EPOCH,
        Duration::from_secs(301),
    );
    // Then the requested window cannot escape retention coverage.
    assert!(
        matches!(outcome, Err(Error::SkewExceeded { maximum, requested })
        if maximum == Duration::from_secs(300) && requested == Duration::from_secs(301))
    );
    Ok(())
}

/// Administrative expiry cannot advance the admission watermark.
#[test]
fn safe_pruning_preserves_replay_after_future_clock_sample() -> Result<(), Error> {
    // Given a live pair admitted at the epoch.
    let skew = Duration::from_secs(300);
    let mut cache = ReplayCache::with_limits(skew, 8);
    assert!(cache.insert(key(1), [1; 32], SystemTime::UNIX_EPOCH, skew)?);
    // When maintenance sees a time beyond retention, without an admission.
    let _: usize = cache.prune_expired_at(SystemTime::UNIX_EPOCH + Duration::from_secs(901));
    // Then rolling back to a valid presentation still rejects the replay.
    assert!(!cache.insert(key(1), [1; 32], SystemTime::UNIX_EPOCH, skew)?);
    Ok(())
}

/// Admission before expiry must not scan live digest records.
#[test]
fn admission_has_bounded_digest_visits() -> Result<(), Error> {
    // Given 256 live pairs.
    let skew = Duration::from_secs(300);
    let mut cache = ReplayCache::with_limits(skew, 512);
    for id in 0..256_u32 {
        let mut digest = [0; 32];
        for (byte, value) in digest.iter_mut().zip(id.to_le_bytes()) {
            *byte = value;
        }
        assert!(cache.insert(key(id), digest, SystemTime::UNIX_EPOCH, skew)?);
    }
    DIGEST_VISITS.set(0);
    // When a fresh pair arrives before the first expiry.
    assert!(cache.insert(key(257), [255; 32], SystemTime::UNIX_EPOCH, skew)?);
    // Then expiry work is independent of the live population.
    assert!(
        DIGEST_VISITS.get() <= 2,
        "visited {} digests",
        DIGEST_VISITS.get()
    );
    Ok(())
}

/// A ticket holder cannot consume another principal's admission share.
#[test]
fn principal_capacity_preserves_other_clients() -> Result<(), Error> {
    let skew = Duration::from_secs(300);
    let mut cache = ReplayCache::with_limits(skew, 8);
    assert!(cache.insert(key(1), [1; 32], SystemTime::UNIX_EPOCH, skew)?);
    let mut second = key(1);
    second.cusec = 2;
    assert!(matches!(
        cache.insert(second, [2; 32], SystemTime::UNIX_EPOCH, skew),
        Err(Error::Capacity { capacity: 1 })
    ));
    assert!(cache.insert(key(2), [3; 32], SystemTime::UNIX_EPOCH, skew)?);
    assert!(!cache.insert(key(1), [1; 32], SystemTime::UNIX_EPOCH, skew)?);
    Ok(())
}
