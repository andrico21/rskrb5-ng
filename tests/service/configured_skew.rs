//! Configured skew and owned replay-cache compatibility.

use super::{Duration, TestError, VALID_AP_REQ, Validator, decode_hex, http_keytab, timestamp};

/// Authenticator timestamps exactly at configured skew remain admissible.
#[test]
fn authenticator_skew_equality_is_accepted() -> Result<(), TestError> {
    let keytab = http_keytab()?;
    let bytes = decode_hex(VALID_AP_REQ)?;
    let mut baseline = Validator::new(&keytab).with_now(timestamp(1_893_553_447)?);
    let accepted = baseline.validate_ap_req(&bytes)?;
    let now = accepted
        .authenticator_time
        .checked_add(Duration::from_secs(2))
        .ok_or("time")?;
    let mut boundary = Validator::new(&keytab)
        .with_now(now)
        .with_max_clock_skew(Duration::from_secs(2))?;
    drop(boundary.validate_ap_req(&bytes)?);
    Ok(())
}

/// A fresh AP-REQ is accepted with a 301-second owned-cache window.
#[test]
fn configured_skew_accepts_fresh_request() -> Result<(), TestError> {
    let keytab = http_keytab()?;
    let mut validator = Validator::new(&keytab)
        .with_now(timestamp(1_893_553_447)?)
        .with_max_clock_skew(Duration::from_secs(301))?;
    drop(validator.validate_ap_req(&decode_hex(VALID_AP_REQ)?)?);
    Ok(())
}

/// Configuring skew after attaching a narrow cache fails before any request.
#[test]
fn shared_cache_rejects_wider_skew_in_reverse_builder_order() -> Result<(), TestError> {
    let keytab = http_keytab()?;
    let validator =
        Validator::new(&keytab).with_shared_replay_cache(super::SharedReplayCache::new())?;
    assert!(matches!(
        validator.with_max_clock_skew(Duration::from_secs(301)),
        Err(super::Error::ReplayCacheSkewExceeded {
            maximum: _,
            requested: _
        })
    ));
    Ok(())
}

/// Changing the window after admission cannot erase existing evidence.
#[test]
fn used_owned_cache_rejects_retention_increase() -> Result<(), TestError> {
    let keytab = http_keytab()?;
    let mut validator = Validator::new(&keytab).with_now(timestamp(1_893_553_447)?);
    drop(validator.validate_ap_req(&decode_hex(VALID_AP_REQ)?)?);
    assert!(matches!(
        validator.with_max_clock_skew(Duration::from_secs(301)),
        Err(super::Error::ReplayCacheSkewExceeded {
            maximum: _,
            requested: _
        })
    ));
    Ok(())
}
