//! TGT refresh scheduling.

use core::time::Duration;
use std::time::SystemTime;

use super::{AsRepSession, session_valid_at};

/// A session is due for refresh once at most 1/6 of its lifetime remains.
const SESSION_REFRESH_DIVISOR: u32 = 6;

/// Whether a session is unusable or inside its refresh window at `now`.
pub(super) fn session_refresh_due_at(session: &AsRepSession, now: SystemTime) -> bool {
    if !session_valid_at(session, now) {
        return true;
    }
    // RFC 4120 keeps auth_time fixed across renewals while a renewal advances
    // start_time, so the current ticket life is end_time - start_time.
    let Ok(lifetime) = session.end_time.duration_since(session.start_time) else {
        return true;
    };
    if lifetime.is_zero() {
        return true;
    }
    let remaining = session
        .end_time
        .duration_since(now)
        .unwrap_or(Duration::ZERO);
    // The divisor is a non-zero constant, so `checked_div` always succeeds.
    lifetime
        .checked_div(SESSION_REFRESH_DIVISOR)
        .is_none_or(|band| remaining <= band)
}

/// How long until a session enters its refresh window; zero when it is due.
pub(super) fn session_refresh_delay_at(session: &AsRepSession, now: SystemTime) -> Duration {
    if session_refresh_due_at(session, now) {
        return Duration::ZERO;
    }
    let Ok(lifetime) = session.end_time.duration_since(session.start_time) else {
        return Duration::ZERO;
    };
    // The divisor is a non-zero constant, so `checked_div` always succeeds.
    let Some(refresh_at) = lifetime
        .checked_div(SESSION_REFRESH_DIVISOR)
        .and_then(|band| session.end_time.checked_sub(band))
    else {
        return Duration::ZERO;
    };
    refresh_at.duration_since(now).unwrap_or(Duration::ZERO)
}
