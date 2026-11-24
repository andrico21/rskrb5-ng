//! Kerberos times of the authenticated messages.

use core::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use rasn::types::Integer;
use rasn_kerberos::KerberosTime;

use crate::error::AuthMessage as Error;

/// A Kerberos time and microseconds for `at`.
///
/// # Errors
///
/// Returns [`Error::TimeOutOfRange`] before the epoch or past the range of a
/// Kerberos time.
pub(super) fn kerberos_time(at: SystemTime) -> Result<(KerberosTime, Integer), Error> {
    let since = at
        .duration_since(UNIX_EPOCH)
        .map_err(|_before_epoch| Error::TimeOutOfRange)?;
    let seconds = i64::try_from(since.as_secs()).map_err(|_range| Error::TimeOutOfRange)?;
    let time = chrono::DateTime::from_timestamp(seconds, 0).ok_or(Error::TimeOutOfRange)?;
    Ok((
        KerberosTime(time.fixed_offset()),
        Integer::from(since.subsec_micros()),
    ))
}

/// The `SystemTime` of a received Kerberos time and microseconds.
///
/// # Errors
///
/// Returns [`Error::TimeOutOfRange`] for a time or microseconds Kerberos cannot carry.
pub(super) fn system_time(
    time: &KerberosTime,
    usec: Option<&Integer>,
) -> Result<SystemTime, Error> {
    let micros = match usec {
        None => 0,
        Some(value) => u32::try_from(value)
            .ok()
            .filter(|micros| *micros <= 999_999)
            .ok_or(Error::TimeOutOfRange)?,
    };
    let whole = UNIX_EPOCH
        .checked_add(Duration::from_secs(
            u64::try_from(time.0.timestamp()).map_err(|_negative| Error::TimeOutOfRange)?,
        ))
        .ok_or(Error::TimeOutOfRange)?;
    whole
        .checked_add(Duration::from_micros(u64::from(micros)))
        .ok_or(Error::TimeOutOfRange)
}
