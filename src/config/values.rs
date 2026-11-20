//! Profile scalar value grammars: durations and booleans.

use core::time::Duration;

#[cfg(test)]
use super::EnctypeExpr;
#[cfg(test)]
use super::ParseMode;
#[cfg(test)]
use super::Toggle;
use super::profile_syntax;
#[cfg(test)]
use crate::crypto::KerberosEtype;
use crate::error::Config as Error;

/// Parse a krb5 duration value.
///
/// # Errors
/// Returns [`Error::InvalidDuration`] for a value in none of these forms, and
/// [`Error::DurationOverflow`] for one whose seconds do not fit a `u64`.
pub(super) fn parse_duration(value: &str) -> Result<Duration, Error> {
    let normalized = value.split_whitespace().collect::<String>();
    if normalized.is_empty() {
        return Err(Error::InvalidDuration(value.to_owned()));
    }

    if let Some((day_text, rest)) = normalized.split_once('d') {
        let Ok(days) = day_text.parse::<u64>() else {
            return Err(Error::InvalidDuration(value.to_owned()));
        };
        let day_seconds = days
            .checked_mul(24 * 60 * 60)
            .ok_or_else(|| Error::DurationOverflow(value.to_owned()))?;
        let mut duration = Duration::from_secs(day_seconds);
        if !rest.is_empty() {
            duration = duration
                .checked_add(parse_unit_duration(rest, value)?)
                .ok_or_else(|| Error::DurationOverflow(value.to_owned()))?;
        }
        return Ok(duration);
    }

    if let Ok(duration) = parse_unit_duration(&normalized, value) {
        return Ok(duration);
    }

    if let Ok(seconds) = normalized.parse::<u64>() {
        return Ok(Duration::from_secs(seconds));
    }

    if normalized.contains(':') {
        return parse_colon_duration(&normalized, value);
    }

    Err(Error::InvalidDuration(value.to_owned()))
}

/// Parse a krb5 boolean value.
///
/// # Errors
/// Returns [`Error::InvalidBoolean`] outside MIT's case-insensitive vocabulary:
/// `1`, `t`, `true`, `y`, `yes`, `on`, `0`, `false`, `n`, `no`, `nil`, `off`.
/// The existing gokrb5 `f` spelling remains a compatible extension.
pub(super) fn parse_boolean(value: &str) -> Result<bool, Error> {
    match value
        .trim_matches(profile_syntax::tag_whitespace)
        .to_ascii_lowercase()
        .as_str()
    {
        "1" | "t" | "true" | "y" | "yes" | "on" => Ok(true),
        "0" | "f" | "false" | "n" | "no" | "nil" | "off" => Ok(false),
        _ => Err(Error::InvalidBoolean(value.to_owned())),
    }
}

/// Parse enctype names to the subset of IDs implemented by gokrb5-compatible
/// crypto.
#[cfg(test)]
pub(super) fn parse_supported_enctype_ids(
    enctypes: &[String],
    _allow_weak_crypto: bool,
) -> Vec<i32> {
    EnctypeExpr::parse(&enctypes.join(" "))
        .and_then(|expr| expr.resolve(Toggle::Enabled, Toggle::Enabled, ParseMode::Compatible))
        .map_or_else(
            |_| Vec::new(),
            |resolved| {
                resolved
                    .enctypes()
                    .iter()
                    .copied()
                    .map(KerberosEtype::etype_id)
                    .collect()
            },
        )
}

/// Parse a duration made of `<number><unit>` groups, where the unit is `h`,
/// `m` or `s` (`12h30m15s`).
///
/// # Errors
///
/// Returns [`Error::InvalidDuration`] naming `original` for an empty input, a
/// group without digits, a number that does not fit a `u64`, or an unknown
/// unit, and [`Error::DurationOverflow`] when the total does not fit.
pub(super) fn parse_unit_duration(input: &str, original: &str) -> Result<Duration, Error> {
    let mut chars = input.char_indices().peekable();
    let mut duration = Duration::ZERO;
    let mut parsed_any = false;

    while chars.peek().is_some() {
        let start = chars.peek().map_or(0, |(index, _)| *index);
        while matches!(chars.peek(), Some((_, ch)) if ch.is_ascii_digit()) {
            let _: Option<(usize, char)> = chars.next();
        }
        let number_end = chars.peek().map_or(input.len(), |(index, _)| *index);
        if number_end == start {
            return Err(Error::InvalidDuration(original.to_owned()));
        }
        // Both ends are `char_indices` boundaries, so the slice always exists.
        let Some(Ok(number)) = input.get(start..number_end).map(str::parse::<u64>) else {
            return Err(Error::InvalidDuration(original.to_owned()));
        };

        let unit_start = number_end;
        while matches!(chars.peek(), Some((_, ch)) if ch.is_ascii_alphabetic()) {
            let _: Option<(usize, char)> = chars.next();
        }
        let unit_end = chars.peek().map_or(input.len(), |(index, _)| *index);
        let unit = input.get(unit_start..unit_end).unwrap_or_default();
        let seconds = match unit {
            "h" => number
                .checked_mul(60 * 60)
                .ok_or_else(|| Error::DurationOverflow(original.to_owned()))?,
            "m" => number
                .checked_mul(60)
                .ok_or_else(|| Error::DurationOverflow(original.to_owned()))?,
            "s" => number,
            _ => return Err(Error::InvalidDuration(original.to_owned())),
        };
        duration = duration
            .checked_add(Duration::from_secs(seconds))
            .ok_or_else(|| Error::DurationOverflow(original.to_owned()))?;
        parsed_any = true;
    }

    if parsed_any {
        Ok(duration)
    } else {
        Err(Error::InvalidDuration(original.to_owned()))
    }
}

/// Parse an `h:m[:s]` duration.
///
/// # Errors
///
/// Returns [`Error::InvalidDuration`] naming `original` unless the input has
/// two or three `:`-separated `u64` fields, and [`Error::DurationOverflow`]
/// when the total seconds do not fit.
pub(super) fn parse_colon_duration(input: &str, original: &str) -> Result<Duration, Error> {
    let parts = input.split(':').collect::<Vec<_>>();
    let (hours_text, minutes_text, seconds_text) = match *parts.as_slice() {
        [hours, minutes] => (hours, minutes, None),
        [hours, minutes, seconds] => (hours, minutes, Some(seconds)),
        _ => return Err(Error::InvalidDuration(original.to_owned())),
    };
    let invalid = || Error::InvalidDuration(original.to_owned());
    let hours = hours_text.parse::<u64>().ok().ok_or_else(invalid)?;
    let minutes = minutes_text.parse::<u64>().ok().ok_or_else(invalid)?;
    let seconds = match seconds_text {
        Some(text) => text.parse::<u64>().ok().ok_or_else(invalid)?,
        None => 0_u64,
    };

    let total = hours
        .checked_mul(60 * 60)
        .and_then(|value| value.checked_add(minutes.checked_mul(60)?))
        .and_then(|value| value.checked_add(seconds))
        .ok_or_else(|| Error::DurationOverflow(original.to_owned()))?;
    Ok(Duration::from_secs(total))
}
