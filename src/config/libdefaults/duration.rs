//! Bounded MIT interval grammar for clock tolerance (x-deltat.y, 1.22.2).

use core::time::Duration;

use super::super::Error;

/// Decode ordered unit intervals or day/clock intervals without losing tokens.
/// # Errors
/// Rejects malformed, negative-total and overflowing signed-32-bit intervals.
pub(crate) fn parse(input: &str) -> Result<Duration, Error> {
    let text = input.trim_matches(super::super::profile_syntax::tag_whitespace);
    let (first, rest) = number(text).ok_or_else(|| Error::InvalidDuration(input.to_owned()))?;
    let seconds = if rest.is_empty() {
        first
    } else if let Some(clock) = rest.strip_prefix('-') {
        first
            .checked_mul(86_400)
            .and_then(|days| days.checked_add(clock_seconds(clock, 3)?))
            .ok_or_else(|| Error::InvalidDuration(input.to_owned()))?
    } else if let Some(clock) = rest.strip_prefix(':') {
        first
            .checked_mul(3_600)
            .and_then(|hours| hours.checked_add(clock_seconds(clock, 2)?))
            .ok_or_else(|| Error::InvalidDuration(input.to_owned()))?
    } else {
        units(first, rest).ok_or_else(|| Error::InvalidDuration(input.to_owned()))?
    };
    let positive =
        u64::try_from(seconds).map_err(|_negative| Error::InvalidDuration(input.to_owned()))?;
    Ok(Duration::from_secs(positive))
}

/// Read one signed decimal token; whitespace cannot join separate numbers.
fn number(text: &str) -> Option<(i32, &str)> {
    let digits = text.strip_prefix('-').unwrap_or(text);
    let count = digits.bytes().take_while(u8::is_ascii_digit).count();
    if count == 0 {
        return None;
    }
    let end = count.checked_add(usize::from(text.starts_with('-')))?;
    let magnitude = digits.get(..count)?.parse::<i32>().ok()?;
    let value = if text.starts_with('-') {
        magnitude.checked_neg()?
    } else {
        magnitude
    };
    Some((value, text.get(end..)?))
}

/// Read two/three day-clock fields or one/two minute-clock fields, each <=2 digits.
fn clock_seconds(text: &str, maximum: usize) -> Option<i32> {
    let mut total = 0_i32;
    let mut count = 0_usize;
    for part in text.split(':') {
        if part.is_empty() || part.len() > 2 || !part.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        total = total
            .checked_mul(60)?
            .checked_add(part.parse::<i32>().ok()?)?;
        count = count.checked_add(1)?;
    }
    match (maximum, count) {
        (3, 3) | (2, 2) => Some(total),
        (2, 1) => total.checked_mul(60),
        _ => None,
    }
}

/// Unit order is d, h, m, s, with optional intervening whitespace/signed terms.
fn units(first: i32, text: &str) -> Option<i32> {
    let mut value = first;
    let mut remaining = text;
    let mut previous = 0_u8;
    let mut total = 0_i32;
    while let Some(unit) = remaining.bytes().next() {
        let (rank, multiplier): (u8, i32) = match unit {
            b'd' => (1, 86_400),
            b'h' => (2, 3_600),
            b'm' => (3, 60),
            b's' => (4, 1),
            _ => return None,
        };
        if rank <= previous {
            return None;
        }
        total = total.checked_add(value.checked_mul(multiplier)?)?;
        previous = rank;
        remaining = remaining
            .get(1..)?
            .trim_start_matches(super::super::profile_syntax::tag_whitespace);
        if remaining.is_empty() {
            return Some(total);
        }
        (value, remaining) = number(remaining)?;
    }
    None
}
