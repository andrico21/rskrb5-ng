//! The identifier octets of a DER element.

use super::{Class, Error, Identifier};

/// Read the identifier octets: the identifier and the number of octets it took.
///
/// # Errors
///
/// Returns [`Error::Truncated`], [`Error::NonMinimalTag`] or [`Error::TagTooLarge`].
pub(super) fn read_identifier(input: &[u8]) -> Result<(Identifier, usize), Error> {
    let (&first, rest) = input.split_first().ok_or(Error::Truncated)?;
    let class = match first >> 6_u32 {
        0 => Class::Universal,
        1 => Class::Application,
        2 => Class::ContextSpecific,
        _ => Class::Private,
    };
    let constructed = first & 0x20 != 0;
    let low = first & 0x1f;
    if low != 0x1f {
        return Ok((
            Identifier {
                class,
                constructed,
                number: u32::from(low),
            },
            1,
        ));
    }
    let mut number = 0_u32;
    let mut used = 1_usize;
    for (index, &octet) in rest.iter().enumerate() {
        used = used.saturating_add(1);
        if index == 0 && octet == 0x80 {
            return Err(Error::NonMinimalTag);
        }
        number = number
            .checked_mul(128)
            .and_then(|shifted| shifted.checked_add(u32::from(octet & 0x7f)))
            .ok_or(Error::TagTooLarge)?;
        if octet & 0x80 == 0 {
            if number < 0x1f {
                return Err(Error::NonMinimalTag);
            }
            return Ok((
                Identifier {
                    class,
                    constructed,
                    number,
                },
                used,
            ));
        }
    }
    Err(Error::Truncated)
}
