//! Capacity observations for the principal component count.

use core::cell::Cell;

use super::Keytab;
use crate::error::Keytab as Error;

std::thread_local! {
    /// Largest component capacity reserved on this test thread.
    static LARGEST: Cell<usize> = const { Cell::new(0) };
}

/// Record a component capacity that is about to be reserved.
pub(super) fn record(capacity: usize) {
    LARGEST.with(|largest| largest.set(largest.get().max(capacity)));
}

/// A component count far beyond the entry reserves no more than the entry can hold.
#[test]
fn component_count_beyond_the_entry_reserves_nothing_large() -> Result<(), Error> {
    // Given a version 2 keytab whose only entry body is count 32767 and an empty realm.
    let bytes = [5_u8, 2, 0, 0, 0, 4, 0x7f, 0xff, 0, 0];
    LARGEST.with(|largest| largest.set(0));

    // When it is parsed.
    let error = Keytab::parse(&bytes).err().ok_or(Error::LengthOverflow)?;

    // Then it is truncated, and the reservation is bounded by the input.
    assert!(
        matches!(
            error,
            Error::Truncated {
                offset: _,
                needed: _,
                remaining: _
            }
        ),
        "{error:?}"
    );
    let reserved = LARGEST.with(Cell::get).saturating_mul(size_of::<String>());
    assert!(
        reserved <= bytes.len(),
        "reserved {reserved} bytes for {} input bytes",
        bytes.len()
    );
    Ok(())
}
