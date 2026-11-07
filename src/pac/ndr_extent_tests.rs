//! Allocation-entry observations for correlated but truncated wire arrays.

use core::cell::Cell;

use super::*;

std::thread_local! {
    /// Reservations reached on this test thread.
    pub(super) static RESERVATIONS: Cell<usize> = const { Cell::new(0) };
}

/// Each million-element declaration is rejected before entering allocation.
#[test]
fn truncated_arrays_never_reserve() -> Result<(), Error> {
    let bytes = 1_000_000_u32.to_le_bytes();
    RESERVATIONS.with(|count| count.set(0));
    let errors = [
        read_deferred_rpc_unicode_strings(&mut Reader::new(&bytes), 1, 1_000_000, "rpc").err(),
        read_deferred_claims_arrays(&mut Reader::new(&bytes), 1, 1_000_000, "claims").err(),
        read_deferred_claim_entries(&mut Reader::new(&bytes), 1, 1_000_000, "entries").err(),
        read_deferred_i64_array(&mut Reader::new(&bytes), 1, 1_000_000, "signed").err(),
        read_deferred_u64_array(&mut Reader::new(&bytes), 1, 1_000_000, "unsigned").err(),
        read_deferred_bool_array(&mut Reader::new(&bytes), 1, 1_000_000, "boolean").err(),
        read_deferred_lpwstr_array(&mut Reader::new(&bytes), 1, 1_000_000, "strings").err(),
        read_deferred_group_memberships(&mut Reader::new(&bytes), 1, 1_000_000, "groups").err(),
        read_deferred_sid_and_attributes(&mut Reader::new(&bytes), 1, 1_000_000, "sids").err(),
        read_deferred_domain_group_memberships(&mut Reader::new(&bytes), 1, 1_000_000, "domains")
            .err(),
    ];
    for candidate in errors {
        let error = candidate.ok_or(Error::LengthOverflow)?;
        assert!(matches!(
            error,
            Error::Truncated {
                offset: _,
                needed: _,
                remaining: _
            }
        ));
    }
    RESERVATIONS.with(|count| assert_eq!(count.get(), 0));
    Ok(())
}

/// Full fixed extent at the inclusive count ceiling is admitted once.
#[test]
fn complete_group_extent_at_ceiling_is_admitted() -> Result<(), Error> {
    let mut bytes = 1_000_000_u32.to_le_bytes().to_vec();
    bytes.resize(8_000_004, 0);
    RESERVATIONS.with(|count| count.set(0));
    let groups = read_deferred_group_memberships(&mut Reader::new(&bytes), 1, 1_000_000, "groups")?;
    assert_eq!(groups.len(), 1_000_000);
    RESERVATIONS.with(|count| assert_eq!(count.get(), 1));
    Ok(())
}
