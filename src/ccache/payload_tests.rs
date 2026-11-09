//! Live payload observations before allocation release.

use core::cell::RefCell;

std::thread_local! {
    /// Allocation length and live erasure state at destruction.
    pub(super) static EVENTS: RefCell<Vec<(usize, bool)>> = const { RefCell::new(Vec::new()) };
}

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::error::Error;

    use super::EVENTS;
    use crate::ccache::{AuthorizationDataEntry, CCache, Credential, Principal};

    /// Payload setters erase previous live allocations before container destruction.
    #[test]
    fn replacement_erases_ticket_and_authorization_payloads() -> Result<(), Box<dyn Error>> {
        let principal = Principal::new("R", 1, vec!["alice".to_owned()]);
        let mut credential = Credential::config_entry(
            principal,
            "opaque",
            None,
            hex::decode("41".repeat(16))?.into(),
        )
        .with_second_ticket(vec![0x52; 17].into());
        let mut authorization = AuthorizationDataEntry::new(1, vec![0x63; 18].into());
        EVENTS.with_borrow_mut(Vec::clear);
        credential = credential.set_ticket(vec![0x74; 19].into());
        credential = credential.set_second_ticket(vec![0x85; 20].into());
        authorization = authorization.set_data(vec![0x96; 21].into());
        credential = credential.with_second_ticket(vec![0xa7; 22].into());
        EVENTS.with_borrow(|events| {
            assert_eq!(
                events.as_slice(),
                [(16, true), (17, true), (18, true), (20, true)]
            );
        });
        drop((credential, authorization));
        Ok(())
    }

    /// Complete and partially parsed credentials erase each retained payload before release.
    #[test]
    fn cache_payloads_erased_on_drop_and_parse_failure() -> Result<(), Box<dyn Error>> {
        // Given distinct nonzero configuration, second-ticket and authorization payloads.
        let principal = Principal::new("R", 1, vec!["alice".to_owned()]);
        let mut credential =
            Credential::config_entry(principal.clone(), "opaque", None, vec![71; 7].into());
        credential = credential.set_second_ticket(vec![81; 8].into());
        credential =
            credential.set_auth_data(vec![AuthorizationDataEntry::new(1, vec![91; 9].into())]);
        let mut cache = CCache::new(principal);
        cache.credentials_mut().push(credential);
        let encoded = cache.to_bytes()?;
        for truncated in [false, true] {
            EVENTS.with_borrow_mut(Vec::clear);
            let input = if truncated {
                encoded
                    .get(..encoded.len().checked_sub(1).ok_or("length")?)
                    .ok_or("slice")?
            } else {
                &encoded
            };
            // When the real cache parser completes or fails after copying the first ticket.
            let result = CCache::parse(input);
            assert_eq!(result.is_ok(), !truncated);
            drop(result);
            // Then every copied payload was observed erased in live storage.
            EVENTS.with_borrow(|events| {
                assert!(
                    events.contains(&(7, true)),
                    "primary/config payload was not erased"
                );
                assert!(
                    events.contains(&(9, true)),
                    "authorization payload was not erased"
                );
                assert!(
                    truncated || events.contains(&(8, true)),
                    "second ticket was not erased"
                );
                assert!(events.iter().all(|(_, wiped)| *wiped));
            });
        }
        Ok(())
    }

    /// A version 3 cache with a credential serializes within its preallocated capacity.
    #[test]
    fn version_three_serialization_fits_preallocation() -> Result<(), Box<dyn Error>> {
        // Given a version 3 cache holding one credential (v3 stores the key etype twice).
        let principal = Principal::new("R", 1, vec!["alice".to_owned()]);
        let credential =
            Credential::config_entry(principal.clone(), "opaque", None, vec![7; 7].into());
        let mut cache = CCache::new(principal);
        cache.version = 3;
        cache.credentials_mut().push(credential);
        // When it is serialized (the test build asserts the output never outgrows its capacity).
        let encoded = cache.to_bytes()?;
        // Then the bytes parse back to the same version 3 cache.
        assert_eq!(CCache::parse(&encoded)?, cache);
        Ok(())
    }
}
