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

    /// Replacing the authorization data erases every previous entry's live payload.
    #[test]
    fn authorization_data_replacement_erases_previous_entries() -> Result<(), Box<dyn Error>> {
        let principal = Principal::new("R", 1, vec!["alice".to_owned()]);
        let mut credential =
            Credential::config_entry(principal, "opaque", None, vec![71; 7].into());
        credential = credential.with_auth_data(vec![
            AuthorizationDataEntry::new(1, hex::decode("31".repeat(23))?.into()),
            AuthorizationDataEntry::new(2, hex::decode("32".repeat(24))?.into()),
        ]);
        EVENTS.with_borrow_mut(Vec::clear);
        credential =
            credential.with_auth_data(vec![AuthorizationDataEntry::new(3, vec![0x33; 25].into())]);
        EVENTS.with_borrow(|events| assert_eq!(events.as_slice(), [(23, true), (24, true)]));
        assert_eq!(credential.auth_data().len(), 1);
        drop(credential);
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
            credential.with_auth_data(vec![AuthorizationDataEntry::new(1, vec![91; 9].into())]);
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

    /// MEMORY removals, replacements and destruction erase the payloads they drop.
    #[test]
    fn memory_store_removals_erase_payloads() -> Result<(), Box<dyn Error>> {
        use crate::ccache::{in_memory::MemoryStore, stores::CredentialStore as _};
        // Given a MEMORY cache holding one credential with a 31-byte payload.
        let principal = Principal::new("R", 1, vec!["alice".to_owned()]);
        let server = Principal::new("R", 1, vec!["svc".to_owned()]);
        let stored = || {
            let mut credential =
                Credential::config_entry(principal.clone(), "x", None, vec![0x5a; 31].into());
            credential.set_server(server.clone());
            credential
        };
        let store = MemoryStore::new();
        let cache = store.resolve("one")?;
        cache.initialize(&principal)?;
        for operation in 0_u8..3 {
            cache.store(stored())?;
            EVENTS.with_borrow_mut(Vec::clear);
            // When the credential is removed, replaced, or the cache destroyed.
            match operation {
                0 => assert_eq!(cache.remove(&server)?, 1),
                1 => cache.store(stored())?,
                _ => {
                    cache.destroy()?;
                    cache.initialize(&principal)?;
                }
            }
            // Then the dropped payload was observed erased in live storage.
            EVENTS.with_borrow(|events| {
                assert!(
                    events.contains(&(31, true)),
                    "operation {operation}: {events:?}"
                );
            });
        }
        Ok(())
    }
}
