//! Live observations of service-key replacement before container destruction.

use std::time::UNIX_EPOCH;

use super::{ApRepOptions, ValidatedApReq, VerifiedApRep};
use crate::{
    crypto::policy::Policy,
    keytab::{EncryptionKey, key_bytes::EVENTS},
};

/// Every service result and option setter erases its previous key allocation.
#[test]
fn service_key_replacements_erase_old_allocations() -> Result<(), hex::FromHexError> {
    let key = EncryptionKey::new(17, hex::decode("4142434445464748494a4b4c4d4e4f50")?);
    let mut options = ApRepOptions::default().with_subkey(Some(key.clone()));
    let mut verified = VerifiedApRep {
        ctime: UNIX_EPOCH,
        cusec: 0,
        authenticator_time: UNIX_EPOCH,
        subkey: Some(key.clone()),
        sequence_number: None,
    };
    let mut validated = ValidatedApReq {
        crypto_policy: Policy::default(),
        client: super::Principal::new("EXAMPLE.COM".to_owned(), 1, vec!["alice".to_owned()]),
        service: super::Principal::new(
            "EXAMPLE.COM".to_owned(),
            2,
            vec!["HTTP".to_owned(), "host".to_owned()],
        ),
        session_key: key.clone(),
        subkey: Some(key.clone()),
        sequence_number: None,
        ticket_start: UNIX_EPOCH,
        ticket_end: UNIX_EPOCH,
        authenticator_ctime: UNIX_EPOCH,
        authenticator_cusec: 0,
        authenticator_time: UNIX_EPOCH,
        pac: None,
    };
    EVENTS.with_borrow_mut(Vec::clear);
    options.set_subkey(None);
    verified.set_subkey(None);
    validated.set_subkey(None);
    validated.set_session_key(key);
    EVENTS.with_borrow(|events| assert_eq!(events.as_slice(), [(16, true); 4]));
    Ok(())
}
