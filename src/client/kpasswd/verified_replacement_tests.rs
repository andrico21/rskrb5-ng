use std::time::UNIX_EPOCH;

use super::{EncryptionKey, VerifiedKpasswdApRep};
use crate::keytab::key_bytes::EVENTS;

/// Clearing a verified server subkey erases its live allocation before reply drop.
#[test]
fn verified_password_subkey_replacement_erases_old_bytes() -> Result<(), hex::FromHexError> {
    let mut reply = VerifiedKpasswdApRep {
        ctime: UNIX_EPOCH,
        cusec: 0,
        authenticator_time: UNIX_EPOCH,
        subkey: Some(EncryptionKey::new(
            17,
            hex::decode("4142434445464748494a4b4c4d4e4f50")?,
        )),
        sequence_number: None,
    };
    EVENTS.with_borrow_mut(Vec::clear);
    reply.set_subkey(None);
    EVENTS.with_borrow(|events| assert_eq!(events.as_slice(), [(16, true)]));
    Ok(())
}
