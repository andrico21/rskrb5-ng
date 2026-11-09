//! Live NTLM replacement observations.

use core::{cell::RefCell, error::Error};

use zeroize::{ZeroizeOnDrop, Zeroizing};

use super::{CredentialsInfo, NtlmSupplementalCredential, SecpkgSupplementalCredential};
use crate::pac::RpcUnicodeString;

std::thread_local! {
    /// Observations while the original container remains alive.
    pub(super) static REPLACEMENTS: RefCell<Vec<bool>> = const { RefCell::new(Vec::new()) };
    /// Old vector lengths and live zero-byte observations.
    pub(super) static BYTE_REPLACEMENTS: RefCell<Vec<(usize, bool)>> = const { RefCell::new(Vec::new()) };
}

/// Both encrypted and decrypted PAC payload setters wipe live old allocations.
#[test]
fn pac_payload_replacement_erases_previous_bytes() -> Result<(), Box<dyn Error>> {
    let mut encrypted = CredentialsInfo {
        version: 0,
        encryption_type: 17,
        encrypted_credential_data: vec![0x41; 16].into(),
    };
    BYTE_REPLACEMENTS.with_borrow_mut(Vec::clear);
    encrypted.set_encrypted_credential_data(vec![0x52; 17].into());
    let mut supplemental = SecpkgSupplementalCredential {
        package_name: RpcUnicodeString {
            length: 0,
            maximum_length: 0,
            value: String::new(),
        },
        credential_size: 18,
        credentials: vec![0x63; 18].into(),
    };
    supplemental.set_credentials(vec![0x74; 19].into())?;
    BYTE_REPLACEMENTS.with_borrow(|events| assert_eq!(events.as_slice(), [(16, true), (18, true)]));
    Ok(())
}

/// Replacing and clearing either hash erases its predecessor before container drop.
#[test]
fn ntlm_replacement_erases_previous_hashes() -> Result<(), Box<dyn Error>> {
    let mut wire = vec![0; 4];
    wire.extend_from_slice(&3_u32.to_le_bytes());
    wire.extend_from_slice(&[0x41; 16]);
    wire.extend_from_slice(&[0x52; 16]);
    let mut credential = NtlmSupplementalCredential::parse(&wire)?;
    require_owner(&credential.lm_password);
    require_owner(&credential.nt_password);
    REPLACEMENTS.with_borrow_mut(Vec::clear);
    credential.set_lm_password(Some(Zeroizing::new([0x63; 16])));
    credential.set_nt_password(Some(Zeroizing::new([0x74; 16])));
    credential.set_lm_password(None);
    credential.set_nt_password(None);
    REPLACEMENTS.with_borrow(|events| assert_eq!(events.as_slice(), [true; 4]));
    assert!(!credential.has_lm_password());
    assert!(!credential.has_nt_password());
    Ok(())
}

/// Require value-attached erasure in addition to the observable setter wipe.
fn require_owner<T>(_: &T)
where
    T: ZeroizeOnDrop,
{
}
