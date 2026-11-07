//! Checked cryptographic dispatch; raw RFC-vector APIs remain in the parent module.

use super::{CryptoPolicy, KerberosEtype, Use};
use crate::error;

/// An implemented enctype authorized by an immutable runtime-policy snapshot.
///
/// Construction checks permission before any derivation, encryption or checksum.
/// This value is not a key owner and contains no secret material.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Etype(KerberosEtype, Option<u32>);

impl Etype {
    /// Authorize an enctype for checked low-level operations.
    ///
    /// # Errors
    /// Returns typed policy rejection for excluded, disabled or unimplemented IDs.
    #[inline]
    pub fn new(policy: &CryptoPolicy, etype: i32) -> Result<Self, error::Policy> {
        policy.check_use(etype, Use::CheckedLowLevel)?;
        KerberosEtype::from_etype_id(etype)
            .map(|value| Self(value, policy.min_s2k_iterations(etype)))
            .ok_or(error::Policy::EnctypeNotPermitted {
                etype,
                usage: Use::CheckedLowLevel,
            })
    }

    /// Derive a key only after runtime enctype authorization.
    ///
    /// # Errors
    /// Returns the policy minimum rejection or the raw primitive's parameter/derivation error.
    #[inline]
    pub fn string_to_key(
        self,
        secret: &[u8],
        salt: &[u8],
        s2kparams: &str,
    ) -> Result<Vec<u8>, error::Crypto> {
        if let Some(minimum) = self.1 {
            let actual = super::s2kparams_to_iterations(s2kparams)?;
            (actual >= minimum).ok_or(error::Policy::S2kIterationsTooLow {
                etype: self.0.etype_id(),
                minimum,
                actual,
            })?;
        }
        self.0.string_to_key(secret, salt, s2kparams)
    }

    /// Compute an authenticated checksum with the authorized enctype.
    ///
    /// # Errors
    /// Returns key-length or cryptographic errors.
    #[inline]
    pub fn checksum(self, key: &[u8], data: &[u8], usage: u32) -> Result<Vec<u8>, error::Crypto> {
        self.0.checksum(key, data, usage)
    }

    /// Verify a checksum with the authorized enctype.
    ///
    /// # Errors
    /// Returns key-length or integrity errors.
    #[inline]
    pub fn verify_checksum(
        self,
        key: &[u8],
        data: &[u8],
        checksum: &[u8],
        usage: u32,
    ) -> Result<(), error::Crypto> {
        self.0
            .verify_checksum(key, data, checksum, usage)
            .ok_or(error::Crypto::IntegrityCheckFailed)
    }

    /// Encrypt with an explicit caller-supplied confounder.
    ///
    /// # Errors
    /// Returns key, confounder or plaintext validation errors.
    #[inline]
    pub fn encrypt_message_with_confounder(
        self,
        key: &[u8],
        plaintext: &[u8],
        usage: u32,
        confounder: &[u8],
    ) -> Result<Vec<u8>, error::Crypto> {
        self.0
            .encrypt_message_with_confounder(key, plaintext, usage, confounder)
    }

    /// Decrypt and authenticate with the authorized enctype.
    ///
    /// # Errors
    /// Returns key-length, framing or integrity errors.
    #[inline]
    pub fn decrypt_message(
        self,
        key: &[u8],
        ciphertext: &[u8],
        usage: u32,
    ) -> Result<Vec<u8>, error::Crypto> {
        self.0.decrypt_message(key, ciphertext, usage)
    }
}
