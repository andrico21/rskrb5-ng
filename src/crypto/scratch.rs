//! Internal zeroizing scratch ownership.

use core::{
    mem,
    ops::{Deref, DerefMut},
};

use zeroize::{Zeroize as _, Zeroizing};

/// Internal byte-buffer owner, erased on ordinary drop.
pub(super) struct SecretScratch {
    /// Allocation with deterministic cleanup on ordinary drop.
    bytes: Zeroizing<Vec<u8>>,
    /// Owner responsibility, retained only for erasure observations.
    purpose: Purpose,
}

/// Distinct sensitive allocations whose erasure must not mask each other.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Purpose {
    /// All other derived keys and intermediate allocations.
    General,
    /// Password-derived PBKDF2 intermediate consumed by string-to-key.
    Pbkdf2,
    /// Authenticated-message decryption allocation, before tag verification.
    Plaintext,
    /// Last partial CTS block's decrypted allocation.
    CtsTail,
    /// Next-IV copy that a CTS encryption returns beside its ciphertext.
    Iv,
}

impl SecretScratch {
    /// Adopt scratch storage without copying it.
    pub(super) fn new(value: Vec<u8>) -> Self {
        Self {
            bytes: Zeroizing::new(value),
            purpose: Purpose::General,
        }
    }

    /// Adopt a sensitive allocation with its independently observed responsibility.
    pub(super) fn for_purpose(value: Vec<u8>, purpose: Purpose) -> Self {
        Self {
            bytes: Zeroizing::new(value),
            purpose,
        }
    }

    /// Transfer the allocation to a caller that assumes cleanup responsibility.
    pub(super) fn into_vec(mut self) -> Vec<u8> {
        mem::take(&mut *self.bytes)
    }
}

impl Deref for SecretScratch {
    type Target = Vec<u8>;
    fn deref(&self) -> &Self::Target {
        &self.bytes
    }
}

impl DerefMut for SecretScratch {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.bytes
    }
}

// Drop audit: zeroing a heap buffer in place never blocks, allocates or panics
// (the erasure assertion and counter exist only under `cfg(test)`).
impl Drop for SecretScratch {
    /// Erase live bytes; the Zeroizing field also erases spare capacity on drop.
    fn drop(&mut self) {
        let Self {
            bytes: owner,
            purpose,
        } = self;
        let _: &mut Purpose = purpose;
        let bytes = owner.as_mut_slice();
        bytes.zeroize();
        #[cfg(test)]
        {
            assert!(
                bytes.iter().all(|byte| *byte == 0),
                "scratch erasure failed"
            );
            super::tests::ERASED_SCRATCH_BYTES
                .with(|count| count.set(count.get().saturating_add(bytes.len())));
            tests::EVENTS.with_borrow_mut(|events| events.push((*purpose, bytes.len())));
        }
    }
}

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::{cell::RefCell, error::Error};

    use super::Purpose;
    use crate::{
        crypto::{AesSha1Etype, KerberosEtype, prf},
        error::Crypto,
    };

    std::thread_local! {
        /// Exact owner-purpose observations, isolated per test thread.
        pub(super) static EVENTS: RefCell<Vec<(Purpose, usize)>> = const { RefCell::new(Vec::new()) };
    }

    /// Each AES PBKDF2 intermediate is erased independently of derived keys.
    #[test]
    fn pbkdf2_owner_erasure_is_independent() -> Result<(), Box<dyn Error>> {
        // Given each AES family with a minimal test work factor.
        for id in [17_i32, 18_i32, 19_i32, 20_i32] {
            let etype = KerberosEtype::from_etype_id(id).ok_or("etype")?;
            EVENTS.with_borrow_mut(Vec::clear);
            // When string-to-key consumes its password-derived intermediate.
            let key = etype.string_to_key(b"password marker", b"salt", "00000001")?;
            // Then exactly that owner, not another key guard, records its full length.
            EVENTS.with_borrow(|events| {
                assert_eq!(
                    events
                        .iter()
                        .copied()
                        .filter(|(purpose, _)| *purpose == Purpose::Pbkdf2)
                        .collect::<Vec<_>>(),
                    [(Purpose::Pbkdf2, etype.key_len())]
                );
            });
            assert_eq!(key.len(), etype.key_len());
        }
        Ok(())
    }

    /// Bad plaintext-MAC messages erase plaintext while SHA2 never decrypts.
    #[test]
    fn plaintext_owner_erasure_is_independent() -> Result<(), Box<dyn Error>> {
        // Given real ciphertext with a changed authentication tag in every family.
        for id in [16_i32, 17_i32, 18_i32, 19_i32, 20_i32, 23_i32] {
            let etype = KerberosEtype::from_etype_id(id).ok_or("etype")?;
            let key = vec![0x42; etype.key_len()];
            let mut ciphertext = etype.encrypt_message_with_confounder(
                &key,
                b"plaintext marker",
                2,
                &vec![0x24; etype.confounder_len()],
            )?;
            let position = if id == 23_i32 {
                0
            } else {
                ciphertext.len().saturating_sub(1)
            };
            *ciphertext.get_mut(position).ok_or("tag byte")? ^= 1;
            EVENTS.with_borrow_mut(Vec::clear);
            // When integrity verification rejects the input.
            let result = etype.decrypt_message(&key, &ciphertext, 2);
            // Then exactly the expected plaintext owner is erased, or never exists for SHA2.
            assert_eq!(result, Err(Crypto::IntegrityCheckFailed));
            let expected = match id {
                19_i32 | 20_i32 => Vec::new(),
                _ => vec![(
                    Purpose::Plaintext,
                    etype.confounder_len().saturating_add(16),
                )],
            };
            EVENTS.with_borrow(|events| {
                assert_eq!(
                    events
                        .iter()
                        .copied()
                        .filter(|(purpose, _)| *purpose == Purpose::Plaintext)
                        .collect::<Vec<_>>(),
                    expected
                );
            });
        }
        Ok(())
    }

    /// CTS tail cleanup cannot be satisfied by its surrounding plaintext guard.
    #[test]
    fn cts_tail_owner_erasure_is_independent() -> Result<(), Box<dyn Error>> {
        // Given a raw AES ciphertext with a one-byte stolen tail.
        let etype = AesSha1Etype::Aes128;
        let (_, ciphertext) = etype.encrypt_data(&[0x42; 16], &[0x33; 33])?;
        EVENTS.with_borrow_mut(Vec::clear);
        // When the real CTS implementation reconstructs the last block.
        let plaintext = etype.decrypt_data(&[0x42; 16], &ciphertext)?;
        // Then the exact sixteen-byte tail owner is observed independently.
        assert_eq!(plaintext, [0x33; 33]);
        EVENTS.with_borrow(|events| {
            assert_eq!(
                events
                    .iter()
                    .copied()
                    .filter(|(purpose, _)| *purpose == Purpose::CtsTail)
                    .collect::<Vec<_>>(),
                [(Purpose::CtsTail, 16)]
            );
        });
        Ok(())
    }

    /// A PRF block that needs only the ciphertext erases the IV copy beside it.
    #[test]
    fn prf_iv_owner_erasure_is_independent() -> Result<(), Box<dyn Error>> {
        // Given every family and the length of the IV its CTS encryption returns, if any.
        for (id, iv_len) in [
            (16_i32, Some(8_usize)),
            (17_i32, Some(16)),
            (18_i32, Some(16)),
            (19_i32, None),
            (20_i32, None),
            (23_i32, None),
        ] {
            let etype = KerberosEtype::from_etype_id(id).ok_or("etype")?;
            let key = vec![0x42; etype.key_len()];
            EVENTS.with_borrow_mut(Vec::clear);
            // When one PRF block is computed from the key.
            let block = prf::pseudo_random(&prf::Key::new(etype, &key), b"prf input")?;
            // Then exactly the IV copy, never the result owner, is erased as an IV.
            assert!(!block.is_empty(), "etype {id}");
            EVENTS.with_borrow(|events| {
                assert_eq!(
                    events
                        .iter()
                        .copied()
                        .filter(|(purpose, _)| *purpose == Purpose::Iv)
                        .collect::<Vec<_>>(),
                    iv_len
                        .map(|len| (Purpose::Iv, len))
                        .into_iter()
                        .collect::<Vec<_>>(),
                    "etype {id}"
                );
            });
        }
        Ok(())
    }
}
