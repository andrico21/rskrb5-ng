//! RFC 6803 section 6 CBC-CTS with a zero initial IV, shared with the AES helpers.

use camellia::{Camellia128, Camellia256};

use super::etype::CamelliaCtsCmacEtype;
use crate::{
    crypto::{
        AES_BLOCK_SIZE, SecretScratch, cbc_encrypt, cts_decrypt, keyed_cipher,
        swap_last_two_blocks, zero_pad,
    },
    error::Crypto as Error,
};

/// CTS-encrypt `plaintext`; returns `(next_iv, ciphertext)` like the AES helpers.
///
/// A plaintext of at most one block is zero-padded and returned without stealing.
///
/// # Errors
/// Returns [`Error::EmptyPlaintext`] for an empty plaintext and
/// [`Error::InvalidKeyLength`] when `key` is not the key size of `etype`.
pub(super) fn encrypt(
    etype: CamelliaCtsCmacEtype,
    key: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), Error> {
    if plaintext.is_empty() {
        return Err(Error::EmptyPlaintext);
    }
    let mut padded = SecretScratch::new(Vec::with_capacity(
        plaintext.len().saturating_add(AES_BLOCK_SIZE - 1),
    ));
    padded.extend_from_slice(plaintext);
    zero_pad(&mut padded, AES_BLOCK_SIZE);
    let (mut ciphertext, last_block) = match etype {
        CamelliaCtsCmacEtype::Camellia128 => {
            cbc_encrypt(&keyed_cipher::<Camellia128>(key)?, &padded)
        }
        CamelliaCtsCmacEtype::Camellia256 => {
            cbc_encrypt(&keyed_cipher::<Camellia256>(key)?, &padded)
        }
    };
    if plaintext.len() > AES_BLOCK_SIZE {
        swap_last_two_blocks(&mut ciphertext);
        ciphertext.truncate(plaintext.len());
    }
    Ok((last_block.to_vec(), ciphertext))
}

/// CTS-decrypt `ciphertext` of at least one block.
///
/// # Errors
/// Returns [`Error::CiphertextTooShort`] for less than one block and
/// [`Error::InvalidKeyLength`] when `key` is not the key size of `etype`.
pub(super) fn decrypt(
    etype: CamelliaCtsCmacEtype,
    key: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, Error> {
    if ciphertext.len() < AES_BLOCK_SIZE {
        return Err(Error::CiphertextTooShort {
            minimum: AES_BLOCK_SIZE,
            actual: ciphertext.len(),
        });
    }
    Ok(match etype {
        CamelliaCtsCmacEtype::Camellia128 => {
            cts_decrypt(&keyed_cipher::<Camellia128>(key)?, ciphertext)
        }
        CamelliaCtsCmacEtype::Camellia256 => {
            cts_decrypt(&keyed_cipher::<Camellia256>(key)?, ciphertext)
        }
    })
}
