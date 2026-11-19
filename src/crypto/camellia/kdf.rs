//! RFC 6803 section 3 key derivation and section 5 CMAC over Camellia.

use camellia::{Camellia128, Camellia256};
use cmac::{Cmac, KeyInit, Mac, block_api::CmacCipher, digest::InvalidLength};
use zeroize::Zeroizing;

use super::CtsCmacEtype;
use crate::error::Crypto as Error;

/// CMAC output and Camellia block size in bytes.
const BLOCK: usize = 16;

/// CMAC (NIST SP 800-38B) of the concatenation of `parts`, keyed with `key`.
///
/// # Errors
/// Returns [`Error::InvalidKeyLength`] when `key` is not the key size of `etype`.
pub(super) fn cmac(
    etype: CtsCmacEtype,
    key: &[u8],
    parts: &[&[u8]],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    match etype {
        CtsCmacEtype::Camellia128 => tag::<Camellia128>(key, parts),
        CtsCmacEtype::Camellia256 => tag::<Camellia256>(key, parts),
    }
    .map_err(|InvalidLength| Error::InvalidKeyLength {
        expected: etype.key_len(),
        actual: key.len(),
    })
}

/// The CMAC tag with the block cipher `C`.
///
/// # Errors
/// Returns [`InvalidLength`] when `key` is not a key size of `C`.
fn tag<C>(key: &[u8], parts: &[&[u8]]) -> Result<Zeroizing<Vec<u8>>, InvalidLength>
where
    C: CmacCipher,
    Cmac<C>: Mac + KeyInit,
{
    let mut mac = <Cmac<C> as KeyInit>::new_from_slice(key)?;
    for part in parts {
        mac.update(part);
    }
    Ok(Zeroizing::new(mac.finalize().into_bytes().to_vec()))
}

/// Check `expected` against the CMAC of `data` in constant time.
pub(super) fn verify(etype: CtsCmacEtype, key: &[u8], data: &[u8], expected: &[u8]) -> bool {
    expected.len() == BLOCK
        && match etype {
            CtsCmacEtype::Camellia128 => check::<Camellia128>(key, data, expected),
            CtsCmacEtype::Camellia256 => check::<Camellia256>(key, data, expected),
        }
}

/// Constant-time CMAC verification with the block cipher `C`.
fn check<C>(key: &[u8], data: &[u8], expected: &[u8]) -> bool
where
    C: CmacCipher,
    Cmac<C>: Mac + KeyInit,
{
    <Cmac<C> as KeyInit>::new_from_slice(key).is_ok_and(|mut mac| {
        mac.update(data);
        mac.verify_slice(expected).is_ok()
    })
}

/// `KDF-FEEDBACK-CMAC(key, constant)`: SP 800-108 feedback mode with a four-octet
/// counter, `K(i) = CMAC(key, K(i-1) | [i]4 | constant | 0x00 | [k]4)` and `K(0)` zero.
///
/// MIT 1.22.2 `src/lib/crypto/builtin/kdf.c` `k5_sp800_108_feedback_cmac`.
///
/// # Errors
/// Returns [`Error::EmptyUsage`] for an empty `constant` and [`Error::InvalidKeyLength`]
/// when `key` is not the key size of `etype`.
pub(super) fn derive(
    etype: CtsCmacEtype,
    key: &[u8],
    constant: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    if constant.is_empty() {
        return Err(Error::EmptyUsage);
    }
    let key_len = etype.key_len();
    let output_bits = u32::try_from(key_len.saturating_mul(8)).unwrap_or(u32::MAX);
    let mut previous = Zeroizing::new(vec![0; BLOCK]);
    let mut out = Zeroizing::new(Vec::with_capacity(key_len));
    let mut counter = 0_u32;
    while out.len() < key_len {
        counter = counter.saturating_add(1);
        let block = cmac(
            etype,
            key,
            &[
                &previous,
                &counter.to_be_bytes(),
                constant,
                &[0],
                &output_bits.to_be_bytes(),
            ],
        )?;
        out.extend_from_slice(&block);
        previous = block;
    }
    Ok(out)
}
