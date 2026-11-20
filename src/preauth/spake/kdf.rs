//! RFC 9588 sections 5 to 7: the multiplier input, the transcript hash and `K'[n]`.

use sha2::{Digest, Sha256, Sha384, Sha512};
use zeroize::Zeroizing;

use super::{Derivation, Params};
use crate::{
    crypto::{KerberosEtype, prf},
    error::{Crypto, Policy, Spake as Error},
    keytab::EncryptionKey,
};

/// A group's hash function over the concatenation of its arguments.
pub(super) type Hash = fn(&[&[u8]]) -> Vec<u8>;

/// SHA-256 over the concatenation of `parts`.
pub(super) fn sha256(parts: &[&[u8]]) -> Vec<u8> {
    parts
        .iter()
        .fold(Sha256::new(), Digest::chain_update)
        .finalize()
        .to_vec()
}

/// SHA-384 over the concatenation of `parts`.
pub(super) fn sha384(parts: &[&[u8]]) -> Vec<u8> {
    parts
        .iter()
        .fold(Sha384::new(), Digest::chain_update)
        .finalize()
        .to_vec()
}

/// SHA-512 over the concatenation of `parts`.
pub(super) fn sha512(parts: &[&[u8]]) -> Vec<u8> {
    parts
        .iter()
        .fold(Sha512::new(), Digest::chain_update)
        .finalize()
        .to_vec()
}

/// The enctype of a reply key, as an implemented algorithm.
///
/// # Errors
/// Returns an unknown-enctype policy error for an enctype without an implementation.
fn etype(key: &EncryptionKey) -> Result<KerberosEtype, Error> {
    KerberosEtype::from_etype_id(key.etype()).ok_or_else(|| {
        Error::Crypto(Crypto::Policy(Policy::UnknownEnctype {
            etype: key.etype(),
        }))
    })
}

/// Section 5: `PRF+(K, "SPAKEsecret" || group)`, `len` bytes (MIT `util.c:104-141`).
///
/// # Errors
/// Returns the PRF errors of the reply key.
pub(super) fn multiplier(
    key: &EncryptionKey,
    group: i32,
    len: usize,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let mut pepper = b"SPAKEsecret".to_vec();
    pepper.extend_from_slice(&group.to_be_bytes());
    Ok(prf::fast_prf_plus(
        &prf::Key::new(etype(key)?, key.value()),
        &pepper,
        len,
    )?)
}

/// Section 6: the transcript hash `thash` (all zeros when `None`) updated with
/// the concatenation of `parts` (MIT `util.c:74-99`).
pub(super) fn update(params: &Params, thash: Option<&[u8]>, parts: &[&[u8]]) -> Vec<u8> {
    let zeros = vec![0_u8; params.hash_len];
    let mut all: Vec<&[u8]> = vec![thash.unwrap_or(&zeros)];
    all.extend_from_slice(parts);
    (params.hash)(&all)
}

/// Section 7: `K'[number]`, a key of the initial reply key's enctype (MIT `util.c:148-212`).
///
/// # Errors
/// Returns the enctype, `random-to-key` and `KRB-FX-CF2` errors.
pub(super) fn derive(input: &Derivation<'_>, number: u32) -> Result<EncryptionKey, Error> {
    let etype = etype(input.key)?;
    let seed_len = prf::seed_len(etype);
    let (group, enctype, index) = (
        input.params.id.to_be_bytes(),
        input.key.etype().to_be_bytes(),
        number.to_be_bytes(),
    );
    let mut seed: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(seed_len));
    let mut counter = 1_u8;
    while seed.len() < seed_len {
        let block = Zeroizing::new((input.params.hash)(&[
            b"SPAKEkey",
            &group,
            &enctype,
            input.wbytes,
            input.result,
            input.thash,
            input.body,
            &index,
            &[counter],
        ]));
        seed.extend_from_slice(&block);
        counter = counter.checked_add(1).ok_or_else(|| {
            Error::Crypto(Crypto::PrfOutputTooLong {
                maximum: usize::from(u8::MAX),
                requested: seed_len,
            })
        })?;
    }
    seed.truncate(seed_len);
    let intermediate = prf::random_to_key(etype, &seed)?;
    let derived = prf::krb_fx_cf2(
        &prf::CfInput::new(prf::Key::new(etype, input.key.value()), b"SPAKE"),
        &prf::CfInput::new(prf::Key::new(etype, &intermediate), b"keyderiv"),
    )?;
    Ok(EncryptionKey::new(input.key.etype(), derived.to_vec()))
}
