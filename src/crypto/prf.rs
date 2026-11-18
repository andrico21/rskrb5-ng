//! Kerberos PRF primitives over the shared per-enctype PRF.
//!
//! RFC 6113 section 5.1 defines `PRF+` with a one-octet counter that starts at one
//! ([`fast_prf_plus`], [`krb_fx_cf2`]); RFC 4402 section 2 defines the GSS
//! `pseudo_random` stream with a four-octet big-endian counter that starts at zero
//! ([`gss_prf_plus`]). They are different functions with different output.
//!
//! Every function takes the key as a [`Key`], a borrowed view that names the
//! enctype, so the key bytes are never copied into a long-lived owner here.
//! Returned values are [`Zeroizing`] owners. Like the rest of [`crate::crypto`],
//! these primitives are policy-free: availability is not permission.

use core::fmt;

use sha1::{Digest as _, Sha1};
use zeroize::Zeroizing;

use super::{
    DES3_SEED_SIZE, Des3CbcSha1KdEtype, KerberosEtype, RC4_HMAC_KEY_SIZE, Rc4HmacEtype,
    SecretScratch, hmac_sha1,
};
use crate::error::Crypto as Error;

/// Most blocks RFC 6113 can address with its one-octet counter.
const FAST_PRF_PLUS_MAX_BLOCKS: usize = 255;
/// Hash prefix length of the RFC 3961 PRF, a whole number of cipher blocks.
const DK_PRF_HASH_PREFIX: usize = 16;
/// RFC 3961 derivation constant of the PRF key.
const PRF_CONSTANT: &[u8] = b"prf";

/// Largest [`gss_prf_plus`] output in bytes.
///
/// RFC 4402 leaves the length to the caller; this local bound keeps one call from
/// allocating without limit (executor decision, MIT has no bound).
pub const GSS_PRF_PLUS_MAX_OUTPUT: usize = 1 << 20;

/// A key and the enctype whose PRF it feeds; a borrowed view with redacted `Debug`.
#[derive(Clone, Copy)]
pub struct Key<'key> {
    /// Enctype of the key.
    etype: KerberosEtype,
    /// Protocol key bytes, borrowed from the caller's owner.
    material: &'key [u8],
}

impl<'key> Key<'key> {
    /// Pair `material` with the enctype that selects its PRF.
    #[inline]
    #[must_use]
    pub const fn new(etype: KerberosEtype, material: &'key [u8]) -> Self {
        Self { etype, material }
    }
}

impl fmt::Debug for Key<'_> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Key")
            .field("etype", &self.etype.etype_id())
            .field("material", &"<redacted>")
            .finish()
    }
}

/// One side of [`krb_fx_cf2`]: a key and its pepper string.
#[derive(Clone, Copy, Debug)]
pub struct CfInput<'input> {
    /// The key that feeds this side's `PRF+`.
    key: Key<'input>,
    /// The pepper, the `PRF+` input.
    pepper: &'input [u8],
}

impl<'input> CfInput<'input> {
    /// Pair a key with its pepper.
    #[inline]
    #[must_use]
    pub const fn new(key: Key<'input>, pepper: &'input [u8]) -> Self {
        Self { key, pepper }
    }
}

/// The counter of one `PRF+` flavour.
#[derive(Clone, Copy)]
enum Counter {
    /// RFC 6113 section 5.1: one octet, starting at 1.
    OneOctet,
    /// RFC 4402 section 2: four octets, network order, starting at 0.
    FourOctets,
}

impl Counter {
    /// Number of counter octets before the input.
    const fn width(self) -> usize {
        match self {
            Self::OneOctet => 1,
            Self::FourOctets => 4,
        }
    }

    /// Value of the counter for the first block.
    const fn first(self) -> u32 {
        match self {
            Self::OneOctet => 1,
            Self::FourOctets => 0,
        }
    }
}

/// Size in bytes of one PRF output block of `etype`.
#[inline]
#[must_use]
pub const fn output_len(etype: KerberosEtype) -> usize {
    match etype {
        KerberosEtype::Sha1(_) | KerberosEtype::Des3CbcSha1Kd(_) | KerberosEtype::Camellia(_) => 16,
        KerberosEtype::Sha2(family) => family.hash_len(),
        KerberosEtype::Rc4Hmac(_) => 20,
    }
}

/// Number of random bytes the `random-to-key` function of `etype` consumes.
const fn seed_len(etype: KerberosEtype) -> usize {
    match etype {
        KerberosEtype::Des3CbcSha1Kd(_) => DES3_SEED_SIZE,
        KerberosEtype::Rc4Hmac(_) => RC4_HMAC_KEY_SIZE,
        KerberosEtype::Sha1(_) | KerberosEtype::Sha2(_) | KerberosEtype::Camellia(_) => {
            etype.key_len()
        }
    }
}

/// The `random-to-key` function of `etype`.
///
/// # Errors
/// Returns the seed-length error of the enctype's function.
fn random_to_key(etype: KerberosEtype, seed: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
    Ok(Zeroizing::new(match etype {
        KerberosEtype::Des3CbcSha1Kd(_) => Des3CbcSha1KdEtype::random_to_key(seed)?,
        KerberosEtype::Rc4Hmac(_) => Rc4HmacEtype::random_to_key(seed)?,
        KerberosEtype::Sha1(_) | KerberosEtype::Sha2(_) | KerberosEtype::Camellia(_) => {
            seed.to_vec()
        }
    }))
}

/// A key checked for length, with the PRF subkey derived once for the families that use one.
struct Prepared<'key> {
    /// The key whose PRF this is.
    key: Key<'key>,
    /// `DK(key, "prf")` for the RFC 3961 families; empty for the others.
    subkey: SecretScratch,
}

impl<'key> Prepared<'key> {
    /// Check the key length and derive the PRF subkey.
    ///
    /// # Errors
    /// Returns [`Error::InvalidKeyLength`] or the derivation error of the subkey.
    fn new(key: Key<'key>) -> Result<Self, Error> {
        let expected = key.etype.key_len();
        if key.material.len() != expected {
            return Err(Error::InvalidKeyLength {
                expected,
                actual: key.material.len(),
            });
        }
        let subkey = match key.etype {
            KerberosEtype::Sha1(family) => family.derive_key(key.material, PRF_CONSTANT)?,
            KerberosEtype::Des3CbcSha1Kd(_) => {
                Des3CbcSha1KdEtype::derive_key(key.material, PRF_CONSTANT)?
            }
            KerberosEtype::Camellia(family) => family.prf_subkey(key.material)?,
            KerberosEtype::Sha2(_) | KerberosEtype::Rc4Hmac(_) => Vec::new(),
        };
        Ok(Self {
            key,
            subkey: SecretScratch::new(subkey),
        })
    }

    /// One PRF block over `input`.
    ///
    /// # Errors
    /// Returns the error of the enctype's PRF.
    fn apply(&self, input: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
        let block = match self.key.etype {
            KerberosEtype::Sha1(family) => {
                family.encrypt_data(&self.subkey, &hash_prefix(input))?.1
            }
            KerberosEtype::Des3CbcSha1Kd(_) => {
                Des3CbcSha1KdEtype::encrypt_data(&self.subkey, &hash_prefix(input))?.1
            }
            KerberosEtype::Sha2(family) => family.derive_random(self.key.material, input)?,
            KerberosEtype::Rc4Hmac(_) => hmac_sha1(self.key.material, input),
            KerberosEtype::Camellia(family) => family.prf_block(&self.subkey, input)?,
        };
        Ok(Zeroizing::new(block))
    }
}

/// The first 16 bytes of SHA-1 over `input`, the plaintext of the RFC 3961 PRF.
fn hash_prefix(input: &[u8]) -> Zeroizing<Vec<u8>> {
    let digest = Sha1::digest(input);
    Zeroizing::new(digest.iter().copied().take(DK_PRF_HASH_PREFIX).collect())
}

/// One block of the per-enctype PRF of `key` over `input`.
///
/// # Errors
/// Returns [`Error::InvalidKeyLength`] when the key does not have the length of its enctype.
///
/// # Security
/// The output is as secret as the key. It is zeroed when the owner drops.
#[inline]
pub fn pseudo_random(key: &Key<'_>, input: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
    Prepared::new(*key)?.apply(input)
}

/// `PRF+(key, input)` of RFC 6113 section 5.1, truncated to `len` bytes.
///
/// # Errors
/// Returns [`Error::InvalidKeyLength`] for a key of the wrong length and
/// [`Error::PrfOutputTooLong`] when `len` needs more than 255 blocks.
///
/// # Security
/// The output is as secret as the key. It is zeroed when the owner drops.
#[inline]
pub fn fast_prf_plus(key: &Key<'_>, input: &[u8], len: usize) -> Result<Zeroizing<Vec<u8>>, Error> {
    let maximum = FAST_PRF_PLUS_MAX_BLOCKS.saturating_mul(output_len(key.etype));
    plus(key, input, len, maximum, Counter::OneOctet)
}

/// `KRB-FX-CF2(key1, key2, pepper1, pepper2)` of RFC 6113 section 5.1: the
/// `random-to-key` of `PRF+(key1, pepper1) XOR PRF+(key2, pepper2)`.
///
/// The result is a key of the first key's enctype. Each `PRF+` has the seed length
/// of that enctype, whatever the enctype of the second key.
///
/// # Errors
/// Returns [`Error::InvalidKeyLength`] for a key of the wrong length and the
/// error of the `random-to-key` function of the first enctype.
///
/// # Security
/// The result is a protocol key: it is zeroed when the owner drops.
#[inline]
pub fn krb_fx_cf2(first: &CfInput<'_>, second: &CfInput<'_>) -> Result<Zeroizing<Vec<u8>>, Error> {
    let seed = seed_len(first.key.etype);
    let left = fast_prf_plus(&first.key, first.pepper, seed)?;
    let right = fast_prf_plus(&second.key, second.pepper, seed)?;
    let combined: Zeroizing<Vec<u8>> = Zeroizing::new(
        left.iter()
            .zip(right.iter())
            .map(|(lhs, rhs)| lhs ^ rhs)
            .collect(),
    );
    random_to_key(first.key.etype, &combined)
}

/// The `PRF+` stream of RFC 4402 section 2 (GSS `pseudo_random`), `len` bytes.
///
/// The caller selects the key (subkey or acceptor subkey) as the GSS layer's
/// `prf_key` argument says.
///
/// # Errors
/// Returns [`Error::InvalidKeyLength`] for a key of the wrong length and
/// [`Error::PrfOutputTooLong`] when `len` exceeds [`GSS_PRF_PLUS_MAX_OUTPUT`].
///
/// # Security
/// The output is as secret as the key. It is zeroed when the owner drops.
#[inline]
pub fn gss_prf_plus(key: &Key<'_>, input: &[u8], len: usize) -> Result<Zeroizing<Vec<u8>>, Error> {
    plus(
        key,
        input,
        len,
        GSS_PRF_PLUS_MAX_OUTPUT,
        Counter::FourOctets,
    )
}

/// `PRF(counter | input)` for consecutive counters, concatenated and cut to `len`.
///
/// # Errors
/// Returns [`Error::InvalidKeyLength`] or [`Error::PrfOutputTooLong`] when `len` exceeds `maximum`.
fn plus(
    key: &Key<'_>,
    input: &[u8],
    len: usize,
    maximum: usize,
    counter: Counter,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let too_long = Error::PrfOutputTooLong {
        maximum,
        requested: len,
    };
    let prepared = Prepared::new(*key)?;
    (len <= maximum).ok_or(too_long)?;
    let width = counter.width();
    let block_len = output_len(key.etype);
    let blocks = u32::try_from(len.div_ceil(block_len)).map_err(|_overflow| too_long)?;
    let mut message = Zeroizing::new(vec![0; width]);
    message.extend_from_slice(input);
    let mut out = Zeroizing::new(Vec::with_capacity(
        usize::try_from(blocks)
            .map_err(|_overflow| too_long)?
            .saturating_mul(block_len),
    ));
    for index in counter.first()..counter.first().saturating_add(blocks) {
        let octets = index.to_be_bytes();
        let counter_octets = octets.get(octets.len().saturating_sub(width)..);
        message
            .iter_mut()
            .zip(counter_octets.unwrap_or_default())
            .for_each(|(slot, octet)| *slot = *octet);
        out.extend_from_slice(&prepared.apply(&message)?);
    }
    out.truncate(len);
    Ok(out)
}
