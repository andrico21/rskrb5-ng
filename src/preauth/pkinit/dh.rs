//! Key agreement for PKINIT.
//!
//! Finite-field Diffie-Hellman over the RFC 3526 MODP groups (RFC 4556
//! section 3.2.3.1) and ECDH over the NIST curves (RFC 5349), as MIT 1.22.2
//! `pkinit_crypto_openssl.c:2873-3010` proposes and checks them.
//!
//! The admitted crates compute: `crypto-bigint`'s constant-time Montgomery
//! exponentiation for the MODP groups, the `p256`/`p384`/`p521` constant-time
//! scalar multiplication for the curves. This module implements no field or
//! group arithmetic.

use core::ops::Mul as _;

use crypto_bigint::{
    Odd, U2048, U4096, Uint,
    modular::{FixedMontyForm, FixedMontyParams},
};
use der::{
    Decode as _, Encode as _, Sequence,
    asn1::{Any, BitString, ObjectIdentifier, Uint as DerUint, UintRef},
};
use p256::elliptic_curve::{
    CurveArithmetic, FieldBytes, FieldBytesSize,
    ff::{Field as _, PrimeField as _},
    group::{Curve as _, Group as _},
    sec1::{FromSec1Point, ModulusSize, Sec1Point, ToSec1Point},
};
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use zeroize::{Zeroize as _, Zeroizing};

use super::{
    super::DhGroup,
    primes::{MODP_2048, MODP_4096},
};
use crate::error::Pkinit as Error;

/// `dhpublicnumber` (ANSI X9.42, RFC 3279 section 2.3.3).
const DH_PUBLIC_NUMBER: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10046.2.1");
/// `id-ecPublicKey` (RFC 5480).
const EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
/// `secp256r1`.
const SECP256R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
/// `secp384r1`.
const SECP384R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
/// `secp521r1`.
const SECP521R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.35");
/// Most candidates a private-key rejection sampling draws.
const MAX_DRAWS: usize = 64;

/// `DomainParameters` (RFC 3279 section 2.3.3) as MIT encodes it: `p`, `g`, `q`.
#[derive(Sequence)]
struct DomainParameters {
    /// The prime `p`.
    prime: DerUint,
    /// The generator `g`, 2.
    generator: DerUint,
    /// The subgroup order `q = (p - 1) / 2`.
    order: DerUint,
}

/// The client's ephemeral private key, erased when dropped.
pub(super) enum Ephemeral {
    /// A 2048-bit MODP exponent.
    Modp2048(Box<Zeroizing<U2048>>),
    /// A 4096-bit MODP exponent.
    Modp4096(Box<Zeroizing<U4096>>),
    /// A P-256 scalar.
    P256(Zeroizing<p256::Scalar>),
    /// A P-384 scalar.
    P384(Zeroizing<p384::Scalar>),
    /// A P-521 scalar.
    P521(Zeroizing<p521::Scalar>),
}

/// Fill `bytes` from the OS generator.
///
/// # Errors
/// Returns [`Error::Random`].
fn random(bytes: &mut [u8]) -> Result<(), Error> {
    getrandom::fill(bytes).map_err(Error::from)
}

/// The DER `SubjectPublicKeyInfo` of `oid` with `parameters` and `key`.
///
/// # Errors
/// Returns [`Error::Malformed`] when encoding fails.
fn spki(oid: ObjectIdentifier, parameters: Any, key: &[u8]) -> Result<Vec<u8>, Error> {
    let malformed = |_detail: der::Error| Error::Malformed {
        structure: "SubjectPublicKeyInfo",
        reason: "cannot be encoded",
    };
    SubjectPublicKeyInfoOwned {
        algorithm: AlgorithmIdentifierOwned {
            oid,
            parameters: Some(parameters),
        },
        subject_public_key: BitString::from_bytes(key).map_err(malformed)?,
    }
    .to_der()
    .map_err(malformed)
}

/// A fresh key in `group` and the DER `SubjectPublicKeyInfo` of its public half.
///
/// # Errors
/// Returns [`Error::Random`] and the encoding errors.
pub(super) fn generate(group: DhGroup) -> Result<(Ephemeral, Vec<u8>), Error> {
    match group {
        DhGroup::Modp2048 => modp::<{ U2048::LIMBS }>(&MODP_2048)
            .map(|(secret, public)| (Ephemeral::Modp2048(Box::new(secret)), public)),
        DhGroup::Modp4096 => modp::<{ U4096::LIMBS }>(&MODP_4096)
            .map(|(secret, public)| (Ephemeral::Modp4096(Box::new(secret)), public)),
        DhGroup::P256 => curve::<p256::NistP256>(SECP256R1, 0xff)
            .map(|(secret, public)| (Ephemeral::P256(secret), public)),
        DhGroup::P384 => curve::<p384::NistP384>(SECP384R1, 0xff)
            .map(|(secret, public)| (Ephemeral::P384(secret), public)),
        DhGroup::P521 => curve::<p521::NistP521>(SECP521R1, 0x01)
            .map(|(secret, public)| (Ephemeral::P521(secret), public)),
    }
}

/// The shared secret of `ephemeral` and the KDC's public value `theirs`
/// (`KDCDHKeyInfo.subjectPublicKey`), left-padded to the group size.
///
/// # Errors
/// Returns [`Error::PublicValue`] for an invalid public value.
pub(super) fn agree(ephemeral: &Ephemeral, theirs: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
    match ephemeral {
        Ephemeral::Modp2048(secret) => modp_agree::<{ U2048::LIMBS }>(&MODP_2048, secret, theirs),
        Ephemeral::Modp4096(secret) => modp_agree::<{ U4096::LIMBS }>(&MODP_4096, secret, theirs),
        Ephemeral::P256(secret) => curve_agree::<p256::NistP256>(secret, theirs),
        Ephemeral::P384(secret) => curve_agree::<p384::NistP384>(secret, theirs),
        Ephemeral::P521(secret) => curve_agree::<p521::NistP521>(secret, theirs),
    }
}

/// The prime, its Montgomery parameters and the subgroup order of `prime`.
///
/// # Errors
/// Returns [`Error::Malformed`] for an even prime (never for the built-in ones).
fn modulus<const LIMBS: usize>(
    prime: &[u8],
) -> Result<(Uint<LIMBS>, FixedMontyParams<LIMBS>, Uint<LIMBS>), Error> {
    let modulus = Uint::<LIMBS>::from_be_slice(prime);
    let odd = Option::<Odd<Uint<LIMBS>>>::from(Odd::new(modulus)).ok_or(Error::Malformed {
        structure: "MODP group",
        reason: "the prime is even",
    })?;
    Ok((
        modulus,
        FixedMontyParams::new_vartime(odd),
        modulus.shr_vartime(1),
    ))
}

/// A MODP key: `x` uniform in `[2, q - 2]`, `y = 2^x mod p`.
///
/// # Errors
/// As [`generate`].
fn modp<const LIMBS: usize>(prime: &[u8]) -> Result<(Zeroizing<Uint<LIMBS>>, Vec<u8>), Error> {
    let (modulus_value, params, order) = modulus::<LIMBS>(prime)?;
    let two = Uint::<LIMBS>::from_u8(2);
    let upper = order.wrapping_sub(&two);
    let mut draw = Zeroizing::new(vec![0_u8; prime.len()]);
    for _ in 0..MAX_DRAWS {
        random(&mut draw)?;
        if let Some(top) = draw.first_mut() {
            *top &= 0x7f;
        }
        let candidate = Zeroizing::new(Uint::<LIMBS>::from_be_slice(&draw));
        if *candidate >= two && *candidate <= upper {
            draw.zeroize();
            let public = FixedMontyForm::new(&two, &params)
                .pow(&*candidate)
                .retrieve();
            let encode = |value: &Uint<LIMBS>| value.to_be_bytes();
            let (pb, gb, qb, yb) = (
                encode(&modulus_value),
                encode(&two),
                encode(&order),
                encode(&public),
            );
            let parameters = DomainParameters {
                prime: integer(pb.as_ref())?,
                generator: integer(gb.as_ref())?,
                order: integer(qb.as_ref())?,
            }
            .to_der()
            .map_err(unencodable)?;
            let key = integer(yb.as_ref())?.to_der().map_err(unencodable)?;
            let any = Any::from_der(&parameters).map_err(unencodable)?;
            return Ok((candidate, spki(DH_PUBLIC_NUMBER, any, &key)?));
        }
    }
    Err(Error::Malformed {
        structure: "DH key",
        reason: "the random generator produced no valid exponent",
    })
}

/// The error of a failed encoding.
const fn unencodable(_detail: der::Error) -> Error {
    Error::Malformed {
        structure: "DomainParameters",
        reason: "cannot be encoded",
    }
}

/// The DER INTEGER of the big-endian unsigned `bytes`.
///
/// # Errors
/// Returns [`Error::Malformed`] when encoding fails.
fn integer(bytes: &[u8]) -> Result<DerUint, Error> {
    DerUint::new(strip(bytes)).map_err(unencodable)
}

/// `bytes` without leading zeros (at least one byte).
fn strip(bytes: &[u8]) -> &[u8] {
    let first = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or_else(|| bytes.len().saturating_sub(1));
    bytes.get(first..).unwrap_or(bytes)
}

/// `theirs^x mod p` after checking `2 <= theirs <= p - 2` and `theirs^q = 1`.
///
/// # Errors
/// Returns [`Error::PublicValue`].
fn modp_agree<const LIMBS: usize>(
    prime: &[u8],
    secret: &Uint<LIMBS>,
    theirs: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let (modulus_value, params, order) = modulus::<LIMBS>(prime)?;
    let integer = UintRef::from_der(theirs).map_err(|_detail| Error::PublicValue)?;
    let magnitude = integer.as_bytes();
    if magnitude.len() > prime.len() {
        return Err(Error::PublicValue);
    }
    let mut padded = vec![0_u8; prime.len()];
    let start = prime.len().saturating_sub(magnitude.len());
    padded
        .get_mut(start..)
        .ok_or(Error::PublicValue)?
        .copy_from_slice(magnitude);
    let value = Uint::<LIMBS>::from_be_slice(&padded);
    let two = Uint::<LIMBS>::from_u8(2);
    if value < two || value > modulus_value.wrapping_sub(&two) {
        return Err(Error::PublicValue);
    }
    let form = FixedMontyForm::new(&value, &params);
    if form.pow_vartime(&order).retrieve() != Uint::<LIMBS>::ONE {
        return Err(Error::PublicValue);
    }
    let shared = Zeroizing::new(form.pow(secret).retrieve());
    let bytes = shared.to_be_bytes();
    Ok(Zeroizing::new(bytes.as_ref().to_vec()))
}

/// An EC key on `C`: a uniform nonzero scalar and its uncompressed point.
///
/// # Errors
/// As [`generate`].
fn curve<C>(curve: ObjectIdentifier, top: u8) -> Result<(Zeroizing<C::Scalar>, Vec<u8>), Error>
where
    C: CurveArithmetic,
    C::AffinePoint: FromSec1Point<C> + ToSec1Point<C>,
    FieldBytesSize<C>: ModulusSize,
{
    for _ in 0..MAX_DRAWS {
        let mut repr = FieldBytes::<C>::default();
        random(repr.as_mut_slice())?;
        if let Some(first) = repr.first_mut() {
            *first &= top;
        }
        let candidate: Option<C::Scalar> = Option::from(C::Scalar::from_repr(repr));
        repr.as_mut_slice().zeroize();
        if let Some(scalar) = candidate.filter(|scalar| !bool::from(scalar.is_zero())) {
            let secret = Zeroizing::new(scalar);
            let point = C::ProjectivePoint::mul_by_generator(&*secret)
                .to_affine()
                .to_sec1_point(false);
            let parameters = Any::from(curve);
            return Ok((secret, spki(EC_PUBLIC_KEY, parameters, point.as_bytes())?));
        }
    }
    Err(Error::Malformed {
        structure: "EC key",
        reason: "the random generator produced no valid scalar",
    })
}

/// The x-coordinate of `secret * theirs` for a valid, non-identity SEC1 point.
///
/// # Errors
/// Returns [`Error::PublicValue`].
fn curve_agree<C>(secret: &C::Scalar, theirs: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error>
where
    C: CurveArithmetic,
    C::AffinePoint: FromSec1Point<C> + ToSec1Point<C>,
    FieldBytesSize<C>: ModulusSize,
{
    let encoded = Sec1Point::<C>::from_bytes(theirs).map_err(|_detail| Error::PublicValue)?;
    let point = Option::<C::AffinePoint>::from(C::AffinePoint::from_sec1_point(&encoded))
        .ok_or(Error::PublicValue)?;
    let projective = C::ProjectivePoint::from(point);
    if bool::from(projective.is_identity()) {
        return Err(Error::PublicValue);
    }
    let shared = Zeroizing::new(projective.mul(*secret));
    if bool::from(shared.is_identity()) {
        return Err(Error::PublicValue);
    }
    let uncompressed = shared.to_affine().to_sec1_point(false);
    let size = FieldBytes::<C>::default().len();
    let end = size.checked_add(1).ok_or(Error::PublicValue)?;
    let x = uncompressed
        .as_bytes()
        .get(1..end)
        .ok_or(Error::PublicValue)?;
    Ok(Zeroizing::new(x.to_vec()))
}
