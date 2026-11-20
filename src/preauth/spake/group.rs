//! Group arithmetic of the four MIT groups (RFC 9588 section 12.2).
//!
//! The admitted crates provide it: `curve25519-dalek` for edwards25519 and
//! `p256`, `p384` and `p521` for the NIST groups. This module composes their
//! constant-time operations and implements no field or curve arithmetic.
//!
//! Only the client role exists: `S = y*G + w*N` and `K = y*(T - w*M)` (RFC 9588
//! section 4.3), with `y` a multiple of the cofactor.

use core::ops::{Add as _, Mul as _, Sub as _};

use curve25519_dalek::{
    EdwardsPoint, Scalar, edwards::CompressedEdwardsY, traits::IsIdentity as _,
};
use p256::elliptic_curve::{
    CurveArithmetic, FieldBytes, FieldBytesSize,
    ff::{Field as _, PrimeField as _},
    group::{Curve as _, Group as _},
    sec1::{FromSec1Point, ModulusSize, Sec1Point, ToSec1Point},
};
use zeroize::{Zeroize as _, Zeroizing};

use super::{Entropy, Group, Shared};
use crate::error::Spake as Error;

/// Most candidates the NIST private-scalar rejection sampling draws.
const MAX_DRAWS: usize = 64;

/// The constants and sizes of one NIST group.
struct Nist {
    /// The group number, for errors.
    id: i32,
    /// `M`, compressed SEC1.
    kdc_constant: &'static [u8],
    /// `N`, compressed SEC1.
    client_constant: &'static [u8],
    /// Bit mask of the most significant byte of a scalar draw.
    top: u8,
    /// Length of the low half of the multiplier split, in bytes.
    half: usize,
}

/// edwards25519 `M` (MIT `iana.c:35-39`).
const EDWARDS25519_M: [u8; 32] = [
    0xd0, 0x48, 0x03, 0x2c, 0x6e, 0xa0, 0xb6, 0xd6, 0x97, 0xdd, 0xc2, 0xe8, 0x6b, 0xda, 0x85, 0xa3,
    0x3a, 0xda, 0xc9, 0x20, 0xf1, 0xbf, 0x18, 0xe1, 0xb0, 0xc6, 0xd1, 0x66, 0xa5, 0xce, 0xcd, 0xaf,
];
/// edwards25519 `N` (MIT `iana.c:41-45`).
const EDWARDS25519_N: [u8; 32] = [
    0xd3, 0xbf, 0xb5, 0x18, 0xf4, 0x4f, 0x34, 0x30, 0xf2, 0x9d, 0x0c, 0x92, 0xaf, 0x50, 0x38, 0x65,
    0xa1, 0xed, 0x32, 0x81, 0xdc, 0x69, 0xb3, 0x5d, 0xd8, 0x68, 0xba, 0x85, 0xf8, 0x86, 0xc4, 0xab,
];
/// P-256 `M` (MIT `iana.c:47-51`).
const P256_M: [u8; 33] = [
    0x02, 0x88, 0x6e, 0x2f, 0x97, 0xac, 0xe4, 0x6e, 0x55, 0xba, 0x9d, 0xd7, 0x24, 0x25, 0x79, 0xf2,
    0x99, 0x3b, 0x64, 0xe1, 0x6e, 0xf3, 0xdc, 0xab, 0x95, 0xaf, 0xd4, 0x97, 0x33, 0x3d, 0x8f, 0xa1,
    0x2f,
];
/// P-256 `N` (MIT `iana.c:53-57`).
const P256_N: [u8; 33] = [
    0x03, 0xd8, 0xbb, 0xd6, 0xc6, 0x39, 0xc6, 0x29, 0x37, 0xb0, 0x4d, 0x99, 0x7f, 0x38, 0xc3, 0x77,
    0x07, 0x19, 0xc6, 0x29, 0xd7, 0x01, 0x4d, 0x49, 0xa2, 0x4b, 0x4f, 0x98, 0xba, 0xa1, 0x29, 0x2b,
    0x49,
];
/// P-384 `M` (MIT `iana.c:59-65`).
const P384_M: [u8; 49] = [
    0x03, 0x0f, 0xf0, 0x89, 0x5a, 0xe5, 0xeb, 0xf6, 0x18, 0x70, 0x80, 0xa8, 0x2d, 0x82, 0xb4, 0x2e,
    0x27, 0x65, 0xe3, 0xb2, 0xf8, 0x74, 0x9c, 0x7e, 0x05, 0xeb, 0xa3, 0x66, 0x43, 0x4b, 0x36, 0x3d,
    0x3d, 0xc3, 0x6f, 0x15, 0x31, 0x47, 0x39, 0x07, 0x4d, 0x2e, 0xb8, 0x61, 0x3f, 0xce, 0xec, 0x28,
    0x53,
];
/// P-384 `N` (MIT `iana.c:67-73`).
const P384_N: [u8; 49] = [
    0x02, 0xc7, 0x2c, 0xf2, 0xe3, 0x90, 0x85, 0x3a, 0x1c, 0x1c, 0x4a, 0xd8, 0x16, 0xa6, 0x2f, 0xd1,
    0x58, 0x24, 0xf5, 0x60, 0x78, 0x91, 0x8f, 0x43, 0xf9, 0x22, 0xca, 0x21, 0x51, 0x8f, 0x9c, 0x54,
    0x3b, 0xb2, 0x52, 0xc5, 0x49, 0x02, 0x14, 0xcf, 0x9a, 0xa3, 0xf0, 0xba, 0xab, 0x4b, 0x66, 0x5c,
    0x10,
];
/// P-521 `M` (MIT `iana.c:75-82`).
const P521_M: [u8; 67] = [
    0x02, 0x00, 0x3f, 0x06, 0xf3, 0x81, 0x31, 0xb2, 0xba, 0x26, 0x00, 0x79, 0x1e, 0x82, 0x48, 0x8e,
    0x8d, 0x20, 0xab, 0x88, 0x9a, 0xf7, 0x53, 0xa4, 0x18, 0x06, 0xc5, 0xdb, 0x18, 0xd3, 0x7d, 0x85,
    0x60, 0x8c, 0xfa, 0xe0, 0x6b, 0x82, 0xe4, 0xa7, 0x2c, 0xd7, 0x44, 0xc7, 0x19, 0x19, 0x35, 0x62,
    0xa6, 0x53, 0xea, 0x1f, 0x11, 0x9e, 0xef, 0x93, 0x56, 0x90, 0x7e, 0xdc, 0x9b, 0x56, 0x97, 0x99,
    0x62, 0xd7, 0xaa,
];
/// P-521 `N` (MIT `iana.c:84-91`).
const P521_N: [u8; 67] = [
    0x02, 0x00, 0xc7, 0x92, 0x4b, 0x9e, 0xc0, 0x17, 0xf3, 0x09, 0x45, 0x62, 0x89, 0x43, 0x36, 0xa5,
    0x3c, 0x50, 0x16, 0x7b, 0xa8, 0xc5, 0x96, 0x38, 0x76, 0x88, 0x05, 0x42, 0xbc, 0x66, 0x9e, 0x49,
    0x4b, 0x25, 0x32, 0xd7, 0x6c, 0x5b, 0x53, 0xdf, 0xb3, 0x49, 0xfd, 0xf6, 0x91, 0x54, 0xb9, 0xe0,
    0x04, 0x8c, 0x58, 0xa4, 0x2e, 0x8e, 0xd0, 0x4c, 0xef, 0x05, 0x2a, 0x3b, 0xc3, 0x49, 0xd9, 0x55,
    0x75, 0xcd, 0x25,
];

/// P-256 parameters.
const P256: Nist = Nist {
    id: 2,
    kdc_constant: &P256_M,
    client_constant: &P256_N,
    top: 0xff,
    half: 16,
};
/// P-384 parameters.
const P384: Nist = Nist {
    id: 3,
    kdc_constant: &P384_M,
    client_constant: &P384_N,
    top: 0xff,
    half: 24,
};
/// P-521 parameters: the order has 521 bits, so a draw keeps one bit of its top byte.
const P521: Nist = Nist {
    id: 4,
    kdc_constant: &P521_M,
    client_constant: &P521_N,
    top: 0x01,
    half: 33,
};

/// Compute `S` and `K` in `group` for the multiplier input `wbytes` and the KDC's element `theirs`.
///
/// # Errors
/// Returns [`Error::InvalidElement`] for an invalid or non-canonical element or
/// an identity result, and the entropy source's error.
pub(super) fn exchange(
    group: Group,
    wbytes: &[u8],
    theirs: &[u8],
    entropy: &mut Entropy<'_>,
) -> Result<Shared, Error> {
    match group {
        Group::Edwards25519 => edwards(wbytes, theirs, entropy),
        Group::P256 => nist::<p256::NistP256>(&P256, wbytes, theirs, entropy),
        Group::P384 => nist::<p384::NistP384>(&P384, wbytes, theirs, entropy),
        Group::P521 => nist::<p521::NistP521>(&P521, wbytes, theirs, entropy),
    }
}

/// A canonical edwards25519 point: decompression accepts some non-canonical
/// encodings (`y >= p`, a negative zero `x`), so the point must compress back
/// to the same bytes.
fn edwards_point(bytes: &[u8]) -> Option<EdwardsPoint> {
    let compressed = CompressedEdwardsY::from_slice(bytes).ok()?;
    let point = compressed.decompress()?;
    (point.compress() == compressed).then_some(point)
}

/// edwards25519 (MIT `edwards25519.c:1646-1739`).
///
/// The private scalar is `y = 8r` with `r` uniform modulo the group order (64
/// random bytes, wide reduction); `w` is the little-endian multiplier reduced
/// modulo the order.
///
/// # Errors
/// As [`exchange`].
fn edwards(wbytes: &[u8], theirs: &[u8], entropy: &mut Entropy<'_>) -> Result<Shared, Error> {
    let invalid = || Error::InvalidElement {
        group: Group::Edwards25519.id(),
    };
    let mut digits = Zeroizing::new([0_u8; 32]);
    digits.copy_from_slice(wbytes.get(..32).ok_or_else(invalid)?);
    let multiplier = Zeroizing::new(Scalar::from_bytes_mod_order(*digits));
    let mut wide = Zeroizing::new([0_u8; 64]);
    entropy(wide.as_mut_slice())?;
    let private = Zeroizing::new(Scalar::from_bytes_mod_order_wide(&wide));
    let (kdc_constant, client_constant) = (
        edwards_point(&EDWARDS25519_M).ok_or_else(invalid)?,
        edwards_point(&EDWARDS25519_N).ok_or_else(invalid)?,
    );
    let kdc_element = edwards_point(theirs).ok_or_else(invalid)?;
    let mask = Zeroizing::new(client_constant.mul(*multiplier));
    let public = EdwardsPoint::mul_base(&private)
        .mul_by_cofactor()
        .add(*mask);
    let unmasked = Zeroizing::new(kdc_element.sub(kdc_constant.mul(*multiplier)));
    let shared = Zeroizing::new(unmasked.mul(*private).mul_by_cofactor());
    if shared.is_identity() {
        return Err(invalid());
    }
    Ok(Shared {
        public: public.compress().to_bytes().to_vec(),
        result: Zeroizing::new(shared.compress().to_bytes().to_vec()),
    })
}

/// A canonical compressed SEC1 point of `C`.
///
/// The length and the `02`/`03` tag are checked before decoding, the identity
/// cannot be encoded in this form, and the point must encode back to the same bytes.
fn nist_point<C>(bytes: &[u8]) -> Option<C::AffinePoint>
where
    C: CurveArithmetic,
    C::AffinePoint: FromSec1Point<C> + ToSec1Point<C>,
    FieldBytesSize<C>: ModulusSize,
{
    let tag = *bytes.first()?;
    let expected = FieldBytes::<C>::default().len().checked_add(1)?;
    if bytes.len() != expected || !matches!(tag, 2 | 3) {
        return None;
    }
    let encoded = Sec1Point::<C>::from_bytes(bytes).ok()?;
    let point = C::AffinePoint::from_sec1_point(&encoded).into_option()?;
    (point.to_sec1_point(true).as_bytes() == bytes).then_some(point)
}

/// The scalar of a big-endian value shorter than the order, left-padded.
fn small_scalar<C>(digits: &[u8]) -> Option<C::Scalar>
where
    C: CurveArithmetic,
{
    let mut repr = FieldBytes::<C>::default();
    let start = repr.len().checked_sub(digits.len())?;
    repr.get_mut(start..)?.copy_from_slice(digits);
    let scalar = Option::from(C::Scalar::from_repr(repr));
    repr.as_mut_slice().zeroize();
    scalar
}

/// The multiplier octet string reduced modulo the order (SEC1 2.3.8, MIT `openssl.c:149-157`).
///
/// It is computed as `high * 2^(8*half) + low` with both halves below the
/// order: `Reduce<FieldBytes>` of `p521` truncates instead of reducing (see
/// `docs/dependency-admission.md#p521`).
fn multiplier<C>(params: &Nist, wbytes: &[u8]) -> Option<Zeroizing<C::Scalar>>
where
    C: CurveArithmetic,
{
    let split = wbytes.len().checked_sub(params.half)?;
    let (high, low) = wbytes.split_at_checked(split)?;
    let mut unit = vec![0_u8; params.half.checked_add(1)?];
    *unit.first_mut()? = 1;
    let shift = small_scalar::<C>(&unit)?;
    let high_scalar = Zeroizing::new(small_scalar::<C>(high)?);
    let low_scalar = Zeroizing::new(small_scalar::<C>(low)?);
    Some(Zeroizing::new(high_scalar.mul(shift).add(*low_scalar)))
}

/// A uniform nonzero scalar by rejection sampling of field-size draws.
///
/// # Errors
/// Returns the entropy source's error, or [`Error::Unexpected`] when every draw
/// was rejected (a broken generator).
fn private<C>(params: &Nist, entropy: &mut Entropy<'_>) -> Result<Zeroizing<C::Scalar>, Error>
where
    C: CurveArithmetic,
{
    for _ in 0..MAX_DRAWS {
        let mut repr = FieldBytes::<C>::default();
        entropy(repr.as_mut_slice())?;
        if let Some(top) = repr.first_mut() {
            *top &= params.top;
        }
        let candidate: Option<C::Scalar> = Option::from(C::Scalar::from_repr(repr));
        repr.as_mut_slice().zeroize();
        if let Some(scalar) = candidate.filter(|scalar| !bool::from(scalar.is_zero())) {
            return Ok(Zeroizing::new(scalar));
        }
    }
    Err(Error::Unexpected {
        message: "the random generator produced no valid scalar",
    })
}

/// A NIST group (MIT `openssl.c:163-270`).
///
/// # Errors
/// As [`exchange`].
fn nist<C>(
    params: &Nist,
    wbytes: &[u8],
    theirs: &[u8],
    entropy: &mut Entropy<'_>,
) -> Result<Shared, Error>
where
    C: CurveArithmetic,
    C::AffinePoint: FromSec1Point<C> + ToSec1Point<C>,
    FieldBytesSize<C>: ModulusSize,
{
    let invalid = || Error::InvalidElement { group: params.id };
    let multiplier = multiplier::<C>(params, wbytes).ok_or_else(invalid)?;
    let private = private::<C>(params, entropy)?;
    let point = |bytes: &[u8]| nist_point::<C>(bytes).map(C::ProjectivePoint::from);
    let kdc_constant = point(params.kdc_constant).ok_or_else(invalid)?;
    let client_constant = point(params.client_constant).ok_or_else(invalid)?;
    let kdc_element = point(theirs).ok_or_else(invalid)?;
    let mask = Zeroizing::new(client_constant.mul(*multiplier));
    let public = C::ProjectivePoint::mul_by_generator(&private).add(*mask);
    let unmasked = Zeroizing::new(kdc_element.sub(kdc_constant.mul(*multiplier)));
    let shared = Zeroizing::new(unmasked.mul(*private));
    if bool::from(shared.is_identity()) {
        return Err(invalid());
    }
    Ok(Shared {
        public: public.to_affine().to_sec1_point(true).as_bytes().to_vec(),
        result: Zeroizing::new(shared.to_affine().to_sec1_point(true).as_bytes().to_vec()),
    })
}
