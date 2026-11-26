//! RFC 5929 section 4.1 `tls-server-end-point`: the hash of the DER
//! end-entity certificate, chosen by the certificate's signature algorithm.
//!
//! Only the outer `Certificate` structure and its `signatureAlgorithm` are
//! decoded (RFC 5280 section 4.1.1.2); the TBS part and the signature stay
//! opaque, since the TLS handshake verified them. RSASSA-PSS parameters follow
//! RFC 4055 section 3.1 (EXPLICIT tags, SHA-1 and MGF1-with-SHA-1 defaults).

use rasn::{
    AsnType, Decode, Decoder as _, Encode, Encoder as _,
    types::{Any, BitString, Integer, ObjectIdentifier},
};
use sha2::{Digest as _, Sha224, Sha256, Sha384, Sha512};

use crate::{der::decode_complete, gss::ChannelBindings};

/// `Certificate` (RFC 5280 section 4.1).
#[derive(AsnType, Decode, Encode)]
struct Certificate {
    /// `tbsCertificate`, opaque.
    tbs: Any,
    /// `signatureAlgorithm`.
    signature_algorithm: AlgorithmIdentifier,
    /// `signatureValue`, opaque.
    signature_value: BitString,
}

/// `AlgorithmIdentifier` (RFC 5280 section 4.1.1.2).
#[derive(AsnType, Decode, Encode)]
struct AlgorithmIdentifier {
    /// The algorithm.
    algorithm: ObjectIdentifier,
    /// Its parameters.
    parameters: Option<Any>,
}

/// `RSASSA-PSS-params` (RFC 4055 section 3.1).
#[derive(AsnType, Decode, Encode)]
struct PssParameters {
    /// `hashAlgorithm`, SHA-1 when absent.
    #[rasn(tag(explicit(0)))]
    hash_algorithm: Option<AlgorithmIdentifier>,
    /// `maskGenAlgorithm`, MGF1 with SHA-1 when absent.
    #[rasn(tag(explicit(1)))]
    mask_gen_algorithm: Option<AlgorithmIdentifier>,
    /// `saltLength`.
    #[rasn(tag(explicit(2)))]
    salt_length: Option<Integer>,
    /// `trailerField`, 1 (`trailerFieldBC`) when absent.
    #[rasn(tag(explicit(3)))]
    trailer_field: Option<Integer>,
}

/// A hash a signature algorithm names.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Hash {
    /// MD5.
    Md5,
    /// SHA-1.
    Sha1,
    /// SHA-224.
    Sha224,
    /// SHA-256.
    Sha256,
    /// SHA-384.
    Sha384,
    /// SHA-512.
    Sha512,
}

/// `id-RSASSA-PSS` (RFC 4055).
const RSASSA_PSS: [u32; 7] = [1, 2, 840, 113_549, 1, 1, 10];
/// `id-mgf1` (RFC 4055).
const MGF1: [u32; 7] = [1, 2, 840, 113_549, 1, 1, 8];

/// The arcs of `oid`.
fn arcs(oid: &ObjectIdentifier) -> &[u32] {
    oid
}

/// The single hash of signature algorithm `arcs` (RFC 3279, RFC 4055, RFC
/// 5758); `None` for an algorithm with no single hash this module knows.
const fn signature_hash(arcs: &[u32]) -> Option<Hash> {
    match arcs {
        [1, 2, 840, 113_549, 1, 1, 4] => Some(Hash::Md5),
        [1, 2, 840, 113_549, 1, 1, 5]
        | [1, 3, 14, 3, 2, 29]
        | [1, 2, 840, 10_045, 4, 1]
        | [1, 2, 840, 10_040, 4, 3] => Some(Hash::Sha1),
        [1, 2, 840, 113_549, 1, 1, 14]
        | [1, 2, 840, 10_045, 4, 3, 1]
        | [2, 16, 840, 1, 101, 3, 4, 3, 1] => Some(Hash::Sha224),
        [1, 2, 840, 113_549, 1, 1, 11]
        | [1, 2, 840, 10_045, 4, 3, 2]
        | [2, 16, 840, 1, 101, 3, 4, 3, 2] => Some(Hash::Sha256),
        [1, 2, 840, 113_549, 1, 1, 12] | [1, 2, 840, 10_045, 4, 3, 3] => Some(Hash::Sha384),
        [1, 2, 840, 113_549, 1, 1, 13] | [1, 2, 840, 10_045, 4, 3, 4] => Some(Hash::Sha512),
        _ => None,
    }
}

/// The hash of digest algorithm `arcs` (RFC 3279, RFC 5754).
const fn digest_hash(arcs: &[u32]) -> Option<Hash> {
    match arcs {
        [1, 3, 14, 3, 2, 26] => Some(Hash::Sha1),
        [2, 16, 840, 1, 101, 3, 4, 2, 4] => Some(Hash::Sha224),
        [2, 16, 840, 1, 101, 3, 4, 2, 1] => Some(Hash::Sha256),
        [2, 16, 840, 1, 101, 3, 4, 2, 2] => Some(Hash::Sha384),
        [2, 16, 840, 1, 101, 3, 4, 2, 3] => Some(Hash::Sha512),
        _ => None,
    }
}

/// The single hash of an RSASSA-PSS signature: its message hash when the MGF1
/// hash is the same one, else `None` (two hashes, no binding).
///
/// # Errors
///
/// Returns why the parameters are not RFC 4055 `RSASSA-PSS-params`.
fn pss_hash(encoded: Option<&Any>) -> Result<Option<Hash>, &'static str> {
    let parameters: PssParameters = decode_complete(
        encoded
            .ok_or("an RSASSA-PSS signature algorithm has no parameters")?
            .as_bytes(),
    )
    .map_err(|_decode| "the RSASSA-PSS parameters do not decode")?;
    if parameters
        .trailer_field
        .is_some_and(|trailer| trailer != Integer::from(1_i32))
    {
        return Err("the RSASSA-PSS trailer field is not 1");
    }
    let message = parameters
        .hash_algorithm
        .map_or(Some(Hash::Sha1), |hash| digest_hash(&hash.algorithm));
    let mask = match parameters.mask_gen_algorithm {
        None => Some(Hash::Sha1),
        Some(mask) if arcs(&mask.algorithm) == MGF1 => {
            let hash: AlgorithmIdentifier = decode_complete(
                mask.parameters
                    .ok_or("the MGF1 algorithm has no hash")?
                    .as_bytes(),
            )
            .map_err(|_decode| "the MGF1 hash does not decode")?;
            digest_hash(&hash.algorithm)
        }
        Some(_other) => None,
    };
    Ok(message.filter(|_hash| message == mask))
}

/// The `tls-server-end-point` bindings of the DER `certificate`; `None` when
/// its signature algorithm defines no single hash this crate computes.
///
/// # Errors
///
/// Returns why `certificate` is not a DER X.509 certificate.
pub(super) fn bindings(certificate: &[u8]) -> Result<Option<ChannelBindings>, &'static str> {
    let parsed: Certificate =
        decode_complete(certificate).map_err(|_decode| "not a DER X.509 certificate")?;
    let algorithm = &parsed.signature_algorithm;
    let hash = if arcs(&algorithm.algorithm) == RSASSA_PSS {
        pss_hash(algorithm.parameters.as_ref())?
    } else {
        signature_hash(&algorithm.algorithm)
    };
    let digest = match hash {
        None => return Ok(None),
        Some(Hash::Md5 | Hash::Sha1 | Hash::Sha256) => Sha256::digest(certificate).to_vec(),
        Some(Hash::Sha224) => Sha224::digest(certificate).to_vec(),
        Some(Hash::Sha384) => Sha384::digest(certificate).to_vec(),
        Some(Hash::Sha512) => Sha512::digest(certificate).to_vec(),
    };
    ChannelBindings::tls_server_end_point(&digest)
        .map(Some)
        .map_err(|_length| "the certificate hash does not fit channel bindings")
}
