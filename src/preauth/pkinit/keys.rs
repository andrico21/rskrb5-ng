//! Signatures, the software signer and PEM.
//!
//! Certificate and CMS signatures are verified with ECDSA over P-256/P-384
//! and RSASSA-PKCS1-v1_5, each with SHA-256/384/512.
//!
//! SHA-1 signatures are refused (MIT accepts what OpenSSL's default security
//! level accepts); RSA moduli below [`MIN_RSA_BITS`] are refused.

use alloc::sync::Arc;
use core::str;

use der::{Decode as _, Encode as _, asn1::ObjectIdentifier, pem};
use p256::{
    ecdsa as ecdsa256,
    ecdsa::signature::{Signer as _, hazmat::PrehashVerifier as _},
    elliptic_curve::{pkcs8::DecodePrivateKey as _, sec1::ToSec1Point as _},
};
use p384::ecdsa as ecdsa384;
use rsa::{
    pkcs1v15,
    pkcs8::DecodePublicKey as _,
    signature::{self, Verifier as _},
    traits::PublicKeyParts as _,
};
use sha2::{Digest as _, Sha256, Sha384, Sha512};
use spki::SubjectPublicKeyInfoOwned;
use x509_cert::Certificate;
use zeroize::Zeroizing;

use super::{
    MAX_CERTIFICATE_BYTES, MAX_CERTIFICATES, MAX_CRL_BYTES, MIN_RSA_BITS, SignatureAlgorithm,
    Signer,
};
use crate::{error::Pkinit as Error, extensions::ProviderError};

/// `id-ecPublicKey`.
const EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
/// `secp256r1`.
const SECP256R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
/// `secp384r1`.
const SECP384R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
/// `rsaEncryption`.
pub(super) const RSA_ENCRYPTION: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
/// `id-sha256`.
pub(super) const ID_SHA256: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
/// `id-sha384`.
pub(super) const ID_SHA384: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2");
/// `id-sha512`.
pub(super) const ID_SHA512: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.3");
/// The signature algorithms this client verifies and offers (MIT
/// `pkinit_constants.c:134-140` offers the ECDSA SHA-256/512 and RSA
/// SHA-256/512 subset).
pub(super) const SIGNATURES: [(&str, Kind, Hash); 6] = [
    ("1.2.840.10045.4.3.2", Kind::Ecdsa, Hash::Sha256),
    ("1.2.840.10045.4.3.3", Kind::Ecdsa, Hash::Sha384),
    ("1.2.840.10045.4.3.4", Kind::Ecdsa, Hash::Sha512),
    ("1.2.840.113549.1.1.11", Kind::Rsa, Hash::Sha256),
    ("1.2.840.113549.1.1.12", Kind::Rsa, Hash::Sha384),
    ("1.2.840.113549.1.1.13", Kind::Rsa, Hash::Sha512),
];

/// A signature scheme.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Kind {
    /// ECDSA.
    Ecdsa,
    /// RSASSA-PKCS1-v1_5.
    Rsa,
}

/// A digest of the SHA-2 family.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Hash {
    /// SHA-256.
    Sha256,
    /// SHA-384.
    Sha384,
    /// SHA-512.
    Sha512,
}

impl Hash {
    /// The digest of `data`.
    pub(super) fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha256 => Sha256::digest(data).to_vec(),
            Self::Sha384 => Sha384::digest(data).to_vec(),
            Self::Sha512 => Sha512::digest(data).to_vec(),
        }
    }

    /// The hash of a digest-algorithm OID.
    pub(super) fn from_oid(oid: &ObjectIdentifier) -> Option<Self> {
        [
            (ID_SHA256, Self::Sha256),
            (ID_SHA384, Self::Sha384),
            (ID_SHA512, Self::Sha512),
        ]
        .into_iter()
        .find_map(|(known, hash)| (known == *oid).then_some(hash))
    }

    /// The OID.
    pub(super) const fn oid(self) -> ObjectIdentifier {
        match self {
            Self::Sha256 => ID_SHA256,
            Self::Sha384 => ID_SHA384,
            Self::Sha512 => ID_SHA512,
        }
    }
}

/// The scheme and hash of a signature-algorithm OID.
///
/// # Errors
/// Returns [`Error::UnsupportedAlgorithm`] for any other algorithm, SHA-1 included.
pub(super) fn signature_algorithm(oid: &ObjectIdentifier) -> Result<(Kind, Hash), Error> {
    SIGNATURES
        .iter()
        .find(|(text, _, _)| ObjectIdentifier::new(text).is_ok_and(|known| known == *oid))
        .map(|&(_, kind, hash)| (kind, hash))
        .ok_or_else(|| Error::UnsupportedAlgorithm {
            algorithm: oid.to_string(),
        })
}

/// Verify `signature` over `message` with the key of `spki`.
///
/// # Errors
/// Returns [`Error::Signature`] for a signature that does not verify,
/// [`Error::UnsupportedAlgorithm`] for a key the scheme cannot use, and
/// [`Error::Certificate`] for an RSA key below [`MIN_RSA_BITS`].
pub(super) fn verify(
    spki: &SubjectPublicKeyInfoOwned,
    (kind, hash): (Kind, Hash),
    message: &[u8],
    signature: &[u8],
    what: &'static str,
) -> Result<(), Error> {
    let invalid = |_detail: signature::Error| Error::Signature { what };
    match kind {
        Kind::Ecdsa => {
            let digest = hash.digest(message);
            let point = spki.subject_public_key.raw_bytes();
            match curve(spki)? {
                Curve::P256 => ecdsa256::VerifyingKey::from_sec1_bytes(point)
                    .map_err(invalid)?
                    .verify_prehash(
                        &digest,
                        &ecdsa256::Signature::from_der(signature).map_err(invalid)?,
                    )
                    .map_err(invalid),
                Curve::P384 => ecdsa384::VerifyingKey::from_sec1_bytes(point)
                    .map_err(invalid)?
                    .verify_prehash(
                        &digest,
                        &ecdsa384::Signature::from_der(signature).map_err(invalid)?,
                    )
                    .map_err(invalid),
            }
        }
        Kind::Rsa => {
            let der = spki.to_der().map_err(|_detail| Error::Signature { what })?;
            let key = rsa::PublicKey::from_public_key_der(&der).map_err(|_detail| {
                Error::UnsupportedAlgorithm {
                    algorithm: "the key is not an RSA public key".to_owned(),
                }
            })?;
            if key.size().saturating_mul(8) < MIN_RSA_BITS {
                return Err(Error::Certificate {
                    reason: "an RSA key is shorter than 2048 bits",
                });
            }
            let parsed = pkcs1v15::Signature::try_from(signature).map_err(invalid)?;
            match hash {
                Hash::Sha256 => pkcs1v15::VerifyingKey::<Sha256>::new(key).verify(message, &parsed),
                Hash::Sha384 => pkcs1v15::VerifyingKey::<Sha384>::new(key).verify(message, &parsed),
                Hash::Sha512 => pkcs1v15::VerifyingKey::<Sha512>::new(key).verify(message, &parsed),
            }
            .map_err(invalid)
        }
    }
}

/// A curve of an EC key.
enum Curve {
    /// P-256.
    P256,
    /// P-384.
    P384,
}

/// The curve of an `id-ecPublicKey` SPKI.
///
/// # Errors
/// Returns [`Error::UnsupportedAlgorithm`] for another key type or curve.
fn curve(spki: &SubjectPublicKeyInfoOwned) -> Result<Curve, Error> {
    let named = spki
        .algorithm
        .parameters
        .as_ref()
        .and_then(|parameters| parameters.decode_as::<ObjectIdentifier>().ok());
    match (spki.algorithm.oid == EC_PUBLIC_KEY, named) {
        (true, Some(oid)) if oid == SECP256R1 => Ok(Curve::P256),
        (true, Some(oid)) if oid == SECP384R1 => Ok(Curve::P384),
        _ => Err(Error::UnsupportedAlgorithm {
            algorithm: spki.algorithm.oid.to_string(),
        }),
    }
}

/// The DER bodies of the PEM blocks of `text` whose label is in `labels`,
/// at most `count` blocks of at most `limit` bytes each.
///
/// # Errors
/// Returns [`Error::Malformed`] for unreadable PEM and [`Error::TooLarge`].
fn blocks(
    text: &[u8],
    labels: &[&str],
    (count, limit): (usize, usize),
) -> Result<Vec<Zeroizing<Vec<u8>>>, Error> {
    let malformed = |_detail: str::Utf8Error| Error::Malformed {
        structure: "PEM",
        reason: "not a PEM document",
    };
    let mut rest = str::from_utf8(text).map_err(malformed)?;
    let mut out = Vec::new();
    while let Some(start) = rest.find("-----BEGIN ") {
        let tail = rest.get(start..).unwrap_or_default();
        let end_marker = tail.find("-----END ").ok_or(Error::Malformed {
            structure: "PEM",
            reason: "a block has no END line",
        })?;
        let after = tail.get(end_marker.saturating_add(9)..).unwrap_or_default();
        let close = after.find("-----").ok_or(Error::Malformed {
            structure: "PEM",
            reason: "a block has no END line",
        })?;
        let length = end_marker
            .saturating_add(9)
            .saturating_add(close)
            .saturating_add(5);
        let block = tail.get(..length).unwrap_or_default();
        rest = tail.get(length..).unwrap_or_default();
        let (label, decoded) =
            pem::decode_vec(block.as_bytes()).map_err(|_detail| Error::Malformed {
                structure: "PEM",
                reason: "not a PEM document",
            })?;
        let body = Zeroizing::new(decoded);
        if !labels.contains(&label) {
            continue;
        }
        if body.len() > limit {
            return Err(Error::TooLarge {
                structure: "PEM block",
                limit,
            });
        }
        out.push(body);
        if out.len() > count {
            return Err(Error::TooLarge {
                structure: "PEM document",
                limit: count,
            });
        }
    }
    Ok(out)
}

/// The DER certificates of a PEM document.
///
/// # Errors
/// As [`blocks`], plus [`Error::Malformed`] for a block that is no certificate.
pub(super) fn pem_certificates(text: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
    blocks(
        text,
        &["CERTIFICATE"],
        (MAX_CERTIFICATES, MAX_CERTIFICATE_BYTES),
    )?
    .into_iter()
    .map(|block| {
        let _parsed: Certificate =
            Certificate::from_der(&block).map_err(|_detail| Error::Malformed {
                structure: "certificate",
                reason: "not a DER X.509 certificate",
            })?;
        Ok(block.to_vec())
    })
    .collect()
}

/// The DER CRLs of a PEM document.
///
/// # Errors
/// As [`blocks`].
pub(super) fn pem_crls(text: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
    Ok(
        blocks(text, &["X509 CRL"], (MAX_CERTIFICATES, MAX_CRL_BYTES))?
            .into_iter()
            .map(|block| block.to_vec())
            .collect(),
    )
}

/// A software EC key; its key is erased when it is dropped.
pub(super) enum SoftwareSigner {
    /// A P-256 key.
    P256(ecdsa256::SigningKey),
    /// A P-384 key.
    P384(ecdsa384::SigningKey),
}

impl Signer for SoftwareSigner {
    fn algorithm(&self) -> SignatureAlgorithm {
        match self {
            Self::P256(_) => SignatureAlgorithm::EcdsaP256Sha256,
            Self::P384(_) => SignatureAlgorithm::EcdsaP384Sha384,
        }
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, ProviderError> {
        Ok(match self {
            Self::P256(key) => {
                let signature: ecdsa256::Signature = key.sign(message);
                signature.to_der().as_bytes().to_vec()
            }
            Self::P384(key) => {
                let signature: ecdsa384::Signature = key.sign(message);
                signature.to_der().as_bytes().to_vec()
            }
        })
    }
}

/// The software signer of a PEM key (`PRIVATE KEY` or `EC PRIVATE KEY`),
/// checked against `certificate`'s public key when one is given.
///
/// # Errors
/// Returns [`Error::Identity`] for a missing, unsupported or mismatched key.
pub(super) fn software_signer(
    text: &[u8],
    certificate: Option<&Vec<u8>>,
) -> Result<Arc<dyn Signer>, Error> {
    let unusable = |reason| Error::Identity { reason };
    let key = blocks(
        text,
        &["PRIVATE KEY", "EC PRIVATE KEY"],
        (1, MAX_CERTIFICATE_BYTES),
    )?
    .into_iter()
    .next()
    .ok_or_else(|| unusable("no PRIVATE KEY or EC PRIVATE KEY block"))?;
    let p256_key = p256::SecretKey::from_pkcs8_der(&key)
        .or_else(|_pkcs8| p256::SecretKey::from_sec1_der(&key))
        .ok();
    let p384_key = p384::SecretKey::from_pkcs8_der(&key)
        .or_else(|_pkcs8| p384::SecretKey::from_sec1_der(&key))
        .ok();
    let (signer, public): (SoftwareSigner, Vec<u8>) = match (p256_key, p384_key) {
        (Some(secret), _) => (
            SoftwareSigner::P256(ecdsa256::SigningKey::from(&secret)),
            secret.public_key().to_sec1_point(false).as_bytes().to_vec(),
        ),
        (None, Some(secret)) => (
            SoftwareSigner::P384(ecdsa384::SigningKey::from(&secret)),
            secret.public_key().to_sec1_point(false).as_bytes().to_vec(),
        ),
        (None, None) => return Err(unusable("the key is not a P-256 or P-384 EC key")),
    };
    if let Some(der) = certificate {
        let parsed =
            Certificate::from_der(der).map_err(|_detail| unusable("unreadable certificate"))?;
        let spki = parsed.tbs_certificate().subject_public_key_info();
        if spki.subject_public_key.raw_bytes() != public.as_slice() {
            return Err(unusable("the key does not match the certificate"));
        }
    }
    Ok(Arc::new(signer))
}
