//! CMS `SignedData` (RFC 5652) as PKINIT uses it.
//!
//! The client's signed or unsigned `AuthPack` (MIT 1.22.2
//! `pkinit_crypto_openssl.c:1714-1929` `cms_signeddata_create`) and the
//! KDC's signed `KDCDHKeyInfo` (`cms_signeddata_verify`, `:1931-2466`).

use std::time::SystemTime;

use cms::{
    cert::{CertificateChoices, IssuerAndSerialNumber},
    content_info::{CmsVersion, ContentInfo},
    revocation::RevocationInfoChoice,
    signed_data::{
        CertificateSet, EncapsulatedContentInfo, SignedData, SignerIdentifier, SignerInfo,
        SignerInfos,
    },
};
use der::{
    Decode as _, Encode as _,
    asn1::{Any, ObjectIdentifier, OctetString, SetOfVec},
};
use spki::AlgorithmIdentifierOwned;
use x509_cert::{
    Certificate, attr::Attribute, crl::CertificateList, ext::pkix::SubjectKeyIdentifier,
};

use super::{
    CertificatePolicy, Identity, KdcTrust, MAX_CERTIFICATES, MAX_MESSAGE_BYTES, SignatureAlgorithm,
    chain::{self, Parsed},
    keys::{self, Hash},
};
use crate::error::Pkinit as Error;

/// `id-signedData` (RFC 5652).
const SIGNED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");
/// `id-contentType` (RFC 5652 section 11.1).
const CONTENT_TYPE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.3");
/// `id-messageDigest` (RFC 5652 section 11.2).
const MESSAGE_DIGEST: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");
/// `id-pkinit-authData` (RFC 4556 section 3.1).
pub(super) const AUTH_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.2.3.1");
/// `id-pkinit-DHKeyData` (RFC 4556 section 3.1).
pub(super) const DH_KEY_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.2.3.2");

/// A malformed-CMS error.
const fn malformed(reason: &'static str) -> Error {
    Error::Malformed {
        structure: "CMS SignedData",
        reason,
    }
}

/// The error of a failed encoding.
fn encoding<E>(_detail: E) -> Error {
    malformed("cannot be encoded")
}

/// An attribute with one value.
///
/// # Errors
/// Returns [`Error::Malformed`] when encoding fails.
fn attribute(oid: ObjectIdentifier, value: Any) -> Result<Attribute, Error> {
    let values = SetOfVec::try_from(vec![value]).map_err(|_detail| malformed("an attribute"))?;
    Ok(Attribute { oid, values })
}

/// The DER `ContentInfo` of a `SignedData` over `content` of `content_type`,
/// signed by `signer_identity`, or unsigned (RFC 6112 section 4.1) without one.
///
/// # Errors
/// Returns the encoding errors and the signer's failure.
pub(super) fn sign(
    content_type: ObjectIdentifier,
    content: &[u8],
    signer_identity: Option<&Identity>,
) -> Result<Vec<u8>, Error> {
    let econtent =
        Any::encode_from(&OctetString::new(content).map_err(encoding)?).map_err(encoding)?;
    let encapsulated = EncapsulatedContentInfo {
        econtent_type: content_type,
        econtent: Some(econtent),
    };
    let (digests, certificates, signers) = match signer_identity {
        None => (SetOfVec::new(), None, SetOfVec::new()),
        Some(identity) => {
            let (hash, signature_oid) = match identity.signer().algorithm() {
                SignatureAlgorithm::EcdsaP256Sha256 => (Hash::Sha256, "1.2.840.10045.4.3.2"),
                SignatureAlgorithm::EcdsaP384Sha384 => (Hash::Sha384, "1.2.840.10045.4.3.3"),
                SignatureAlgorithm::RsaPkcs1Sha256 => (Hash::Sha256, "1.2.840.113549.1.1.11"),
            };
            let digest_algorithm = AlgorithmIdentifierOwned {
                oid: hash.oid(),
                parameters: None,
            };
            let chain = identity
                .certificates()
                .iter()
                .map(|der| chain::parse(der).map(|parsed| parsed.certificate))
                .collect::<Result<Vec<Certificate>, Error>>()?;
            let leaf = chain.first().ok_or(Error::Identity {
                reason: "the chain is empty",
            })?;
            let attributes = SetOfVec::try_from(vec![
                attribute(
                    CONTENT_TYPE,
                    Any::encode_from(&content_type).map_err(encoding)?,
                )?,
                attribute(
                    MESSAGE_DIGEST,
                    Any::encode_from(&OctetString::new(hash.digest(content)).map_err(encoding)?)
                        .map_err(encoding)?,
                )?,
            ])
            .map_err(encoding)?;
            let signature = identity
                .signer()
                .sign(&attributes.to_der().map_err(encoding)?)
                .map_err(Error::Provider)?;
            let signer = SignerInfo {
                version: CmsVersion::V1,
                sid: SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
                    issuer: leaf.tbs_certificate().issuer().clone(),
                    serial_number: leaf.tbs_certificate().serial_number().clone(),
                }),
                digest_alg: digest_algorithm.clone(),
                signed_attrs: Some(attributes),
                signature_algorithm: AlgorithmIdentifierOwned {
                    oid: ObjectIdentifier::new(signature_oid).map_err(encoding)?,
                    parameters: None,
                },
                signature: OctetString::new(signature).map_err(encoding)?,
                unsigned_attrs: None,
            };
            let set = SetOfVec::try_from(
                chain
                    .into_iter()
                    .map(CertificateChoices::Certificate)
                    .collect::<Vec<_>>(),
            )
            .map_err(encoding)?;
            (
                SetOfVec::try_from(vec![digest_algorithm]).map_err(encoding)?,
                Some(CertificateSet(set)),
                SetOfVec::try_from(vec![signer]).map_err(encoding)?,
            )
        }
    };
    let signed = SignedData {
        version: CmsVersion::V3,
        digest_algorithms: digests,
        encap_content_info: encapsulated,
        certificates,
        crls: None,
        signer_infos: SignerInfos(signers),
    };
    ContentInfo {
        content_type: SIGNED_DATA,
        content: Any::encode_from(&signed).map_err(encoding)?,
    }
    .to_der()
    .map_err(encoding)
}

/// What the KDC's verified `SignedData` yields.
pub(super) struct Verified {
    /// The encapsulated content.
    pub content: Vec<u8>,
    /// The signer's certificate.
    pub signer: Certificate,
}

/// The time and trust a verification uses.
pub(super) struct Context<'input> {
    /// The anchors, pool and CRLs.
    pub trust: &'input KdcTrust,
    /// The policy.
    pub policy: &'input CertificatePolicy,
    /// The time of the check.
    pub now: SystemTime,
}

/// Verify the KDC's DER `ContentInfo` of `content_type`: one signer, signed
/// attributes binding the content type and digest, a valid signature, and a
/// signer certificate that chains to the anchors.
///
/// # Errors
/// Returns [`Error::TooLarge`], [`Error::Malformed`], [`Error::Signature`] and
/// the chain errors.
pub(super) fn verify(
    bytes: &[u8],
    content_type: ObjectIdentifier,
    context: &Context<'_>,
) -> Result<Verified, Error> {
    if bytes.len() > MAX_MESSAGE_BYTES {
        return Err(Error::TooLarge {
            structure: "CMS SignedData",
            limit: MAX_MESSAGE_BYTES,
        });
    }
    let info = ContentInfo::from_der(bytes).map_err(|_detail| malformed("not a ContentInfo"))?;
    if info.content_type != SIGNED_DATA {
        return Err(malformed("not SignedData"));
    }
    let signed_data: SignedData = info
        .content
        .decode_as()
        .map_err(|_detail| malformed("not a SignedData"))?;
    if signed_data.encap_content_info.econtent_type != content_type {
        return Err(malformed("the content type is not the expected one"));
    }
    let encapsulated = signed_data
        .encap_content_info
        .econtent
        .as_ref()
        .and_then(|any| any.decode_as::<OctetString>().ok())
        .ok_or_else(|| malformed("no encapsulated content"))?
        .into_bytes()
        .into_vec();
    let mut infos = signed_data.signer_infos.0.iter();
    let (Some(signer), None) = (infos.next(), infos.next()) else {
        return Err(malformed("not exactly one signer"));
    };
    let received: Vec<Parsed> = signed_data
        .certificates
        .as_ref()
        .map(|set| set.0.iter())
        .into_iter()
        .flatten()
        .filter_map(|choice| match choice {
            CertificateChoices::Certificate(certificate) => certificate.to_der().ok(),
            CertificateChoices::Other(_) => None,
        })
        .map(|der: Vec<u8>| chain::parse(&der))
        .collect::<Result<_, _>>()?;
    let pool = context
        .trust
        .intermediates()
        .iter()
        .map(|der| chain::parse(der))
        .collect::<Result<Vec<_>, _>>()?;
    let anchors = context
        .trust
        .anchors()
        .iter()
        .map(|der| chain::parse(der))
        .collect::<Result<Vec<_>, _>>()?;
    let candidates: Vec<Parsed> = received.into_iter().chain(pool).collect();
    if candidates.len() > MAX_CERTIFICATES {
        return Err(Error::TooLarge {
            structure: "certificate set",
            limit: MAX_CERTIFICATES,
        });
    }
    let certificate = signer_certificate(&signer.sid, &candidates, &anchors)?;
    check_signature(signer, &certificate, (content_type, &encapsulated))?;
    let mut crls = chain::parse_crls(context.trust.crls())?;
    crls.extend(
        signed_data
            .crls
            .iter()
            .flat_map(|set| set.0.iter())
            .filter_map(|choice| match choice {
                RevocationInfoChoice::Crl(crl) => Some(crl.clone()),
                RevocationInfoChoice::Other(_) => None,
            }),
    );
    let lists: Vec<CertificateList> = crls;
    chain::validate(
        &certificate,
        (&candidates, &anchors, &lists),
        context.policy.crl_checking(),
        context.now,
    )?;
    Ok(Verified {
        content: encapsulated,
        signer: certificate,
    })
}

/// The certificate `sid` names, from the received set, the pool or the anchors.
///
/// # Errors
/// Returns [`Error::Certificate`] when none matches.
fn signer_certificate(
    sid: &SignerIdentifier,
    candidates: &[Parsed],
    anchors: &[Parsed],
) -> Result<Certificate, Error> {
    candidates
        .iter()
        .chain(anchors)
        .map(|parsed| &parsed.certificate)
        .find(|certificate| match sid {
            SignerIdentifier::IssuerAndSerialNumber(id) => {
                certificate.tbs_certificate().issuer() == &id.issuer
                    && certificate.tbs_certificate().serial_number() == &id.serial_number
            }
            SignerIdentifier::SubjectKeyIdentifier(id) => certificate
                .tbs_certificate()
                .get_extension::<SubjectKeyIdentifier>()
                .ok()
                .flatten()
                .is_some_and(|(_, value)| value.0 == id.0),
        })
        .cloned()
        .ok_or(Error::Certificate {
            reason: "the signer certificate is not available",
        })
}

/// Check the signed attributes and the signature of `signer`.
///
/// # Errors
/// Returns [`Error::Malformed`] and [`Error::Signature`].
fn check_signature(
    signer: &SignerInfo,
    certificate: &Certificate,
    (content_type, content): (ObjectIdentifier, &[u8]),
) -> Result<(), Error> {
    let algorithm =
        chain::signer_algorithm(&signer.signature_algorithm.oid, &signer.digest_alg.oid)?;
    let attributes = signer
        .signed_attrs
        .as_ref()
        .ok_or_else(|| malformed("no signed attributes"))?;
    let single = |oid: ObjectIdentifier| -> Result<&Any, Error> {
        let mut found = attributes.iter().filter(|attribute| attribute.oid == oid);
        match (found.next(), found.next()) {
            (Some(attribute), None) => {
                let mut values = attribute.values.iter();
                match (values.next(), values.next()) {
                    (Some(value), None) => Ok(value),
                    _ => Err(malformed("an attribute has not exactly one value")),
                }
            }
            _ => Err(malformed("a signed attribute is missing or repeated")),
        }
    };
    let typed: ObjectIdentifier = single(CONTENT_TYPE)?
        .decode_as()
        .map_err(|_detail| malformed("the content-type attribute"))?;
    let digest: OctetString = single(MESSAGE_DIGEST)?
        .decode_as()
        .map_err(|_detail| malformed("the message-digest attribute"))?;
    if typed != content_type || digest.as_bytes() != algorithm.1.digest(content).as_slice() {
        return Err(Error::Signature {
            what: "CMS message digest",
        });
    }
    let message = attributes
        .to_der()
        .map_err(|_detail| malformed("the signed attributes"))?;
    keys::verify(
        certificate.tbs_certificate().subject_public_key_info(),
        algorithm,
        &message,
        signer.signature.as_bytes(),
        "CMS",
    )
}
