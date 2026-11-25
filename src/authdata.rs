//! AD-KDC-ISSUED and AD-AND-OR authorization data (RFC 4120 section 5.2.6.2),
//! AD-CAMMAC (RFC 7751) and authentication indicators (RFC 8129).
//!
//! The acceptor ([`crate::service::Validator`]) uses these helpers; they are
//! public so a KDC or an application can build and read the same elements.
//!
//! # Security
//!
//! An AD-KDC-ISSUED checksum is keyed with the session key, which the client
//! knows too. It therefore authenticates the element only where the client
//! cannot have written it, in the ticket; the acceptor refuses it in an
//! authenticator. AD-AND-OR needs an application that knows what each
//! condition means: no condition counts as satisfied unless the
//! [`ConditionEvaluator`] says so. An AD-CAMMAC's service verifier is keyed
//! with the service's long-term key; a CAMMAC copied into an authenticator or
//! into another ticket of the same service would still verify, so the
//! acceptor reads CAMMACs only from the ticket it decrypted.

use alloc::string::ToString as _;
use core::fmt::Debug;

use rasn::{
    AsnType, Decode, Decoder as _, Encode, Encoder as _, der,
    types::{SequenceOf, Utf8String},
};
use rasn_kerberos::{
    AdAndOr, AdKdcIssued, AuthorizationData, AuthorizationDataValue, Checksum, Verifier,
    VerifierMac,
};

use crate::{
    crypto::selection,
    der::decode_complete,
    error::{AuthData as Error, Crypto},
    keytab::EncryptionKey,
};

/// The key usage of the AD-KDC-ISSUED checksum (RFC 4120 section 7.5.1).
pub const KDC_ISSUED_CHECKSUM_USAGE: u32 = 19;

/// The key usage of an AD-CAMMAC verifier (RFC 7751 section 4; MIT
/// `KRB5_KEYUSAGE_CAMMAC`).
pub const CAMMAC_USAGE: u32 = 64;

/// AD-CAMMAC (RFC 7751 section 4).
///
/// ```text
/// AD-CAMMAC ::= SEQUENCE {
///     elements        [0] AuthorizationData,
///     kdc-verifier    [1] Verifier-MAC OPTIONAL,
///     svc-verifier    [2] Verifier-MAC OPTIONAL,
///     other-verifiers [3] SEQUENCE (SIZE (1..MAX)) OF Verifier OPTIONAL
/// }
/// ```
///
/// `rasn_kerberos::AdCammac` makes `other-verifiers` mandatory, so it cannot
/// read the CAMMACs MIT issues, which leave it out (`src/kdc/cammac.c:105-109`).
#[derive(AsnType, Clone, Debug, Decode, Encode, Eq, PartialEq)]
#[non_exhaustive]
pub struct Cammac {
    /// The authorization data the verifiers cover.
    #[rasn(tag(explicit(0)))]
    pub elements: AuthorizationData,
    /// The verifier under the KDC's ticket-granting key, over the ticket.
    #[rasn(tag(explicit(1)))]
    pub kdc_verifier: Option<VerifierMac>,
    /// The verifier under the key that encrypts the ticket, over `elements`.
    #[rasn(tag(explicit(2)))]
    pub svc_verifier: Option<VerifierMac>,
    /// Verifiers under the keys of other named principals.
    #[rasn(tag(explicit(3)))]
    pub other_verifiers: Option<SequenceOf<Verifier>>,
}

/// What an application knows about the conditions of an AD-AND-OR element.
pub trait ConditionEvaluator: Debug + Send + Sync {
    /// Whether the condition `element` holds: `Some(true)` when it holds,
    /// `Some(false)` when it does not and `None` when the evaluator does not
    /// understand it. An element that is not understood never counts.
    fn evaluate(&self, element: &AuthorizationDataValue) -> Option<bool>;
}

/// A cryptographic failure of a checksum computation.
const fn crypto_error(source: Crypto) -> Error {
    Error::Crypto(source)
}

/// Decode a complete DER value.
///
/// # Errors
///
/// Returns [`Error::Decode`] naming `target`.
fn decode<T>(target: &'static str, bytes: &[u8]) -> Result<T, Error>
where
    T: Decode,
{
    decode_complete(bytes).map_err(|message| Error::Decode { target, message })
}

/// The DER of `elements`, which the checksum covers.
///
/// # Errors
///
/// Returns [`Error::Encode`].
fn elements_der(elements: &AuthorizationData) -> Result<Vec<u8>, Error> {
    der::encode(elements).map_err(|source| Error::Encode {
        target: "AuthorizationData",
        message: source.to_string(),
    })
}

/// Build an AD-KDC-ISSUED element over `elements`, checksummed under `key` with
/// key usage 19 and the mandatory checksum type of the key's encryption type.
///
/// # Errors
///
/// Returns [`Error::UnsupportedEtype`], [`Error::Policy`], [`Error::Encode`]
/// and [`Error::Crypto`].
#[inline]
pub fn build_kdc_issued(
    elements: AuthorizationData,
    key: &EncryptionKey,
) -> Result<AdKdcIssued, Error> {
    let etype =
        selection::enctype(key.etype())?.ok_or_else(|| Error::UnsupportedEtype(key.etype()))?;
    let checksum = etype
        .checksum(
            key.value(),
            &elements_der(&elements)?,
            KDC_ISSUED_CHECKSUM_USAGE,
        )
        .map_err(crypto_error)?;
    Ok(AdKdcIssued {
        ad_checksum: Checksum {
            r#type: etype.checksum_type_id(),
            checksum: checksum.into(),
        },
        realm: None,
        sname: None,
        elements,
    })
}

/// Verify the checksum of an AD-KDC-ISSUED element under `key`.
///
/// # Errors
///
/// Returns [`Error::UnsupportedChecksumType`] for a checksum type that is not
/// implemented, [`Error::KeyChecksumTypeMismatch`] when it does not belong to
/// the key, [`Error::Encode`] and [`Error::ChecksumMismatch`].
#[inline]
pub fn verify_kdc_issued(issued: &AdKdcIssued, key: &EncryptionKey) -> Result<(), Error> {
    let checksum_type = issued.ad_checksum.r#type;
    let etype =
        selection::checksum(checksum_type)?.ok_or(Error::UnsupportedChecksumType(checksum_type))?;
    if etype.etype_id() != key.etype() {
        return Err(Error::KeyChecksumTypeMismatch {
            key_etype: key.etype(),
            checksum_type,
        });
    }
    if etype.verify_checksum(
        key.value(),
        &elements_der(&issued.elements)?,
        issued.ad_checksum.checksum.as_ref(),
        KDC_ISSUED_CHECKSUM_USAGE,
    ) {
        Ok(())
    } else {
        Err(Error::ChecksumMismatch)
    }
}

/// Decode the DER of an AD-KDC-ISSUED element.
///
/// # Errors
///
/// Returns [`Error::Decode`].
#[inline]
pub fn decode_kdc_issued(bytes: &[u8]) -> Result<AdKdcIssued, Error> {
    decode("AD-KDC-ISSUED", bytes)
}

/// Decode the DER of an AD-CAMMAC element.
///
/// # Errors
///
/// Returns [`Error::Decode`].
#[inline]
pub fn decode_cammac(bytes: &[u8]) -> Result<Cammac, Error> {
    decode("AD-CAMMAC", bytes)
}

/// Verify the service verifier of an AD-CAMMAC under `key`, the key that
/// decrypted the ticket: an RFC 3961 checksum with key usage 64 over the DER
/// of the elements, of a checksum type of the key's encryption type (RFC 7751
/// section 4; MIT `check_svcver`, `src/lib/krb5/krb/cammac_util.c:36-59`).
///
/// # Errors
///
/// Returns [`Error::CammacVerifierAbsent`] without a service verifier (MIT
/// refuses it too), [`Error::KeyChecksumTypeMismatch`] for a checksum type of
/// another key type, [`Error::Encode`], and [`Error::CammacVerifierMismatch`]
/// for an unknown checksum type or a checksum that does not verify.
#[inline]
pub fn verify_cammac(cammac: &Cammac, key: &EncryptionKey) -> Result<(), Error> {
    let verifier = cammac
        .svc_verifier
        .as_ref()
        .ok_or(Error::CammacVerifierAbsent)?;
    let checksum_type = verifier.mac.r#type;
    let etype = selection::checksum(checksum_type)?.ok_or(Error::CammacVerifierMismatch)?;
    if etype.etype_id() != key.etype() {
        return Err(Error::KeyChecksumTypeMismatch {
            key_etype: key.etype(),
            checksum_type,
        });
    }
    if etype.verify_checksum(
        key.value(),
        &elements_der(&cammac.elements)?,
        verifier.mac.checksum.as_ref(),
        CAMMAC_USAGE,
    ) {
        Ok(())
    } else {
        Err(Error::CammacVerifierMismatch)
    }
}

/// Decode the DER of an AD-AUTHENTICATION-INDICATOR element, `SEQUENCE OF
/// UTF8String` (RFC 8129 section 4; MIT `k5_authind_decode`,
/// `src/lib/krb5/krb/authdata_dec.c:260-296`).
///
/// # Errors
///
/// Returns [`Error::Decode`].
#[inline]
pub fn decode_auth_indicators(bytes: &[u8]) -> Result<Vec<String>, Error> {
    decode::<SequenceOf<Utf8String>>("AD-AUTHENTICATION-INDICATOR", bytes)
}

/// Decode the DER of an AD-AND-OR element.
///
/// # Errors
///
/// Returns [`Error::Decode`].
#[inline]
pub fn decode_and_or(bytes: &[u8]) -> Result<AdAndOr, Error> {
    decode("AD-AND-OR", bytes)
}

/// Evaluate an AD-AND-OR element: its conditions are met when at least
/// `condition-count` of its elements are satisfied (1 is "or", the number of
/// elements is "and").
///
/// # Errors
///
/// Returns [`Error::InvalidConditionCount`] when the count is below one or above
/// the number of elements: such an element cannot be satisfied by design and
/// fails closed.
#[inline]
pub fn evaluate_and_or(
    and_or: &AdAndOr,
    evaluator: &dyn ConditionEvaluator,
) -> Result<bool, Error> {
    let elements = and_or.elements.len();
    let required = usize::try_from(and_or.condition_count)
        .ok()
        .filter(|count| (1..=elements).contains(count))
        .ok_or(Error::InvalidConditionCount {
            count: and_or.condition_count,
            elements,
        })?;
    let satisfied = and_or
        .elements
        .iter()
        .filter(|element| evaluator.evaluate(element) == Some(true))
        .count();
    Ok(satisfied >= required)
}
