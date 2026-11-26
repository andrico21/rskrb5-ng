//! AD-CAMMAC fixtures (RFC 7751), built without the crate's own CAMMAC code.
//!
//! The service verifier is the RFC 3961 checksum of the DER of the elements
//! under the key that encrypts the ticket, key usage 64 (RFC 7751 section 4;
//! MIT 1.22.2 `src/kdc/cammac.c:94-103`, `KRB5_KEYUSAGE_CAMMAC` in
//! `krb5.hin:1001`). The KDC puts the container inside AD-IF-RELEVANT
//! (`cammac.c:111-121`) and the indicators in an AD-AUTH-INDICATOR element, a
//! `SEQUENCE OF UTF8String` (`kdc_authdata.c:301-336`).

use core::error::Error;

use rasn::{AsnType, Decode, Decoder as _, Encode, Encoder as _, der, types::Utf8String};
use rasn_kerberos::{AuthorizationData, AuthorizationDataValue, Checksum};
use rskrb5_ng::{crypto::AesSha1Etype, keytab::EncryptionKey};

/// The failure of a fixture builder.
type Failure = Box<dyn Error>;

/// AD-IF-RELEVANT.
pub(crate) const AD_IF_RELEVANT: i32 = 1;
/// AD-CAMMAC.
pub(crate) const AD_CAMMAC: i32 = 96;
/// AD-AUTH-INDICATOR.
pub(crate) const AD_AUTH_INDICATOR: i32 = 97;
/// The key usage of a Verifier-MAC.
const CAMMAC_USAGE: u32 = 64;

/// `Verifier-MAC` of RFC 7751 section 4.
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq)]
pub(crate) struct VerifierMac {
    /// `identifier`.
    #[rasn(tag(explicit(0)))]
    pub identifier: Option<rasn_kerberos::PrincipalName>,
    /// `kvno`.
    #[rasn(tag(explicit(1)))]
    pub kvno: Option<u32>,
    /// `enctype`.
    #[rasn(tag(explicit(2)))]
    pub enctype: Option<i32>,
    /// `mac`.
    #[rasn(tag(explicit(3)))]
    pub mac: Checksum,
}

/// `AD-CAMMAC` of RFC 7751 section 4, without `other-verifiers`, as MIT issues it.
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq)]
pub(crate) struct Cammac {
    /// `elements`.
    #[rasn(tag(explicit(0)))]
    pub elements: AuthorizationData,
    /// `kdc-verifier`.
    #[rasn(tag(explicit(1)))]
    pub kdc_verifier: Option<VerifierMac>,
    /// `svc-verifier`.
    #[rasn(tag(explicit(2)))]
    pub svc_verifier: Option<VerifierMac>,
}

/// An AD-AUTH-INDICATOR element holding `values`.
///
/// # Errors
///
/// Returns the encoding error.
pub(crate) fn indicators(values: &[&str]) -> Result<AuthorizationDataValue, Failure> {
    let list: Vec<Utf8String> = values.iter().map(|value| (*value).to_owned()).collect();
    Ok(element(AD_AUTH_INDICATOR, der::encode(&list)?))
}

/// One authorization-data element.
pub(crate) fn element(kind: i32, data: Vec<u8>) -> AuthorizationDataValue {
    AuthorizationDataValue {
        r#type: kind,
        data: data.into(),
    }
}

/// The CAMMAC of `elements` whose service verifier is made under `key` (an
/// AES-SHA1 key) with the key's checksum type.
///
/// # Errors
///
/// Returns the key-type, encoding and checksum errors.
pub(crate) fn cammac(elements: AuthorizationData, key: &EncryptionKey) -> Result<Cammac, Failure> {
    let etype = AesSha1Etype::from_etype_id(key.etype()).ok_or("an AES-SHA1 key")?;
    let mac = etype.checksum(key.value(), &der::encode(&elements)?, CAMMAC_USAGE)?;
    Ok(Cammac {
        elements,
        kdc_verifier: None,
        svc_verifier: Some(VerifierMac {
            identifier: None,
            kvno: None,
            enctype: None,
            mac: Checksum {
                r#type: etype.checksum_type_id(),
                checksum: mac.into(),
            },
        }),
    })
}

/// `cammac` as the KDC puts it into a ticket: one AD-CAMMAC element inside
/// AD-IF-RELEVANT.
///
/// # Errors
///
/// Returns the encoding error.
pub(crate) fn wrapped(cammac: &Cammac) -> Result<AuthorizationData, Failure> {
    let inner = vec![element(AD_CAMMAC, der::encode(cammac)?)];
    Ok(vec![element(AD_IF_RELEVANT, der::encode(&inner)?)])
}
