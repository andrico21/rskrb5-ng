//! RFC 4556, RFC 8070 and RFC 8636 PKINIT messages, DER with explicit tags
//! (the RFC 4556 module is `DEFINITIONS EXPLICIT TAGS`; MIT 1.22.2
//! `asn1_k_encode.c:1346-1520`).
//!
//! The CMS and X.509 structures they carry stay DER bytes here; `cms` and
//! `x509-cert` decode them.

use alloc::borrow::Cow;

use rasn::{
    AsnType, Decode, Decoder as _, Encode, Encoder as _,
    types::{Any, BitString, ObjectIdentifier, OctetString, SequenceOf},
};
use rasn_kerberos::{KerberosTime, Microseconds, PrincipalName, Realm};

/// `id-pkinit-kdf-ah-sha1` (RFC 8636 section 8).
pub(super) const KDF_SHA1: &[u32] = &[1, 3, 6, 1, 5, 2, 3, 6, 1];
/// `id-pkinit-kdf-ah-sha256`.
pub(super) const KDF_SHA256: &[u32] = &[1, 3, 6, 1, 5, 2, 3, 6, 2];
/// `id-pkinit-kdf-ah-sha512`.
pub(super) const KDF_SHA512: &[u32] = &[1, 3, 6, 1, 5, 2, 3, 6, 3];
/// `id-sha256` (RFC 5754), the paChecksum2 digest.
pub(super) const SHA256: &[u32] = &[2, 16, 840, 1, 101, 3, 4, 2, 1];

/// A rasn object identifier of `arcs`.
pub(super) const fn oid(arcs: &'static [u32]) -> ObjectIdentifier {
    ObjectIdentifier::new_unchecked(Cow::Borrowed(arcs))
}

/// `AlgorithmIdentifier` (RFC 5280 section 4.1.1.2).
#[derive(AsnType, Clone, Debug, Decode, Encode, Eq, PartialEq)]
pub(super) struct AlgorithmIdentifier {
    /// The algorithm.
    pub algorithm: ObjectIdentifier,
    /// Its parameters.
    pub parameters: Option<Any>,
}

/// `PA-PK-AS-REQ` (RFC 4556 section 3.2.1).
#[derive(AsnType, Clone, Debug, Decode, Encode, Eq, PartialEq)]
pub(super) struct PaPkAsReq {
    /// The CMS `ContentInfo` of the signed `AuthPack`.
    #[rasn(tag(0))]
    pub signed_auth_pack: OctetString,
    /// CAs the client trusts; not sent.
    #[rasn(tag(explicit(1)))]
    pub trusted_certifiers: Option<SequenceOf<Any>>,
    /// The KDC key the client expects; not sent.
    #[rasn(tag(2))]
    pub kdc_pk_id: Option<OctetString>,
}

/// `PAChecksum2` (RFC 8636 section 4).
#[derive(AsnType, Clone, Debug, Decode, Encode, Eq, PartialEq)]
pub(super) struct PaChecksum2 {
    /// The digest of the KDC-REQ-BODY.
    #[rasn(tag(explicit(0)))]
    pub checksum: OctetString,
    /// The digest algorithm.
    #[rasn(tag(explicit(1)))]
    pub algorithm_identifier: AlgorithmIdentifier,
}

/// `PKAuthenticator` (RFC 4556 section 3.2.1, RFC 8070, RFC 8636).
#[derive(AsnType, Clone, Debug, Decode, Encode, Eq, PartialEq)]
pub(super) struct PkAuthenticator {
    /// Microseconds of `ctime`.
    #[rasn(tag(explicit(0)))]
    pub cusec: Microseconds,
    /// The client time.
    #[rasn(tag(explicit(1)))]
    pub ctime: KerberosTime,
    /// The request nonce (MIT reuses the AS-REQ nonce, `pkinit_clnt.c:127-132`).
    #[rasn(tag(explicit(2)))]
    pub nonce: u32,
    /// SHA-1 of the KDC-REQ-BODY.
    #[rasn(tag(explicit(3)))]
    pub pa_checksum: Option<OctetString>,
    /// The KDC's freshness token (RFC 8070).
    #[rasn(tag(explicit(4)))]
    pub freshness_token: Option<OctetString>,
    /// SHA-256 of the KDC-REQ-BODY (RFC 8636).
    #[rasn(tag(explicit(5)))]
    pub pa_checksum2: Option<PaChecksum2>,
}

/// `KDFAlgorithmId` (RFC 8636 section 4).
#[derive(AsnType, Clone, Debug, Decode, Encode, Eq, PartialEq)]
pub(super) struct KdfAlgorithmId {
    /// The KDF.
    #[rasn(tag(explicit(0)))]
    pub kdf_id: ObjectIdentifier,
}

/// `AuthPack` (RFC 4556 section 3.2.1, RFC 8636).
#[derive(AsnType, Clone, Debug, Decode, Encode, Eq, PartialEq)]
pub(super) struct AuthPack {
    /// The authenticator.
    #[rasn(tag(explicit(0)))]
    pub pk_authenticator: PkAuthenticator,
    /// The client's DER `SubjectPublicKeyInfo` for key agreement.
    #[rasn(tag(explicit(1)))]
    pub client_public_value: Option<Any>,
    /// CMS algorithms the client supports.
    #[rasn(tag(explicit(2)))]
    pub supported_cms_types: Option<SequenceOf<AlgorithmIdentifier>>,
    /// A nonce for DH key reuse; never sent.
    #[rasn(tag(explicit(3)))]
    pub client_dh_nonce: Option<OctetString>,
    /// The KDFs the client supports, in preference order.
    #[rasn(tag(explicit(4)))]
    pub supported_kdfs: Option<SequenceOf<KdfAlgorithmId>>,
}

/// `DHRepInfo` (RFC 4556 section 3.2.3, RFC 8636).
#[derive(AsnType, Clone, Debug, Decode, Encode, Eq, PartialEq)]
pub(super) struct DhRepInfo {
    /// The CMS `ContentInfo` of the signed `KDCDHKeyInfo`.
    #[rasn(tag(0))]
    pub dh_signed_data: OctetString,
    /// A server nonce for key reuse; refused, as no client nonce is sent.
    #[rasn(tag(explicit(1)))]
    pub server_dh_nonce: Option<OctetString>,
    /// The KDF the KDC chose; absent means `octetstring2key`.
    #[rasn(tag(explicit(2)))]
    pub kdf: Option<KdfAlgorithmId>,
}

/// `PA-PK-AS-REP` (RFC 4556 section 3.2.3), an extensible CHOICE.
#[derive(AsnType, Clone, Debug, Decode, Encode, Eq, PartialEq)]
#[rasn(choice)]
pub(super) enum PaPkAsRep {
    /// Diffie-Hellman key delivery.
    #[rasn(tag(explicit(0)))]
    DhInfo(DhRepInfo),
    /// RSA key transport: rejected (D2).
    #[rasn(tag(1))]
    EncKeyPack(OctetString),
}

/// `KDCDHKeyInfo` (RFC 4556 section 3.2.3.1).
#[derive(AsnType, Clone, Debug, Decode, Encode, Eq, PartialEq)]
pub(super) struct KdcDhKeyInfo {
    /// The KDC's public value: a DER INTEGER or an EC point.
    #[rasn(tag(explicit(0)))]
    pub subject_public_key: BitString,
    /// The `PKAuthenticator` nonce.
    #[rasn(tag(explicit(1)))]
    pub nonce: u32,
    /// When a reused KDC key expires; ignored.
    #[rasn(tag(explicit(2)))]
    pub dh_key_expiration: Option<KerberosTime>,
}

/// `KRB5PrincipalName` (RFC 4556 section 3.2.2): the `id-pkinit-san` value.
#[derive(AsnType, Clone, Debug, Decode, Encode, Eq, PartialEq)]
pub(super) struct Krb5PrincipalName {
    /// The realm.
    #[rasn(tag(explicit(0)))]
    pub realm: Realm,
    /// The name.
    #[rasn(tag(explicit(1)))]
    pub principal_name: PrincipalName,
}

/// `PkinitSuppPubInfo` (RFC 8636 section 6).
#[derive(AsnType, Clone, Debug, Decode, Encode, Eq, PartialEq)]
pub(super) struct PkinitSuppPubInfo {
    /// The reply key's enctype.
    #[rasn(tag(explicit(0)))]
    pub enctype: i32,
    /// The DER AS-REQ as sent.
    #[rasn(tag(explicit(1)))]
    pub as_req: OctetString,
    /// The DER PA-PK-AS-REP as received.
    #[rasn(tag(explicit(2)))]
    pub pk_as_rep: OctetString,
}

/// SP 800-56A `OtherInfo` of RFC 8636 section 6.
#[derive(AsnType, Clone, Debug, Decode, Encode, Eq, PartialEq)]
pub(super) struct OtherInfo {
    /// The KDF, without parameters.
    pub algorithm_id: AlgorithmIdentifier,
    /// The DER `KRB5PrincipalName` of the client.
    #[rasn(tag(explicit(0)))]
    pub party_u_info: OctetString,
    /// The DER `KRB5PrincipalName` of the TGS.
    #[rasn(tag(explicit(1)))]
    pub party_v_info: OctetString,
    /// The DER `PkinitSuppPubInfo`.
    #[rasn(tag(explicit(2)))]
    pub supp_pub_info: OctetString,
}
