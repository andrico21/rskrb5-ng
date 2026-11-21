//! PKINIT: public-key initial authentication (RFC 4556) and anonymous PKINIT
//! (RFC 6112), the `pkinit` leaf.
//!
//! [`Exchange`] is the client half of PA-PK-AS-REQ/PA-PK-AS-REP (MIT
//! 1.22.2 `src/plugins/preauth/pkinit/pkinit_clnt.c`). The AS exchange engine
//! runs it when it is built with `InitCreds::with_pkinit`: the client signs an
//! `AuthPack` with its [`Identity`] (or sends it unsigned for anonymous
//! PKINIT), proposes an ephemeral Diffie-Hellman key in the configured
//! [`DhGroup`], and derives the reply key from the KDC's signed public value
//! with the RFC 8636 KDF it negotiated (or the RFC 4556 `octetstring2key`
//! when the KDC names none). The KDC's certificate must chain to the
//! [`KdcTrust`] anchors and satisfy the [`CertificatePolicy`].
//!
//! Without the `pkinit` Cargo feature the names, the configuration and the
//! policy types exist, [`AVAILABLE`] is `false`, and every operation that
//! needs cryptography or certificate parsing returns
//! [`Error::Unavailable`](crate::error::Pkinit::Unavailable).
//!
//! The traits [`Signer`] and [`IdentityProvider`] are the plugin point (owner
//! decision D8): applications plug in remote signers or tokens through them;
//! no PKCS#11 module is ever loaded. Built-in software identities sign with
//! EC keys only (P-256, P-384) read from PEM files; RSA client keys sign
//! through an application [`Signer`].
//!
//! # Security
//!
//! - The KDC's `SignedData` must carry exactly one signer whose certificate
//!   chains to a configured anchor within [`MAX_CHAIN_LENGTH`] certificates
//!   and [`MAX_CERTIFICATES`] candidates; every link's signature, validity,
//!   CA constraints and key usage are checked, unknown critical extensions are
//!   refused, and configured CRLs are applied (`pkinit_require_crl_checking`
//!   makes a missing CRL fatal).
//! - The KDC certificate must name the realm's TGS in an `id-pkinit-san`, or
//!   a configured `pkinit_kdc_hostname` in a dNSName. Under
//!   [`EkuChecking::KpKdc`] (the default) it must carry `id-pkinit-KPKdc`
//!   (or `id-kp-serverAuth` under [`EkuChecking::KpServerAuth`]) and the
//!   `digitalSignature` key usage, also when the SAN names the TGS: stricter
//!   than MIT, which skips the EKU check then (`pkinit_clnt.c:395-399`).
//! - Finite-field groups are the RFC 3526 2048- and 4096-bit MODP groups;
//!   smaller groups are refused by name (`pkinit_dh_min_bits = 1024` is a
//!   typed error). The KDC's public value must lie in `2..=p-2` and in the
//!   prime-order subgroup; EC points must be valid, non-identity points of
//!   the requested curve. The private exponent and scalar, the shared secret
//!   and the derived key live in zeroizing owners, and the exponentiation is
//!   the constant-time one of the admitted crates.
//! - RSA key transport (the `encKeyPack` reply) and draft-9 PKINIT stay
//!   rejected (D2); RSA *signatures* on certificates are verified, with
//!   moduli of at least [`MIN_RSA_BITS`] bits.
//! - Every untrusted structure is bounded before it is decoded:
//!   [`MAX_MESSAGE_BYTES`], [`MAX_CERTIFICATE_BYTES`] and [`MAX_CRL_BYTES`].

use alloc::sync::Arc;
use core::fmt;
use std::path::{Path, PathBuf};

use crate::{
    client::principal::Principal, config::Config, error::Pkinit as Error, extensions::ProviderError,
};

/// The anonymous FAST armor source.
#[path = "pkinit/armor.rs"]
mod armor;
/// RFC 4556 and RFC 8636 messages.
#[cfg(feature = "pkinit")]
#[path = "pkinit/asn1.rs"]
mod asn1;
/// The bounded path validator and the KDC identity checks.
#[cfg(feature = "pkinit")]
#[path = "pkinit/chain.rs"]
mod chain;
/// CMS `SignedData`.
#[cfg(feature = "pkinit")]
#[path = "pkinit/cms.rs"]
mod cms;
/// Configuration of the client half from `[realms]` and `[libdefaults]`.
#[path = "pkinit/config.rs"]
mod config;
/// Key agreement.
#[cfg(feature = "pkinit")]
#[path = "pkinit/dh.rs"]
mod dh;
/// The exchange state and its engine-facing calls.
#[path = "pkinit/exchange.rs"]
pub(crate) mod exchange;
/// The RFC 8636 KDF and `octetstring2key`.
#[cfg(feature = "pkinit")]
#[path = "pkinit/kdf.rs"]
mod kdf;
/// Signatures, the software signer and PEM.
#[cfg(feature = "pkinit")]
#[path = "pkinit/keys.rs"]
mod keys;
/// The cryptographic and parsing operations of the leaf.
#[cfg(feature = "pkinit")]
#[path = "pkinit/ops.rs"]
mod ops;
/// The operations without the leaf: every call is [`Error::Unavailable`].
#[cfg(not(feature = "pkinit"))]
#[path = "pkinit/unavailable.rs"]
mod ops;
/// The RFC 3526 primes.
#[cfg(feature = "pkinit")]
#[path = "pkinit/primes.rs"]
mod primes;
/// Known-answer and negative tests of the operations.
#[cfg(test)]
#[cfg(feature = "pkinit")]
#[path = "pkinit/tests.rs"]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests;

/// `PA-PK-AS-REQ` (RFC 4556 section 3.2.1).
pub const PA_PK_AS_REQ: i32 = 16;
/// `PA-PK-AS-REP` (RFC 4556 section 3.2.3).
pub const PA_PK_AS_REP: i32 = 17;
/// `PA-PKINIT-KX` (RFC 6112 section 6).
pub const PA_PKINIT_KX: i32 = 147;
/// `PA-AS-FRESHNESS` (RFC 8070 section 4).
pub const PA_AS_FRESHNESS: i32 = 150;
/// `KEY_USAGE_PA_PKINIT_KX` (RFC 6112 section 6).
pub const KEY_USAGE_PA_PKINIT_KX: u32 = 44;
/// `request-anonymous`, KDC option bit 16 (RFC 6112 section 4.1).
pub const KDC_OPTION_REQUEST_ANONYMOUS: u32 = 0x0000_8000;
/// The largest PA-PK-AS-REP this client decodes, in bytes.
pub const MAX_MESSAGE_BYTES: usize = 0x0001_0000;
/// The largest certificate this client decodes, in bytes.
pub const MAX_CERTIFICATE_BYTES: usize = 0x4000;
/// The largest CRL this client decodes, in bytes.
pub const MAX_CRL_BYTES: usize = 0x0010_0000;
/// The most certificates of one chain, anchor included.
pub const MAX_CHAIN_LENGTH: usize = 8;
/// The most certificates a chain is built from (pool, anchors and the
/// KDC's `SignedData` together).
pub const MAX_CERTIFICATES: usize = 64;
/// The smallest RSA modulus accepted on a certificate or a CMS signature.
pub const MIN_RSA_BITS: usize = 2048;
/// Whether the `pkinit` leaf feature, and with it the cryptography, is compiled in.
pub const AVAILABLE: bool = cfg!(feature = "pkinit");

/// A signature algorithm a [`Signer`] produces.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SignatureAlgorithm {
    /// ECDSA over P-256 with SHA-256; the signature is a DER `ECDSA-Sig-Value`.
    EcdsaP256Sha256,
    /// ECDSA over P-384 with SHA-384; the signature is a DER `ECDSA-Sig-Value`.
    EcdsaP384Sha384,
    /// RSASSA-PKCS1-v1_5 with SHA-256.
    RsaPkcs1Sha256,
}

/// Signs the client's CMS signed attributes: the D8 plugin point for remote
/// signers, tokens and RSA keys.
///
/// # Security
///
/// The message is the DER `SignedAttributes` of the `AuthPack`; a signer
/// hashes it with the algorithm's digest and must sign nothing else.
pub trait Signer: Send + Sync {
    /// The algorithm of [`Signer::sign`], which must match the key of the
    /// identity's certificate.
    fn algorithm(&self) -> SignatureAlgorithm;

    /// Sign `message`.
    ///
    /// # Errors
    ///
    /// Returns the signer's failure; the exchange reports
    /// [`Error::Provider`](crate::error::Pkinit::Provider).
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, ProviderError>;
}

/// A client certificate chain (leaf first, DER) and the signer of its key.
/// Its `Debug` output names the chain length only.
#[derive(Clone)]
pub struct Identity {
    /// The DER certificates, the client's own first.
    certificates: Vec<Vec<u8>>,
    /// The signer of the first certificate's key.
    signer: Arc<dyn Signer>,
}

impl Identity {
    /// An identity from DER `certificates` (the client's own first) and its signer.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Identity`](crate::error::Pkinit::Identity) for an
    /// empty chain, more than [`MAX_CHAIN_LENGTH`] certificates or a
    /// certificate over [`MAX_CERTIFICATE_BYTES`].
    #[inline]
    pub fn new(certificates: Vec<Vec<u8>>, signer: Arc<dyn Signer>) -> Result<Self, Error> {
        let oversized = certificates
            .iter()
            .any(|certificate| certificate.len() > MAX_CERTIFICATE_BYTES);
        if certificates.is_empty() || certificates.len() > MAX_CHAIN_LENGTH || oversized {
            return Err(Error::Identity {
                reason: "the chain must hold 1 to MAX_CHAIN_LENGTH bounded certificates",
            });
        }
        Ok(Self {
            certificates,
            signer,
        })
    }

    /// A software identity: PEM `certificate` (the client's own first, then
    /// any intermediates) and a PEM P-256 or P-384 private key (`PRIVATE
    /// KEY` or `EC PRIVATE KEY`). The key is erased when the identity is
    /// dropped.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Unavailable`](crate::error::Pkinit::Unavailable)
    /// without the leaf, and [`Error::Identity`](crate::error::Pkinit::Identity)
    /// for unreadable PEM, an unsupported key or a key that does not match
    /// the certificate.
    #[inline]
    pub fn from_pem(certificate: &[u8], key: &[u8]) -> Result<Self, Error> {
        let certificates = ops::pem_certificates(certificate)?;
        let signer = ops::software_signer(key, certificates.first())?;
        Self::new(certificates, signer)
    }

    /// A software identity from files (MIT `FILE:cert[,key]`): the key is in
    /// `key`, or in `certificate` when `key` is `None`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`](crate::error::Pkinit::Io) for an unreadable file
    /// and the errors of [`Identity::from_pem`].
    #[inline]
    pub fn from_files(certificate: &Path, key: Option<&Path>) -> Result<Self, Error> {
        let certificates = config::read(certificate, MAX_CRL_BYTES)?;
        let keys = config::read(key.unwrap_or(certificate), MAX_CERTIFICATE_BYTES)?;
        Self::from_pem(&certificates, &keys)
    }

    /// The client's DER certificate.
    #[inline]
    #[must_use]
    pub fn certificate(&self) -> &[u8] {
        self.certificates.first().map_or(&[], Vec::as_slice)
    }

    /// The DER chain, the client's certificate first.
    #[inline]
    #[must_use]
    pub fn certificates(&self) -> &[Vec<u8>] {
        &self.certificates
    }

    /// The signer of the client's key.
    #[inline]
    #[must_use]
    pub fn signer(&self) -> &dyn Signer {
        &*self.signer
    }
}

impl fmt::Debug for Identity {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Identity")
            .field("certificates", &self.certificates.len())
            .field("algorithm", &self.signer.algorithm())
            .finish_non_exhaustive()
    }
}

/// Supplies the client identity for an exchange: the D8 plugin point for
/// smart cards and remote key stores.
pub trait IdentityProvider: Send + Sync {
    /// The identity to authenticate `client` with.
    ///
    /// # Errors
    ///
    /// Returns the provider's failure; the exchange reports
    /// [`Error::Provider`](crate::error::Pkinit::Provider).
    fn identity(&self, client: &Principal) -> Result<Identity, ProviderError>;
}

/// The identities of `pkinit_identities`: `FILE:` and `DIR:` locations, and
/// `ENV:` references to them, tried in order (MIT `pkinit_identity.c`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfiguredIdentities {
    /// `(certificate, key)` file pairs, in order.
    files: Vec<(PathBuf, Option<PathBuf>)>,
}

impl ConfiguredIdentities {
    /// The identities of `realm` in `config`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnsupportedLocation`](crate::error::Pkinit::UnsupportedLocation)
    /// for `PKCS11:` (D8) and `PKCS12:` locations, for an `ENV:` variable that
    /// names one and for configured `pkinit_cert_match` rules (not evaluated),
    /// and [`Error::Io`](crate::error::Pkinit::Io) for an unreadable `DIR:`
    /// location.
    #[inline]
    pub fn from_config(config: &Config, realm: &str) -> Result<Self, Error> {
        config::identities(config, realm).map(|files| Self { files })
    }

    /// The `(certificate, key)` file pairs, in order.
    #[inline]
    #[must_use]
    pub fn files(&self) -> &[(PathBuf, Option<PathBuf>)] {
        &self.files
    }
}

impl IdentityProvider for ConfiguredIdentities {
    #[inline]
    fn identity(&self, _client: &Principal) -> Result<Identity, ProviderError> {
        let mut last: Option<Error> = None;
        for (certificate, key) in &self.files {
            match Identity::from_files(certificate, key.as_deref()) {
                Ok(identity) => return Ok(identity),
                Err(error) => last = Some(error),
            }
        }
        Err(Box::new(last.unwrap_or(Error::Identity {
            reason: "pkinit_identities names no identity",
        })))
    }
}

/// The certificates the client trusts to vouch for a KDC: anchors
/// (`pkinit_anchors`), intermediates (`pkinit_pool`) and CRLs
/// (`pkinit_revoke`), all DER. Its `Debug` output names the counts only.
#[derive(Clone, Default, Eq, PartialEq)]
pub struct KdcTrust {
    /// Trust anchors.
    anchors: Vec<Vec<u8>>,
    /// Intermediate certificates.
    intermediates: Vec<Vec<u8>>,
    /// Certificate revocation lists.
    crls: Vec<Vec<u8>>,
}

impl KdcTrust {
    /// Trust in DER `anchors`.
    #[inline]
    #[must_use]
    pub const fn new(anchors: Vec<Vec<u8>>) -> Self {
        Self {
            anchors,
            intermediates: Vec::new(),
            crls: Vec::new(),
        }
    }

    /// Trust in the PEM certificates of `anchors`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Unavailable`](crate::error::Pkinit::Unavailable)
    /// without the leaf and [`Error::Malformed`](crate::error::Pkinit::Malformed)
    /// for unreadable PEM.
    #[inline]
    pub fn from_pem(anchors: &[u8]) -> Result<Self, Error> {
        ops::pem_certificates(anchors).map(Self::new)
    }

    /// The trust of `realm` in `config` (`pkinit_anchors`, `pkinit_pool`,
    /// `pkinit_revoke`).
    ///
    /// # Errors
    ///
    /// Returns [`Error::NoAnchors`](crate::error::Pkinit::NoAnchors) when no
    /// anchor is configured, [`Error::Io`](crate::error::Pkinit::Io) for an
    /// unreadable location and the PEM errors of [`KdcTrust::from_pem`].
    #[inline]
    pub fn from_config(config: &Config, realm: &str) -> Result<Self, Error> {
        config::trust(config, realm)
    }

    /// Add DER intermediate certificates.
    #[inline]
    #[must_use]
    pub fn with_intermediates(mut self, intermediates: Vec<Vec<u8>>) -> Self {
        self.intermediates = intermediates;
        self
    }

    /// Add DER certificate revocation lists.
    #[inline]
    #[must_use]
    pub fn with_crls(mut self, crls: Vec<Vec<u8>>) -> Self {
        self.crls = crls;
        self
    }

    /// The DER anchors.
    #[inline]
    #[must_use]
    pub fn anchors(&self) -> &[Vec<u8>] {
        &self.anchors
    }

    /// The DER intermediates.
    #[inline]
    #[must_use]
    pub fn intermediates(&self) -> &[Vec<u8>] {
        &self.intermediates
    }

    /// The DER CRLs.
    #[inline]
    #[must_use]
    pub fn crls(&self) -> &[Vec<u8>] {
        &self.crls
    }
}

impl fmt::Debug for KdcTrust {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KdcTrust")
            .field("anchors", &self.anchors.len())
            .field("intermediates", &self.intermediates.len())
            .field("crls", &self.crls.len())
            .finish()
    }
}

/// Which Extended Key Usage the KDC certificate must carry (`pkinit_eku_checking`).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub enum EkuChecking {
    /// `id-pkinit-KPKdc` (RFC 4556), the default.
    #[default]
    KpKdc,
    /// `id-pkinit-KPKdc` or `id-kp-serverAuth`.
    KpServerAuth,
    /// No EKU check (not recommended).
    None,
}

/// The Diffie-Hellman group the client proposes (`pkinit_dh_min_bits`).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub enum DhGroup {
    /// The RFC 3526 2048-bit MODP group (group 14), MIT's default.
    #[default]
    Modp2048,
    /// The RFC 3526 4096-bit MODP group (group 16).
    Modp4096,
    /// ECDH over P-256 (RFC 5349).
    P256,
    /// ECDH over P-384 (RFC 5349).
    P384,
    /// ECDH over P-521 (RFC 5349).
    P521,
}

impl DhGroup {
    /// The group of a `pkinit_dh_min_bits` value, as MIT's
    /// `parse_dh_min_bits` (`pkinit_crypto_openssl.c:5673-5700`) maps it:
    /// a number up to 2048 selects the 2048-bit group, up to 4096 the
    /// 4096-bit group; curve names are matched without case.
    ///
    /// # Errors
    ///
    /// Returns [`Error::DhGroupTooSmall`](crate::error::Pkinit::DhGroupTooSmall)
    /// for 1024 bits or fewer (MIT accepts 1024; the floor here is 2048), and
    /// [`Error::InvalidDhGroup`](crate::error::Pkinit::InvalidDhGroup) for
    /// anything else MIT would replace by its default.
    #[inline]
    pub fn from_min_bits(value: &str) -> Result<Self, Error> {
        config::dh_group(value)
    }
}

/// How the client judges the KDC certificate.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CertificatePolicy {
    /// The EKU requirement.
    eku: EkuChecking,
    /// Hostnames accepted in a dNSName SAN (`pkinit_kdc_hostname`).
    kdc_hostnames: Vec<String>,
    /// Whether a missing CRL fails the chain (`pkinit_require_crl_checking`).
    require_crl_checking: bool,
    /// The proposed group.
    group: DhGroup,
}

impl CertificatePolicy {
    /// The policy of `realm` in `config`.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`DhGroup::from_min_bits`].
    #[inline]
    pub fn from_config(config: &Config, realm: &str) -> Result<Self, Error> {
        config::policy(config, realm)
    }

    /// Set the EKU requirement.
    #[inline]
    #[must_use]
    pub const fn with_eku_checking(mut self, eku: EkuChecking) -> Self {
        self.eku = eku;
        self
    }

    /// Accept these hostnames in a dNSName SAN of the KDC certificate.
    #[inline]
    #[must_use]
    pub fn with_kdc_hostnames(mut self, hostnames: Vec<String>) -> Self {
        self.kdc_hostnames = hostnames;
        self
    }

    /// Fail when no CRL covers a certificate's issuer.
    #[inline]
    #[must_use]
    pub const fn with_crl_checking(mut self, required: bool) -> Self {
        self.require_crl_checking = required;
        self
    }

    /// Propose `group`.
    #[inline]
    #[must_use]
    pub const fn with_group(mut self, group: DhGroup) -> Self {
        self.group = group;
        self
    }

    /// The EKU requirement.
    #[inline]
    #[must_use]
    pub const fn eku_checking(&self) -> EkuChecking {
        self.eku
    }

    /// The accepted dNSName hostnames.
    #[inline]
    #[must_use]
    pub fn kdc_hostnames(&self) -> &[String] {
        &self.kdc_hostnames
    }

    /// Whether a missing CRL fails the chain.
    #[inline]
    #[must_use]
    pub const fn crl_checking(&self) -> bool {
        self.require_crl_checking
    }

    /// The proposed group.
    #[inline]
    #[must_use]
    pub const fn group(&self) -> DhGroup {
        self.group
    }
}

/// Anonymous initial credentials (RFC 6112), set on the request options.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum AnonymousOptions {
    /// Fully anonymous: the client is `WELLKNOWN/ANONYMOUS@REALM` in the
    /// request, authenticates by anonymous PKINIT, and the ticket names
    /// `WELLKNOWN/ANONYMOUS@WELLKNOWN:ANONYMOUS` (MIT `kinit -n @REALM`).
    Full,
    /// Realm-exposed: a client that authenticates normally asks the KDC to
    /// replace its name, not its realm, by `WELLKNOWN/ANONYMOUS` (MIT 1.22.2
    /// KDCs do not issue these; the request then fails with the KDC's error).
    RealmExposed,
}

impl AnonymousOptions {
    /// The anonymous principal `WELLKNOWN/ANONYMOUS@realm` (name type
    /// `KRB5_NT_WELLKNOWN`).
    #[inline]
    #[must_use]
    pub fn client(realm: &str) -> Principal {
        Principal::new(
            realm.to_owned(),
            NT_WELLKNOWN,
            vec!["WELLKNOWN".to_owned(), "ANONYMOUS".to_owned()],
        )
    }

    /// The client name the ticket must carry for a request in `realm`.
    #[inline]
    #[must_use]
    pub fn expected_client(self, realm: &str) -> Principal {
        match self {
            Self::Full => Self::client(ANONYMOUS_REALM),
            Self::RealmExposed => Self::client(realm),
        }
    }
}

/// Admit an outgoing PA-PK-AS-REQ: only a bounded DER PA-PK-AS-REQ leaves
/// the client (the outgoing PA-DATA admission of `client::crypto_policy`).
///
/// # Errors
/// Returns [`Error::Unavailable`](crate::error::Pkinit::Unavailable) without
/// the leaf, and [`Error::TooLarge`](crate::error::Pkinit::TooLarge) or
/// [`Error::Malformed`](crate::error::Pkinit::Malformed) for anything else.
pub(crate) fn outgoing(value: &[u8]) -> Result<(), Error> {
    ops::outgoing(value)
}

/// Anonymous FAST armor (RFC 6113 section 5.4.1.1 with RFC 6112): the armor
/// TGT of a realm, from anonymous PKINIT over a blocking transport.
///
/// It is the [`AnonymousArmor`](trait@crate::preauth::fast::AnonymousArmor)
/// hook of FAST (MIT `kinit -n` for the armor cache, then `kinit -T`): use it
/// as `ArmorSource::Anonymous`. Each call runs one fully anonymous PKINIT
/// exchange for the requested realm and authenticates the KDC with `trust`
/// and `policy`. With the Tokio transport, obtain the anonymous TGT with
/// `drive_tokio` first and armor with `ArmorSource::Ticket` instead. Its
/// `Debug` output names no key.
pub struct AnonymousArmorSource<T> {
    /// The blocking transport to the realm's KDCs.
    transport: T,
    /// The KDC trust.
    trust: KdcTrust,
    /// The KDC certificate and group policy.
    policy: CertificatePolicy,
}

impl<T> AnonymousArmorSource<T> {
    /// An armor source over `transport` that trusts KDCs per `trust` and `policy`.
    #[inline]
    #[must_use]
    pub const fn new(transport: T, trust: KdcTrust, policy: CertificatePolicy) -> Self {
        Self {
            transport,
            trust,
            policy,
        }
    }
}

impl<T> fmt::Debug for AnonymousArmorSource<T> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AnonymousArmorSource")
            .field("trust", &self.trust)
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}

/// `KRB5_NT_WELLKNOWN` (RFC 6111).
const NT_WELLKNOWN: i32 = 11;
/// The anonymous realm (RFC 6111).
const ANONYMOUS_REALM: &str = "WELLKNOWN:ANONYMOUS";

/// Who the client is in an exchange.
#[derive(Clone)]
enum Credential {
    /// A fixed identity.
    Identity(Identity),
    /// An identity the provider supplies for the client.
    Provider(Arc<dyn IdentityProvider>),
    /// Anonymous PKINIT: an unsigned `AuthPack`.
    Anonymous,
}

/// The client half of one PKINIT exchange; install it with
/// `InitCreds::with_pkinit`. Its `Debug` output names no key.
pub struct Exchange {
    /// The client credential.
    credential: Credential,
    /// The anchors, pool and CRLs.
    trust: KdcTrust,
    /// The certificate and group policy.
    policy: CertificatePolicy,
    /// The state between request and reply.
    pending: Option<exchange::Pending>,
}

impl Exchange {
    /// Authenticate with `identity`.
    #[inline]
    #[must_use]
    pub const fn new(identity: Identity, trust: KdcTrust, policy: CertificatePolicy) -> Self {
        Self {
            credential: Credential::Identity(identity),
            trust,
            policy,
            pending: None,
        }
    }

    /// Authenticate with the identity `provider` supplies for the client.
    #[inline]
    #[must_use]
    pub fn with_provider(
        provider: Arc<dyn IdentityProvider>,
        trust: KdcTrust,
        policy: CertificatePolicy,
    ) -> Self {
        Self {
            credential: Credential::Provider(provider),
            trust,
            policy,
            pending: None,
        }
    }

    /// Anonymous PKINIT (RFC 6112): no client certificate; the KDC is still
    /// authenticated by `trust` and `policy`.
    #[inline]
    #[must_use]
    pub const fn anonymous(trust: KdcTrust, policy: CertificatePolicy) -> Self {
        Self {
            credential: Credential::Anonymous,
            trust,
            policy,
            pending: None,
        }
    }

    /// An exchange for `realm` from `config`: [`ConfiguredIdentities`],
    /// [`KdcTrust::from_config`] and [`CertificatePolicy::from_config`].
    ///
    /// # Errors
    ///
    /// Returns the configuration errors of the three.
    #[inline]
    pub fn from_config(config: &Config, realm: &str) -> Result<Self, Error> {
        let identities = ConfiguredIdentities::from_config(config, realm)?;
        Ok(Self::with_provider(
            Arc::new(identities),
            KdcTrust::from_config(config, realm)?,
            CertificatePolicy::from_config(config, realm)?,
        ))
    }

    /// An anonymous exchange for `realm` from `config`.
    ///
    /// # Errors
    ///
    /// Returns the configuration errors of the trust and the policy.
    #[inline]
    pub fn anonymous_from_config(config: &Config, realm: &str) -> Result<Self, Error> {
        Ok(Self::anonymous(
            KdcTrust::from_config(config, realm)?,
            CertificatePolicy::from_config(config, realm)?,
        ))
    }

    /// Whether this is anonymous PKINIT.
    #[inline]
    #[must_use]
    pub const fn is_anonymous(&self) -> bool {
        matches!(self.credential, Credential::Anonymous)
    }

    /// The trust.
    #[inline]
    #[must_use]
    pub const fn trust(&self) -> &KdcTrust {
        &self.trust
    }

    /// The policy.
    #[inline]
    #[must_use]
    pub const fn policy(&self) -> &CertificatePolicy {
        &self.policy
    }
}

impl fmt::Debug for Exchange {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let credential = match &self.credential {
            Credential::Identity(_) => "identity",
            Credential::Provider(_) => "provider",
            Credential::Anonymous => "anonymous",
        };
        f.debug_struct("Exchange")
            .field("credential", &credential)
            .field("trust", &self.trust)
            .field("policy", &self.policy)
            .field("pending", &self.pending.is_some())
            .finish()
    }
}
