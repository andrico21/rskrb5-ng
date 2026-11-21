//! A fake KDC for PKINIT (RFC 4556, RFC 6112, RFC 8636).
//!
//! It is independent of the crate's PKINIT code: its own ASN.1 definitions, its own CMS assembly with
//! the `cms` crate, `p256` for ECDH and the KDC signature, and its own
//! RFC 8636 KDF over `sha2`. The KDC key and certificates are the OpenSSL
//! fixtures of `fixtures/generate.sh`.

use core::{error::Error, ops::Mul as _, time::Duration};
use std::time::{SystemTime, UNIX_EPOCH};

use cms::{
    cert::{CertificateChoices, IssuerAndSerialNumber},
    content_info::{CmsVersion, ContentInfo},
    signed_data::{
        CertificateSet, EncapsulatedContentInfo, SignedData, SignerIdentifier, SignerInfo,
        SignerInfos,
    },
};
use der::{
    Decode as _, Encode as _,
    asn1::{Any as DerAny, ObjectIdentifier, OctetString as DerOctetString, SetOfVec},
    pem,
};
use p256::{
    ecdsa::{Signature, SigningKey, signature::Signer as _},
    elliptic_curve::{pkcs8::DecodePrivateKey as _, sec1::ToSec1Point as _},
};
use rasn::{
    AsnType, Decode, Decoder as _, Encode, Encoder as _, der as rasn_der,
    types::{Any, BitString, Integer, ObjectIdentifier as RasnOid, OctetString, SequenceOf},
};
use rasn_kerberos::{
    AsReq, EncryptedData, EncryptionKey as KeyBlock, KerberosString, KerberosTime, KrbError,
    PaData, PrincipalName, Realm,
};
use rskrb5_ng::{
    client::KdcTransport,
    crypto::{KerberosEtype, prf},
    error::Client as ClientError,
    keytab::EncryptionKey,
    preauth::pkinit::{
        KEY_USAGE_PA_PKINIT_KX, PA_AS_FRESHNESS, PA_PK_AS_REP, PA_PK_AS_REQ, PA_PKINIT_KX,
    },
};
use sha2::{Digest as _, Sha256};
use x509_cert::{Certificate, attr::Attribute};

/// A boxed test failure.
pub(crate) type TestError = Box<dyn Error>;

/// The realm.
pub(crate) const REALM: &str = "TEST.RSKRB5";
/// The freshness token the KDC hands out.
pub(crate) const FRESHNESS: &[u8] = b"kdc-freshness-token";
/// `KDC_ERR_PREAUTH_REQUIRED`.
const PREAUTH_REQUIRED: i32 = 25;
/// The KDC clock: now, in whole seconds (the client checks the KDC
/// certificate at the real time, so the scenarios run at it too).
fn start() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// A fixture file.
macro_rules! fixture {
    ($name:literal) => {
        include_bytes!(concat!("fixtures/", $name))
    };
}

/// The CA certificate the client trusts.
pub(crate) const CA_EC: &[u8] = fixture!("ca-ec.pem");
/// The client certificate.
pub(crate) const CLIENT_PEM: &[u8] = fixture!("client.pem");
/// The client key (SEC1).
pub(crate) const CLIENT_KEY: &[u8] = fixture!("client.key");

/// Which certificate the KDC signs with, or how it misbehaves.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Behaviour {
    /// The proper KDC certificate.
    Honest,
    /// A certificate without the KDC EKU.
    NoEku,
    /// A certificate naming another realm's TGS.
    WrongSan,
    /// A certificate from an untrusted CA.
    Untrusted,
    /// RSA key transport (`encKeyPack`).
    EncKeyPack,
    /// A `KDCDHKeyInfo` nonce other than the authenticator's.
    WrongNonce,
    /// A truncated `SignedData`.
    MalformedCms,
    /// No PA-PKINIT-KX in an anonymous reply.
    MissingKx,
    /// A PA-PKINIT-KX key that is not the one the session key was made from.
    WrongKx,
}

/// `AlgorithmIdentifier`.
#[derive(AsnType, Clone, Debug, Decode, Encode)]
pub(crate) struct AlgorithmIdentifier {
    /// The algorithm.
    algorithm: RasnOid,
    /// The parameters.
    parameters: Option<Any>,
}

/// `PA-PK-AS-REQ`.
#[derive(AsnType, Clone, Debug, Decode, Encode)]
struct PaPkAsReq {
    /// The signed `AuthPack`.
    #[rasn(tag(0))]
    signed_auth_pack: OctetString,
    /// Trusted CAs.
    #[rasn(tag(explicit(1)))]
    trusted_certifiers: Option<SequenceOf<Any>>,
    /// The KDC key id.
    #[rasn(tag(2))]
    kdc_pk_id: Option<OctetString>,
}

/// `PAChecksum2`.
#[derive(AsnType, Clone, Debug, Decode, Encode)]
pub(crate) struct PaChecksum2 {
    /// The digest.
    #[rasn(tag(explicit(0)))]
    checksum: OctetString,
    /// Its algorithm.
    #[rasn(tag(explicit(1)))]
    algorithm: AlgorithmIdentifier,
}

/// `PKAuthenticator`.
#[derive(AsnType, Clone, Debug, Decode, Encode)]
pub(crate) struct PkAuthenticator {
    /// Microseconds.
    #[rasn(tag(explicit(0)))]
    pub cusec: Integer,
    /// Client time.
    #[rasn(tag(explicit(1)))]
    pub ctime: KerberosTime,
    /// Nonce.
    #[rasn(tag(explicit(2)))]
    pub nonce: u32,
    /// SHA-1 of the body.
    #[rasn(tag(explicit(3)))]
    pub pa_checksum: Option<OctetString>,
    /// The freshness token.
    #[rasn(tag(explicit(4)))]
    pub freshness_token: Option<OctetString>,
    /// SHA-256 of the body.
    #[rasn(tag(explicit(5)))]
    pub pa_checksum2: Option<PaChecksum2>,
}

/// `KDFAlgorithmId`.
#[derive(AsnType, Clone, Debug, Decode, Encode)]
pub(crate) struct KdfAlgorithmId {
    /// The KDF.
    #[rasn(tag(explicit(0)))]
    kdf_id: RasnOid,
}

/// `AuthPack`.
#[derive(AsnType, Clone, Debug, Decode, Encode)]
pub(crate) struct AuthPack {
    /// The authenticator.
    #[rasn(tag(explicit(0)))]
    pub pk_authenticator: PkAuthenticator,
    /// The client's SPKI.
    #[rasn(tag(explicit(1)))]
    pub client_public_value: Option<Any>,
    /// CMS types.
    #[rasn(tag(explicit(2)))]
    pub supported_cms_types: Option<SequenceOf<AlgorithmIdentifier>>,
    /// DH nonce.
    #[rasn(tag(explicit(3)))]
    pub client_dh_nonce: Option<OctetString>,
    /// KDFs.
    #[rasn(tag(explicit(4)))]
    pub supported_kdfs: Option<SequenceOf<KdfAlgorithmId>>,
}

/// `DHRepInfo`.
#[derive(AsnType, Clone, Debug, Decode, Encode)]
struct DhRepInfo {
    /// The signed `KDCDHKeyInfo`.
    #[rasn(tag(0))]
    dh_signed_data: OctetString,
    /// Server nonce.
    #[rasn(tag(explicit(1)))]
    server_dh_nonce: Option<OctetString>,
    /// The KDF.
    #[rasn(tag(explicit(2)))]
    kdf: Option<KdfAlgorithmId>,
}

/// `PA-PK-AS-REP`.
#[derive(AsnType, Clone, Debug, Decode, Encode)]
#[rasn(choice)]
enum PaPkAsRep {
    /// DH.
    #[rasn(tag(explicit(0)))]
    DhInfo(DhRepInfo),
    /// RSA key transport.
    #[rasn(tag(1))]
    EncKeyPack(OctetString),
}

/// `KDCDHKeyInfo`.
#[derive(AsnType, Clone, Debug, Decode, Encode)]
struct KdcDhKeyInfo {
    /// The KDC public value.
    #[rasn(tag(explicit(0)))]
    subject_public_key: BitString,
    /// The nonce.
    #[rasn(tag(explicit(1)))]
    nonce: u32,
    /// Expiration.
    #[rasn(tag(explicit(2)))]
    dh_key_expiration: Option<KerberosTime>,
}

/// `KRB5PrincipalName`.
#[derive(AsnType, Clone, Debug, Decode, Encode)]
struct Krb5PrincipalName {
    /// The realm.
    #[rasn(tag(explicit(0)))]
    realm: Realm,
    /// The name.
    #[rasn(tag(explicit(1)))]
    name: PrincipalName,
}

/// `PkinitSuppPubInfo`.
#[derive(AsnType, Clone, Debug, Decode, Encode)]
struct SuppPubInfo {
    /// The enctype.
    #[rasn(tag(explicit(0)))]
    enctype: i32,
    /// The AS-REQ.
    #[rasn(tag(explicit(1)))]
    as_req: OctetString,
    /// The PA-PK-AS-REP.
    #[rasn(tag(explicit(2)))]
    pk_as_rep: OctetString,
}

/// `OtherInfo`.
#[derive(AsnType, Clone, Debug, Decode, Encode)]
struct OtherInfo {
    /// The KDF.
    algorithm: AlgorithmIdentifier,
    /// The client.
    #[rasn(tag(explicit(0)))]
    party_u: OctetString,
    /// The TGS.
    #[rasn(tag(explicit(1)))]
    party_v: OctetString,
    /// The public information.
    #[rasn(tag(explicit(2)))]
    supp: OctetString,
}

/// The KDC.
pub(crate) struct Kdc {
    /// How it behaves.
    behaviour: Behaviour,
    /// Whether it offers a freshness token.
    freshness: bool,
    /// The `AuthPack`s it received.
    auth_packs: Vec<AuthPack>,
    /// Whether every received paChecksum matched the body.
    checksums_match: bool,
}

impl Kdc {
    /// A KDC that behaves as `behaviour`.
    pub(crate) const fn new(behaviour: Behaviour, freshness: bool) -> Self {
        Self {
            behaviour,
            freshness,
            auth_packs: Vec::new(),
            checksums_match: true,
        }
    }

    /// The `AuthPack`s received.
    pub(crate) fn auth_packs(&self) -> &[AuthPack] {
        &self.auth_packs
    }

    /// Whether every paChecksum and paChecksum2 matched its body.
    pub(crate) const fn checksums_match(&self) -> bool {
        self.checksums_match
    }

    /// Answer one AS-REQ.
    ///
    /// # Errors
    /// Returns the decoding and building errors.
    pub(crate) fn answer(&mut self, bytes: &[u8]) -> Result<Vec<u8>, TestError> {
        let request: AsReq = rasn_der::decode(bytes)?;
        let padata = request.0.padata.clone().unwrap_or_default();
        let Some(pk) = padata.iter().find(|entry| entry.r#type == PA_PK_AS_REQ) else {
            let mut offers = vec![
                offer(PA_PK_AS_REQ, Vec::new()),
                offer(PA_PKINIT_KX, Vec::new()),
            ];
            if self.freshness {
                offers.push(offer(PA_AS_FRESHNESS, FRESHNESS.to_vec()));
            }
            return krb_error(PREAUTH_REQUIRED, &offers);
        };
        let pa: PaPkAsReq = rasn_der::decode(&pk.value)?;
        let info = ContentInfo::from_der(&pa.signed_auth_pack)?;
        let signed: SignedData = info.content.decode_as()?;
        let content: DerOctetString = signed
            .encap_content_info
            .econtent
            .ok_or("no AuthPack")?
            .decode_as()?;
        let auth_pack: AuthPack = rasn_der::decode(content.as_bytes())?;
        let body = rasn_der::encode(&request.0.req_body)?;
        let sha1 = sha1::Sha1::digest(&body).to_vec();
        let sha256 = Sha256::digest(&body).to_vec();
        let authenticator = &auth_pack.pk_authenticator;
        if authenticator.pa_checksum.as_deref() != Some(sha1.as_slice())
            || authenticator
                .pa_checksum2
                .as_ref()
                .map(|sum| sum.checksum.to_vec())
                != Some(sha256)
        {
            self.checksums_match = false;
        }
        let nonce = authenticator.nonce;
        let spki_der = auth_pack
            .client_public_value
            .as_ref()
            .ok_or("no client value")?;
        self.auth_packs.push(auth_pack.clone());
        self.reply(&request, bytes, spki_der.as_bytes(), nonce)
    }

    /// The AS-REP for the `AuthPack`'s ECDH public value.
    fn reply(
        &self,
        request: &AsReq,
        request_der: &[u8],
        spki_der: &[u8],
        nonce: u32,
    ) -> Result<Vec<u8>, TestError> {
        let spki = spki::SubjectPublicKeyInfoOwned::from_der(spki_der)?;
        let client_point = p256::PublicKey::from_sec1_bytes(spki.subject_public_key.raw_bytes())?;
        let kdc_secret = p256::NonZeroScalar::from_repr([0x42_u8; 32].into())
            .into_option()
            .ok_or("scalar")?;
        let kdc_public = p256::PublicKey::from_secret_scalar(&kdc_secret);
        let shared = client_point.to_projective().mul(*kdc_secret).to_affine();
        let shared_bytes = shared.to_sec1_point(false);
        let z = shared_bytes.as_bytes().get(1..33).ok_or("x")?.to_vec();
        let key_info = KdcDhKeyInfo {
            subject_public_key: BitString::from_slice(kdc_public.to_sec1_point(false).as_bytes()),
            nonce: if self.behaviour == Behaviour::WrongNonce {
                nonce.wrapping_add(1)
            } else {
                nonce
            },
            dh_key_expiration: None,
        };
        let mut signed = self.sign(&rasn_der::encode(&key_info)?)?;
        if self.behaviour == Behaviour::MalformedCms {
            signed.truncate(64);
        }
        let rep = if self.behaviour == Behaviour::EncKeyPack {
            PaPkAsRep::EncKeyPack(signed.into())
        } else {
            PaPkAsRep::DhInfo(DhRepInfo {
                dh_signed_data: signed.into(),
                server_dh_nonce: None,
                kdf: Some(KdfAlgorithmId {
                    kdf_id: RasnOid::new(vec![1, 3, 6, 1, 5, 2, 3, 6, 2]).ok_or("oid")?,
                }),
            })
        };
        let rep_der = rasn_der::encode(&rep)?;
        let anonymous = request.0.req_body.cname.as_ref().is_some_and(|name| {
            name.string
                .iter()
                .any(|part| part.as_bytes() == b"ANONYMOUS")
        });
        let reply_key = kdf(&z, request, request_der, &rep_der, anonymous)?;
        let mut padata = vec![offer(PA_PK_AS_REP, rep_der)];
        let session = if anonymous {
            let kdc_key = EncryptionKey::new(18, vec![0x77_u8; 32]);
            let session = cf2((&kdc_key, b"PKINIT"), (&reply_key, b"KEYEXCHANGE"))?;
            let sealed_key = if self.behaviour == Behaviour::WrongKx {
                EncryptionKey::new(18, vec![0x78_u8; 32])
            } else {
                kdc_key
            };
            let kx = seal(
                &reply_key,
                KEY_USAGE_PA_PKINIT_KX,
                &rasn_der::encode(&KeyBlock {
                    r#type: 18,
                    value: sealed_key.value().to_vec().into(),
                })?,
            )?;
            if self.behaviour != Behaviour::MissingKx {
                padata.push(offer(PA_PKINIT_KX, rasn_der::encode(&kx)?));
            }
            session
        } else {
            EncryptionKey::new(18, vec![0x5a_u8; 32])
        };
        let naming = if anonymous {
            Naming::Anonymous
        } else {
            Naming::Client
        };
        as_rep(request, &reply_key, &session, padata, naming)
    }

    /// The DER `ContentInfo` of a `SignedData` of `content`.
    fn sign(&self, content: &[u8]) -> Result<Vec<u8>, TestError> {
        let (pem, key): (&[u8], &[u8]) = match self.behaviour {
            Behaviour::NoEku => (fixture!("kdc-noeku.pem"), fixture!("kdc-noeku.key")),
            Behaviour::WrongSan => (fixture!("kdc-wrongsan.pem"), fixture!("kdc-wrongsan.key")),
            Behaviour::Untrusted => (fixture!("kdc-untrusted.pem"), fixture!("kdc-untrusted.key")),
            Behaviour::Honest
            | Behaviour::EncKeyPack
            | Behaviour::WrongNonce
            | Behaviour::MalformedCms
            | Behaviour::MissingKx
            | Behaviour::WrongKx => (fixture!("kdc.pem"), fixture!("kdc.key")),
        };
        let (_, cert_der) = pem::decode_vec(pem)?;
        let certificate = Certificate::from_der(&cert_der)?;
        let (_, key_der) = pem::decode_vec(key)?;
        let secret = p256::SecretKey::from_sec1_der(&key_der)
            .or_else(|_sec1| p256::SecretKey::from_pkcs8_der(&key_der))?;
        let signing = SigningKey::from(&secret);
        let content_type = ObjectIdentifier::new("1.3.6.1.5.2.3.2")?;
        let digest = Sha256::digest(content).to_vec();
        let attributes = SetOfVec::try_from(vec![
            Attribute {
                oid: ObjectIdentifier::new("1.2.840.113549.1.9.3")?,
                values: SetOfVec::try_from(vec![DerAny::encode_from(&content_type)?])?,
            },
            Attribute {
                oid: ObjectIdentifier::new("1.2.840.113549.1.9.4")?,
                values: SetOfVec::try_from(vec![DerAny::encode_from(&DerOctetString::new(
                    digest,
                )?)?])?,
            },
        ])?;
        let signature: Signature = signing.sign(&attributes.to_der()?);
        let sha256 = spki::AlgorithmIdentifierOwned {
            oid: ObjectIdentifier::new("2.16.840.1.101.3.4.2.1")?,
            parameters: None,
        };
        let signer = SignerInfo {
            version: CmsVersion::V1,
            sid: SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
                issuer: certificate.tbs_certificate().issuer().clone(),
                serial_number: certificate.tbs_certificate().serial_number().clone(),
            }),
            digest_alg: sha256.clone(),
            signed_attrs: Some(attributes),
            signature_algorithm: spki::AlgorithmIdentifierOwned {
                oid: ObjectIdentifier::new("1.2.840.10045.4.3.2")?,
                parameters: None,
            },
            signature: DerOctetString::new(signature.to_der().as_bytes())?,
            unsigned_attrs: None,
        };
        let signed_data = SignedData {
            version: CmsVersion::V3,
            digest_algorithms: SetOfVec::try_from(vec![sha256])?,
            encap_content_info: EncapsulatedContentInfo {
                econtent_type: content_type,
                econtent: Some(DerAny::encode_from(&DerOctetString::new(content)?)?),
            },
            certificates: Some(CertificateSet(SetOfVec::try_from(vec![
                CertificateChoices::Certificate(certificate),
            ])?)),
            crls: None,
            signer_infos: SignerInfos(SetOfVec::try_from(vec![signer])?),
        };
        Ok(ContentInfo {
            content_type: ObjectIdentifier::new("1.2.840.113549.1.7.2")?,
            content: DerAny::encode_from(&signed_data)?,
        }
        .to_der()?)
    }
}

/// An AS-REP without preauthentication for the DER AS-REQ `bytes`, in `key`,
/// naming the client as `naming`.
///
/// # Errors
/// Returns the decoding and building errors.
pub(crate) fn plain_reply(
    bytes: &[u8],
    key: &EncryptionKey,
    naming: Naming,
) -> Result<Vec<u8>, TestError> {
    let request: AsReq = rasn_der::decode(bytes)?;
    let session = EncryptionKey::new(18, vec![0x5a_u8; 32]);
    as_rep(&request, key, &session, Vec::new(), naming)
}

/// A blocking transport to a fake KDC.
pub(crate) struct Transport(pub Kdc);

impl KdcTransport for Transport {
    fn send(&mut self, _realm: &str, request: &[u8]) -> Result<Vec<u8>, ClientError> {
        self.0
            .answer(request)
            .map_err(|error| ClientError::Transport(error.to_string()))
    }
}

/// The DER `KRB5PrincipalName` of `realm` and `name`.
fn principal(realm: &str, name: &PrincipalName) -> Result<OctetString, TestError> {
    Ok(rasn_der::encode(&Krb5PrincipalName {
        realm: KerberosString::try_from(realm.to_owned())?,
        name: name.clone(),
    })?
    .into())
}

/// The RFC 8636 SHA-256 KDF for an AES256 reply key.
fn kdf(
    z: &[u8],
    request: &AsReq,
    request_der: &[u8],
    rep_der: &[u8],
    anonymous: bool,
) -> Result<EncryptionKey, TestError> {
    let body = &request.0.req_body;
    let client_realm = if anonymous {
        "WELLKNOWN:ANONYMOUS".to_owned()
    } else {
        String::from_utf8(body.realm.as_bytes().to_vec())?
    };
    let realm = String::from_utf8(body.realm.as_bytes().to_vec())?;
    let info = OtherInfo {
        algorithm: AlgorithmIdentifier {
            algorithm: RasnOid::new(vec![1, 3, 6, 1, 5, 2, 3, 6, 2]).ok_or("oid")?,
            parameters: None,
        },
        party_u: principal(&client_realm, body.cname.as_ref().ok_or("cname")?)?,
        party_v: principal(&realm, body.sname.as_ref().ok_or("sname")?)?,
        supp: rasn_der::encode(&SuppPubInfo {
            enctype: 18,
            as_req: request_der.to_vec().into(),
            pk_as_rep: rep_der.to_vec().into(),
        })?
        .into(),
    };
    let encoded = rasn_der::encode(&info)?;
    let block = Sha256::new()
        .chain_update(1_u32.to_be_bytes())
        .chain_update(z)
        .chain_update(&encoded)
        .finalize();
    Ok(EncryptionKey::new(18, block.to_vec()))
}

/// `KRB-FX-CF2` of two AES256 keys.
fn cf2(
    (first, first_pepper): (&EncryptionKey, &[u8]),
    (second, second_pepper): (&EncryptionKey, &[u8]),
) -> Result<EncryptionKey, TestError> {
    let etype = KerberosEtype::from_etype_id(18).ok_or("etype")?;
    let combined = prf::krb_fx_cf2(
        &prf::CfInput::new(prf::Key::new(etype, first.value()), first_pepper),
        &prf::CfInput::new(prf::Key::new(etype, second.value()), second_pepper),
    )?;
    Ok(EncryptionKey::new(18, combined.to_vec()))
}

/// Encrypt in AES256 with a fixed confounder.
fn seal(key: &EncryptionKey, usage: u32, plain: &[u8]) -> Result<EncryptedData, TestError> {
    let etype = KerberosEtype::from_etype_id(18).ok_or("etype")?;
    let cipher =
        etype.encrypt_message_with_confounder(key.value(), plain, usage, &[0x11_u8; 16])?;
    Ok(EncryptedData {
        etype: 18,
        kvno: None,
        cipher: cipher.into(),
    })
}

/// One PA-DATA entry.
fn offer(kind: i32, value: Vec<u8>) -> PaData {
    PaData {
        r#type: kind,
        value: value.into(),
    }
}

/// A Kerberos time.
fn kerberos_time(seconds: u64) -> Result<KerberosTime, TestError> {
    let time = UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds))
        .ok_or("time")?;
    Ok(KerberosTime(
        chrono::DateTime::<chrono::Utc>::from(time).into(),
    ))
}

/// The TGS name.
fn tgs() -> Result<PrincipalName, TestError> {
    Ok(PrincipalName {
        r#type: 2,
        string: vec![
            KerberosString::try_from("krbtgt".to_owned())?,
            KerberosString::try_from(REALM.to_owned())?,
        ],
    })
}

/// A KRB-ERROR with `code` and METHOD-DATA `offers`.
fn krb_error(code: i32, offers: &[PaData]) -> Result<Vec<u8>, TestError> {
    Ok(rasn_der::encode(&KrbError {
        pvno: Integer::from(5_i32),
        msg_type: Integer::from(30_i32),
        ctime: None,
        cusec: None,
        stime: kerberos_time(start())?,
        susec: Integer::from(0_i32),
        error_code: code,
        crealm: None,
        cname: None,
        realm: KerberosString::try_from(REALM.to_owned())?,
        sname: tgs()?,
        e_text: None,
        e_data: Some(rasn_der::encode(&offers.to_vec())?.into()),
    })?)
}

/// The client name an AS-REP carries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Naming {
    /// The request's client.
    Client,
    /// `WELLKNOWN/ANONYMOUS@WELLKNOWN:ANONYMOUS`.
    Anonymous,
    /// `WELLKNOWN/ANONYMOUS` in the request's realm.
    RealmExposed,
}

/// The AS-REP for `request` in `reply_key` with `session` and `padata`.
fn as_rep(
    request: &AsReq,
    reply_key: &EncryptionKey,
    session: &EncryptionKey,
    padata: Vec<PaData>,
    naming: Naming,
) -> Result<Vec<u8>, TestError> {
    let body = &request.0.req_body;
    let sname = body.sname.clone().ok_or("sname")?;
    let anonymous_name = PrincipalName {
        r#type: 11,
        string: vec![
            KerberosString::try_from("WELLKNOWN".to_owned())?,
            KerberosString::try_from("ANONYMOUS".to_owned())?,
        ],
    };
    let (crealm, cname) = match naming {
        Naming::Client => (body.realm.clone(), body.cname.clone().ok_or("cname")?),
        Naming::Anonymous => (
            KerberosString::try_from("WELLKNOWN:ANONYMOUS".to_owned())?,
            anonymous_name,
        ),
        Naming::RealmExposed => (body.realm.clone(), anonymous_name),
    };
    let part = rasn_kerberos::EncAsRepPart(rasn_kerberos::EncKdcRepPart {
        key: rasn_kerberos::EncryptionKey {
            r#type: 18,
            value: session.value().to_vec().into(),
        },
        last_req: vec![rasn_kerberos::LastReqValue {
            r#type: 0,
            value: kerberos_time(start())?,
        }],
        nonce: body.nonce,
        key_expiration: None,
        flags: rasn_kerberos::TicketFlags(rasn_kerberos::KerberosFlags::from_slice(&[0_u8; 4])),
        auth_time: kerberos_time(start())?,
        start_time: Some(kerberos_time(start())?),
        end_time: kerberos_time(start().saturating_add(3600))?,
        renew_till: None,
        srealm: body.realm.clone(),
        sname: sname.clone(),
        caddr: None,
        encrypted_pa_data: None,
    });
    let enc = seal(reply_key, 3, &rasn_der::encode(&part)?)?;
    Ok(rasn_der::encode(&rasn_kerberos::AsRep(
        rasn_kerberos::KdcRep {
            pvno: Integer::from(5_i32),
            msg_type: Integer::from(11_i32),
            padata: Some(padata),
            crealm,
            cname,
            ticket: rasn_kerberos::Ticket {
                tkt_vno: Integer::from(5_i32),
                realm: body.realm.clone(),
                sname,
                enc_part: EncryptedData {
                    etype: 18,
                    kvno: Some(2),
                    cipher: vec![0xde_u8, 0xad, 0xbe, 0xef].into(),
                },
            },
            enc_part: enc,
        },
    ))?)
}
