//! The operations of the `pkinit` leaf: request construction, reply
//! verification and key derivation over the admitted crates.

use alloc::sync::Arc;

use crypto_bigint::ctutils::CtEq as _;
use rasn::{
    der as rasn_der,
    types::{Any, ObjectIdentifier as RasnOid, OctetString},
};
use rasn_kerberos::{EncryptedData, EncryptionKey as KeyBlock, KerberosTime};
use sha1::{Digest as _, Sha1};
use sha2::Sha256;
use zeroize::Zeroizing;

use super::{
    CertificatePolicy, DhGroup, Identity, KEY_USAGE_PA_PKINIT_KX, KdcTrust, MAX_MESSAGE_BYTES,
    Signer, asn1, chain, cms, dh,
    exchange::{ReplyInput, RequestInput},
    kdf, keys,
};
use crate::{
    crypto::{KerberosEtype, prf, selection},
    error::{Crypto, Pkinit as Error, Policy, RejectedFeature, RejectionReason},
    keytab::EncryptionKey,
};

/// The compiled `pkinit_cert_match` rules.
pub(super) type Rules = super::matching::CertificateRules;

/// The index of the one candidate (DER) that `rules` select.
///
/// # Errors
/// Returns the errors of [`Rules::select`](super::matching::CertificateRules::select).
pub(super) fn select_rules(rules: &Rules, certificates: &[&[u8]]) -> Result<usize, Error> {
    rules.select(certificates)
}

/// The DER certificates of a PEM document.
///
/// # Errors
/// Returns [`Error::Malformed`] and [`Error::TooLarge`].
pub(super) fn pem_certificates(text: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
    keys::pem_certificates(text)
}

/// The DER CRLs of a PEM document.
///
/// # Errors
/// Returns [`Error::Malformed`] and [`Error::TooLarge`].
pub(super) fn pem_crls(text: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
    keys::pem_crls(text)
}

/// The software signer of a PEM EC key, checked against `certificate`.
///
/// # Errors
/// Returns [`Error::Identity`].
pub(super) fn software_signer(
    key: &[u8],
    certificate: Option<&Vec<u8>>,
) -> Result<Arc<dyn Signer>, Error> {
    keys::software_signer(key, certificate)
}

/// The DER PA-PK-AS-REQ for `input` and the ephemeral key it proposes.
///
/// # Errors
/// Returns the key-agreement, encoding and signing errors.
pub(super) fn request(
    identity: Option<&Identity>,
    group: DhGroup,
    input: &RequestInput<'_>,
) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), Error> {
    let (ephemeral, spki) = dh::generate(group)?;
    let (whole, micros) = input.time;
    let authenticator = asn1::PkAuthenticator {
        cusec: micros.into(),
        ctime: KerberosTime(chrono::DateTime::<chrono::Utc>::from(whole).into()),
        nonce: input.nonce,
        pa_checksum: Some(OctetString::from(Sha1::digest(input.body).to_vec())),
        freshness_token: input
            .freshness
            .map(|token| OctetString::from(token.to_vec())),
        pa_checksum2: Some(asn1::PaChecksum2 {
            checksum: OctetString::from(Sha256::digest(input.body).to_vec()),
            algorithm_identifier: asn1::AlgorithmIdentifier {
                algorithm: asn1::oid(asn1::SHA256),
                parameters: None,
            },
        }),
    };
    let cms_types = keys::SIGNATURES
        .iter()
        .filter_map(|(text, _, _)| {
            let arcs: Vec<u32> = text
                .split('.')
                .map(str::parse)
                .collect::<Result<_, _>>()
                .ok()?;
            Some(asn1::AlgorithmIdentifier {
                algorithm: RasnOid::new(arcs)?,
                parameters: None,
            })
        })
        .collect();
    let auth_pack = asn1::AuthPack {
        pk_authenticator: authenticator,
        client_public_value: Some(Any::new(spki)),
        supported_cms_types: Some(cms_types),
        client_dh_nonce: None,
        supported_kdfs: Some(
            kdf::Kdf::OFFERED
                .iter()
                .map(|kdf| asn1::KdfAlgorithmId {
                    kdf_id: asn1::oid(kdf.arcs()),
                })
                .collect(),
        ),
    };
    let encoded = kdf::encode("AuthPack", &auth_pack)?;
    let signed = cms::sign(cms::AUTH_DATA, &encoded, identity)?;
    let value = kdf::encode(
        "PA-PK-AS-REQ",
        &asn1::PaPkAsReq {
            signed_auth_pack: signed.into(),
            trusted_certifiers: None,
            kdc_pk_id: None,
        },
    )?;
    Ok((value, ephemeral))
}

/// Decode an outgoing PA-PK-AS-REQ within [`MAX_MESSAGE_BYTES`].
///
/// # Errors
/// Returns [`Error::TooLarge`] and [`Error::Malformed`].
pub(super) fn outgoing(value: &[u8]) -> Result<(), Error> {
    if value.len() > MAX_MESSAGE_BYTES {
        return Err(Error::TooLarge {
            structure: "PA-PK-AS-REQ",
            limit: MAX_MESSAGE_BYTES,
        });
    }
    let _request: asn1::PaPkAsReq =
        rasn_der::decode(value).map_err(|_detail| Error::Malformed {
            structure: "PA-PK-AS-REQ",
            reason: "not a DER PA-PK-AS-REQ",
        })?;
    Ok(())
}

/// The reply key of the KDC's PA-PK-AS-REP.
///
/// # Errors
/// Returns the CMS, certificate, identity, key-agreement and KDF errors.
pub(super) fn reply(
    (group, ephemeral): (DhGroup, &[u8]),
    nonce: u32,
    (trust, policy): (&KdcTrust, &CertificatePolicy),
    input: &ReplyInput<'_>,
) -> Result<EncryptionKey, Error> {
    if input.pk_as_rep.len() > MAX_MESSAGE_BYTES {
        return Err(Error::TooLarge {
            structure: "PA-PK-AS-REP",
            limit: MAX_MESSAGE_BYTES,
        });
    }
    let decoded: asn1::PaPkAsRep =
        rasn_der::decode(input.pk_as_rep).map_err(|_detail| Error::Malformed {
            structure: "PA-PK-AS-REP",
            reason: "not a DER PA-PK-AS-REP",
        })?;
    let info = match decoded {
        asn1::PaPkAsRep::DhInfo(info) => info,
        asn1::PaPkAsRep::EncKeyPack(_) => {
            return Err(Error::Policy(Policy::RejectedFeature {
                feature: RejectedFeature::RsaPkinit,
                reason: RejectionReason::RemovedAndInsecure,
            }));
        }
    };
    if info.server_dh_nonce.is_some() {
        return Err(Error::Malformed {
            structure: "DHRepInfo",
            reason: "a server DH nonce answers no client nonce",
        });
    }
    let verified = cms::verify(
        &info.dh_signed_data,
        cms::DH_KEY_DATA,
        &cms::Context {
            trust,
            policy,
            now: input.now,
        },
    )?;
    chain::kdc_identity(&verified.signer, &input.server.realm, policy)?;
    let key_info: asn1::KdcDhKeyInfo =
        rasn_der::decode(&verified.content).map_err(|_detail| Error::Malformed {
            structure: "KDCDHKeyInfo",
            reason: "not a DER KDCDHKeyInfo",
        })?;
    if key_info.nonce != nonce {
        return Err(Error::NonceMismatch {
            expected: nonce,
            actual: key_info.nonce,
        });
    }
    let public = key_info.subject_public_key.as_raw_slice();
    let secret = dh::agree(group, ephemeral, public)?;
    let inputs = kdf::Inputs {
        secret: &secret,
        etype: input.etype,
        client: input.client,
        server: input.server,
        as_req: input.request,
        pk_as_rep: input.pk_as_rep,
    };
    match info.kdf {
        None => kdf::octetstring2key(&secret, input.etype),
        Some(id) => {
            let arcs: &[u32] = &id.kdf_id;
            let chosen = kdf::Kdf::from_arcs(arcs).ok_or_else(|| Error::UnsupportedAlgorithm {
                algorithm: id.kdf_id.to_string(),
            })?;
            kdf::derive(chosen, &inputs)
        }
    }
}

/// RFC 6112 section 4.1: the session key equals
/// `KRB-FX-CF2(kdc_key, reply_key, "PKINIT", "KEYEXCHANGE")`, compared in
/// constant time.
///
/// # Errors
/// Returns [`Error::Anonymous`].
pub(super) fn verify_anonymous(
    kx: &[u8],
    reply_key: &EncryptionKey,
    session_key: &EncryptionKey,
) -> Result<(), Error> {
    let invalid = |reason| Error::Anonymous { reason };
    let encrypted: EncryptedData =
        rasn_der::decode(kx).map_err(|_detail| invalid("PA-PKINIT-KX is not EncryptedData"))?;
    let kind = enctype(reply_key.etype())?;
    if encrypted.etype != reply_key.etype() {
        return Err(invalid("PA-PKINIT-KX is not in the reply key's enctype"));
    }
    let plain = Zeroizing::new(
        kind.decrypt_message(reply_key.value(), &encrypted.cipher, KEY_USAGE_PA_PKINIT_KX)
            .map_err(|_detail| invalid("PA-PKINIT-KX does not decrypt"))?,
    );
    let kdc: KeyBlock = rasn_der::decode(&plain)
        .map_err(|_detail| invalid("PA-PKINIT-KX holds no EncryptionKey"))?;
    let kdc_value = Zeroizing::new(kdc.value.to_vec());
    let expected = prf::krb_fx_cf2(
        &prf::CfInput::new(prf::Key::new(enctype(kdc.r#type)?, &kdc_value), b"PKINIT"),
        &prf::CfInput::new(prf::Key::new(kind, reply_key.value()), b"KEYEXCHANGE"),
    )?;
    let same = kdc.r#type == session_key.etype()
        && expected.len() == session_key.value().len()
        && expected.as_slice().ct_eq(session_key.value()).to_bool();
    if same {
        Ok(())
    } else {
        Err(invalid("the session key is not the PKINIT key exchange"))
    }
}

/// The implemented enctype `id`.
///
/// # Errors
/// Returns [`Error::Crypto`].
fn enctype(id: i32) -> Result<KerberosEtype, Error> {
    selection::enctype(id)
        .map_err(Crypto::from)?
        .ok_or_else(|| Error::UnsupportedAlgorithm {
            algorithm: format!("enctype {id}"),
        })
}
