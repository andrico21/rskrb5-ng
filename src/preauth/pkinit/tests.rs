//! Known-answer and negative tests of the PKINIT operations.
//!
//! Vectors: RFC 8636 appendix A as MIT 1.22.2 `pkinit_kdf_test.c:41-71`
//! carries them; OpenSSL 3.5.5 key agreements and CMS from
//! `tests/pkinit/fixtures/generate.sh` (independent of this crate).

use core::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use der::Decode as _;
use p256::elliptic_curve::PrimeField as _;
use x509_cert::{Certificate, crl::CertificateList};

use super::{
    chain::{self, Parsed},
    cms, dh, kdf, keys,
};
use crate::{
    client::principal::Principal,
    error::Pkinit as Error,
    keytab::EncryptionKey,
    preauth::pkinit::{CertificatePolicy, EkuChecking, KdcTrust},
};

/// A boxed test failure.
type TestError = Box<dyn core::error::Error>;

/// A fixture file.
macro_rules! fixture {
    ($name:literal) => {
        include_bytes!(concat!("../../../tests/pkinit/fixtures/", $name))
    };
}

/// The time of the checks: 2026-11-21, inside every fixture's validity but
/// the expired one's.
fn now() -> SystemTime {
    UNIX_EPOCH
        .checked_add(Duration::from_secs(1_795_219_200))
        .unwrap_or(UNIX_EPOCH)
}

/// The DER certificate of a PEM fixture.
fn certificate(pem: &[u8]) -> Result<Certificate, TestError> {
    let der = keys::pem_certificates(pem)?
        .into_iter()
        .next()
        .ok_or("no certificate")?;
    Ok(Certificate::from_der(&der)?)
}

/// Parsed anchors of PEM fixtures.
fn parsed(pems: &[&[u8]]) -> Result<Vec<Parsed>, TestError> {
    let mut out = Vec::new();
    for pem in pems {
        for der in keys::pem_certificates(pem)? {
            out.push(chain::parse(&der)?);
        }
    }
    Ok(out)
}

/// Bytes of a hex fixture.
fn hex(text: &[u8]) -> Result<Vec<u8>, TestError> {
    let text = core::str::from_utf8(text)?.trim();
    (0..text.len())
        .step_by(2)
        .map(|start| {
            let pair = text.get(start..start.saturating_add(2)).ok_or("odd hex")?;
            Ok(u8::from_str_radix(pair, 16)?)
        })
        .collect()
}

#[test]
fn rfc8636_kdf_vectors() -> Result<(), TestError> {
    // Given MIT's RFC 8636 inputs: a 256-byte zero secret, lha@SU.SE and
    // krbtgt/SU.SE@SU.SE (NT-PRINCIPAL), 10 bytes of 0xaa and 9 of 0xbb.
    let secret = [0_u8; 256];
    let client = Principal::new("SU.SE".to_owned(), 1, vec!["lha".to_owned()]);
    let server = Principal::new(
        "SU.SE".to_owned(),
        1,
        vec!["krbtgt".to_owned(), "SU.SE".to_owned()],
    );
    let vectors: [(kdf::Kdf, i32, &str); 3] = [
        (
            kdf::Kdf::Sha1,
            18,
            "e6ab38c9413e035bb079201ed0b6b73d8d49a814a737c04ee6649614206f73ad",
        ),
        (
            kdf::Kdf::Sha256,
            18,
            "77ef4e48c420ae3fec75109d7981697eed5d295c90c62564f7bfd101fa9bc1d5",
        ),
        (
            kdf::Kdf::Sha512,
            16,
            "d3c78a79d65213efe9a826f75dfb01f72362fb16fb01dad6",
        ),
    ];
    for (algorithm, etype, expected) in vectors {
        // When the KDF runs, then it yields the published key.
        let key = kdf::derive(
            algorithm,
            &kdf::Inputs {
                secret: &secret,
                etype,
                client: &client,
                server: &server,
                as_req: &[0xaa; 10],
                pk_as_rep: &[0xbb; 9],
            },
        )?;
        assert_eq!(
            key.value().as_ref(),
            hex(expected.as_bytes())?.as_slice(),
            "{algorithm:?}"
        );
    }
    Ok(())
}

#[test]
fn octetstring2key_concatenates_counted_sha1_blocks() -> Result<(), TestError> {
    // RFC 4556 section 3.2.3.1: SHA-1(0x00 || Z) || SHA-1(0x01 || Z) ...
    use sha1::{Digest as _, Sha1};
    let secret = b"pkinit shared secret";
    let mut expected = Sha1::new()
        .chain_update([0_u8])
        .chain_update(secret)
        .finalize()
        .to_vec();
    expected.extend_from_slice(
        &Sha1::new()
            .chain_update([1_u8])
            .chain_update(secret)
            .finalize(),
    );
    expected.truncate(32);
    let key = kdf::octetstring2key(secret, 18)?;
    assert_eq!(key.value().as_ref(), expected.as_slice());
    Ok(())
}

#[test]
fn modp_2048_agreement_matches_openssl() -> Result<(), TestError> {
    // Given OpenSSL's modp_2048 private exponent of side a and public value of side b.
    let private = hex(fixture!("dh-a.priv.hex"))?;
    let mut padded = vec![0_u8; 256];
    let start = 256_usize.checked_sub(private.len()).ok_or("long key")?;
    padded
        .get_mut(start..)
        .ok_or("pad")?
        .copy_from_slice(&private);
    let secret = crypto_bigint::U2048::from_be_slice(&padded);
    let public = hex(fixture!("dh-b.pub.hex"))?;
    let integer = der::asn1::Uint::new(&public)?;
    let encoded = der::Encode::to_der(&integer)?;
    // When this client agrees, then the secret is OpenSSL's, padded to 256 bytes.
    let shared = dh::agree(
        &dh::Ephemeral::Modp2048(Box::new(zeroize::Zeroizing::new(secret))),
        &encoded,
    )?;
    assert_eq!(shared.as_slice(), fixture!("dh-shared.bin").as_slice());
    Ok(())
}

#[test]
fn p256_agreement_matches_openssl() -> Result<(), TestError> {
    let private = hex(fixture!("ec-a.priv.hex"))?;
    let repr = p256::FieldBytes::try_from(private.as_slice())?;
    let scalar = Option::<p256::Scalar>::from(p256::Scalar::from_repr(repr)).ok_or("scalar")?;
    let shared = dh::agree(
        &dh::Ephemeral::P256(zeroize::Zeroizing::new(scalar)),
        &hex(fixture!("ec-b.pub.hex"))?,
    )?;
    assert_eq!(shared.as_slice(), fixture!("ec-shared.bin").as_slice());
    Ok(())
}

#[test]
fn invalid_public_values_are_refused() -> Result<(), TestError> {
    let (ephemeral, _) = dh::generate(crate::preauth::pkinit::DhGroup::Modp2048)?;
    let p_minus_two = {
        let mut bytes = super::primes::MODP_2048.to_vec();
        if let Some(last) = bytes.last_mut() {
            *last = last.wrapping_sub(2);
        }
        bytes
    };
    let encode = |bytes: &[u8]| -> Result<Vec<u8>, TestError> {
        Ok(der::Encode::to_der(&der::asn1::Uint::new(bytes)?)?)
    };
    // 1, p-1 and p-2 (outside the prime-order subgroup), and a non-INTEGER.
    let mut p_minus_one = super::primes::MODP_2048.to_vec();
    if let Some(last) = p_minus_one.last_mut() {
        *last = last.wrapping_sub(1);
    }
    for value in [
        encode(&[1])?,
        encode(&p_minus_one)?,
        encode(&p_minus_two)?,
        vec![0x04, 0x01, 0x00],
    ] {
        assert!(matches!(
            dh::agree(&ephemeral, &value),
            Err(Error::PublicValue)
        ));
    }
    let (curve, _) = dh::generate(crate::preauth::pkinit::DhGroup::P256)?;
    let mut off_curve = hex(fixture!("ec-b.pub.hex"))?;
    if let Some(last) = off_curve.last_mut() {
        *last ^= 1;
    }
    for value in [vec![0x00], off_curve] {
        assert!(matches!(dh::agree(&curve, &value), Err(Error::PublicValue)));
    }
    Ok(())
}

#[test]
fn openssl_cms_signed_data_verifies() -> Result<(), TestError> {
    // Given OpenSSL's `cms -sign` of id-pkinit-DHKeyData by the KDC key.
    let trust = KdcTrust::new(keys::pem_certificates(fixture!("ca-ec.pem"))?);
    let policy = CertificatePolicy::default();
    let context = cms::Context {
        trust: &trust,
        policy: &policy,
        now: now(),
    };
    // When it is verified, then the content and the signer come back.
    let verified = cms::verify(fixture!("cms-dhkeydata.der"), cms::DH_KEY_DATA, &context)?;
    assert_eq!(
        verified.content.as_slice(),
        fixture!("dhkeydata.der").as_slice()
    );
    chain::kdc_identity(&verified.signer, "TEST.RSKRB5", &policy)?;
    // And a tampered or truncated message, another content type or an
    // untrusted anchor fail.
    let original = fixture!("cms-dhkeydata.der");
    let mut tampered = original.to_vec();
    let position = tampered
        .windows(5)
        .position(|window| window == b"fixtu")
        .ok_or("content")?;
    if let Some(byte) = tampered.get_mut(position) {
        *byte ^= 1;
    }
    assert!(matches!(
        cms::verify(&tampered, cms::DH_KEY_DATA, &context),
        Err(Error::Signature { .. })
    ));
    let truncated = original.get(..original.len() / 2).ok_or("half")?;
    assert!(matches!(
        cms::verify(truncated, cms::DH_KEY_DATA, &context),
        Err(Error::Malformed { .. })
    ));
    assert!(matches!(
        cms::verify(original, cms::AUTH_DATA, &context),
        Err(Error::Malformed { .. })
    ));
    let other = KdcTrust::new(keys::pem_certificates(fixture!("ca-other.pem"))?);
    let untrusted = cms::Context {
        trust: &other,
        policy: &policy,
        now: now(),
    };
    assert!(matches!(
        cms::verify(original, cms::DH_KEY_DATA, &untrusted),
        Err(Error::Certificate { .. })
    ));
    Ok(())
}

/// Validate the KDC certificate `pem` against `anchors` and `crls`.
fn validate(
    pem: &[u8],
    anchors: &[&[u8]],
    crls: &[CertificateList],
    require_crl: bool,
) -> Result<(), Error> {
    let leaf = certificate(pem).map_err(|_detail| Error::Malformed {
        structure: "fixture",
        reason: "unreadable",
    })?;
    let anchors = parsed(anchors).map_err(|_detail| Error::Malformed {
        structure: "fixture",
        reason: "unreadable",
    })?;
    chain::validate(&leaf, (&[], &anchors, crls), require_crl, now())
}

#[test]
fn chain_validation_rules() -> Result<(), TestError> {
    let crl = CertificateList::from_der(&der::pem::decode_vec(fixture!("crl-ec.pem"))?.1)?;
    let ca: &[u8] = fixture!("ca-ec.pem");
    // Valid chains: EC under the EC root, EC under the RSA-3072 root.
    validate(fixture!("kdc.pem"), &[ca], &[], false)?;
    validate(
        fixture!("kdc-rsachain.pem"),
        &[fixture!("ca-rsa.pem")],
        &[],
        false,
    )?;
    validate(fixture!("kdc.pem"), &[ca], &[crl.clone()], true)?;
    // Expired, untrusted, revoked, and unknown revocation status.
    assert!(matches!(
        validate(fixture!("kdc-expired.pem"), &[ca], &[], false),
        Err(Error::Certificate { .. })
    ));
    assert!(matches!(
        validate(fixture!("kdc-untrusted.pem"), &[ca], &[], false),
        Err(Error::Certificate { .. })
    ));
    assert!(matches!(
        validate(fixture!("kdc-revoked.pem"), &[ca], &[crl], false),
        Err(Error::Revoked)
    ));
    assert!(matches!(
        validate(fixture!("kdc.pem"), &[ca], &[], true),
        Err(Error::RevocationUnknown)
    ));
    Ok(())
}

#[test]
fn kdc_identity_rules() -> Result<(), TestError> {
    let realm = "TEST.RSKRB5";
    let strict = CertificatePolicy::default();
    // QA scenario: no KDC EKU under pkinit_eku_checking = kpKDC is refused,
    // also though the SAN names the TGS.
    let no_eku = certificate(fixture!("kdc-noeku.pem"))?;
    assert!(matches!(
        chain::kdc_identity(&no_eku, realm, &strict),
        Err(Error::KeyPurpose)
    ));
    chain::kdc_identity(
        &no_eku,
        realm,
        &strict.clone().with_eku_checking(EkuChecking::None),
    )?;
    // serverAuth with a dNSName needs both kpServerAuth and the hostname.
    let server = certificate(fixture!("kdc-serverauth.pem"))?;
    assert!(matches!(
        chain::kdc_identity(&server, realm, &strict),
        Err(Error::KdcName { .. })
    ));
    let hosts = strict
        .clone()
        .with_kdc_hostnames(vec!["KDC.test.rskrb5".to_owned()]);
    assert!(matches!(
        chain::kdc_identity(&server, realm, &hosts),
        Err(Error::KeyPurpose)
    ));
    chain::kdc_identity(
        &server,
        realm,
        &hosts.with_eku_checking(EkuChecking::KpServerAuth),
    )?;
    // Another realm's TGS.
    assert!(matches!(
        chain::kdc_identity(&certificate(fixture!("kdc-wrongsan.pem"))?, realm, &strict),
        Err(Error::KdcName { .. })
    ));
    Ok(())
}

#[test]
fn software_identities_and_outgoing_requests() -> Result<(), TestError> {
    // SEC1 and PKCS#8 keys load; a key that is not the certificate's is refused.
    let certificates = keys::pem_certificates(fixture!("client.pem"))?;
    for key in [
        fixture!("client.key").as_slice(),
        fixture!("client-pkcs8.key"),
    ] {
        drop(keys::software_signer(key, certificates.first())?);
    }
    let p384 = keys::pem_certificates(fixture!("client-p384.pem"))?;
    drop(keys::software_signer(
        fixture!("client-p384-pkcs8.key"),
        p384.first(),
    )?);
    assert!(matches!(
        keys::software_signer(fixture!("kdc.key"), certificates.first()),
        Err(Error::Identity { .. })
    ));
    // Only a DER PA-PK-AS-REQ is admitted outgoing.
    assert!(matches!(
        super::outgoing(&[0x47; 32]),
        Err(Error::Malformed { .. })
    ));
    Ok(())
}

#[test]
fn anonymous_key_exchange_must_match_the_session_key() -> Result<(), TestError> {
    // A PA-PKINIT-KX that does not decrypt, or names another key, fails.
    let reply = EncryptionKey::new(18, vec![0x31; 32]);
    let session = EncryptionKey::new(18, vec![0x32; 32]);
    assert!(matches!(
        super::verify_anonymous(&[0x30, 0x00], &reply, &session),
        Err(Error::Anonymous { .. })
    ));
    Ok(())
}
