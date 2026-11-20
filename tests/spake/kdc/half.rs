//! The KDC half of RFC 9588 for edwards25519 and AES256 reply keys.

use core::ops::{Add as _, Mul as _, Sub as _};

use curve25519_dalek::{EdwardsPoint, Scalar, edwards::CompressedEdwardsY};
use rasn::{AsnType, Decode, Decoder as _, Encode, Encoder as _, der, types::OctetString};
use rasn_kerberos::{EncryptedData, PaData};
use rskrb5_ng::{
    crypto::{KerberosEtype, prf},
    keytab::EncryptionKey,
    preauth::spake::{KEY_USAGE_SPAKE, Message, PA_SPAKE},
};
use sha2::{Digest, Sha256};

use super::{
    Fault, Kdc, PA_ENC_TIMESTAMP, PREAUTH_FAILED, TestError, as_rep, cookie_offer, krb_error, offer,
};

/// `KDC_ERR_MORE_PREAUTH_DATA_REQUIRED`.
const MORE_PREAUTH_DATA_REQUIRED: i32 = 91;
/// edwards25519 `M` (RFC 9588 section 12.2.2.1).
const EDWARDS25519_M: &str = "d048032c6ea0b6d697ddc2e86bda85a33adac920f1bf18e1b0c6d166a5cecdaf";
/// edwards25519 `N`.
const EDWARDS25519_N: &str = "d3bfb518f44f3430f29d0c92af503865a1ed3281dc69b35dd868ba85f886c4ab";
/// `r`, where the KDC's private scalar is `x = 8r`.
const PRIVATE: [u8; 32] = [7_u8; 32];
/// DER `SPAKESecondFactor { SF-NONE }`.
const FACTOR_NONE: [u8; 7] = [0x30, 0x05, 0xa0, 0x03, 0x02, 0x01, 0x01];

/// `SPAKESecondFactor` as the KDC encodes it.
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq)]
struct SecondFactor {
    /// Factor type.
    #[rasn(tag(explicit(0)))]
    kind: i32,
    /// Factor data.
    #[rasn(tag(explicit(1)))]
    data: Option<OctetString>,
}

/// `SPAKEChallenge` as the KDC encodes it.
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq)]
struct Challenge {
    /// Group.
    #[rasn(tag(explicit(0)))]
    group: i32,
    /// The KDC's element `T`.
    #[rasn(tag(explicit(1)))]
    pubkey: OctetString,
    /// Offered factors.
    #[rasn(tag(explicit(2)))]
    factors: Vec<SecondFactor>,
}

/// The KDC's PA-SPAKE messages.
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq)]
#[rasn(choice)]
enum KdcMessage {
    /// `challenge`.
    #[rasn(tag(explicit(1)))]
    Challenge(Challenge),
    /// `encdata`.
    #[rasn(tag(explicit(3)))]
    Encdata(EncryptedData),
}

/// SHA-256 over the concatenation of `parts`.
fn sha256(parts: &[&[u8]]) -> Vec<u8> {
    parts
        .iter()
        .fold(Sha256::new(), Digest::chain_update)
        .finalize()
        .to_vec()
}

/// An edwards25519 constant.
///
/// # Errors
/// Returns an error for an invalid constant.
fn constant(text: &str) -> Result<EdwardsPoint, TestError> {
    let bytes = hex::decode(text)?;
    Ok(CompressedEdwardsY::from_slice(&bytes)?
        .decompress()
        .ok_or("constant")?)
}

/// The multiplier input and `w`.
///
/// # Errors
/// Returns the PRF errors.
fn multiplier(key: &EncryptionKey) -> Result<(Vec<u8>, Scalar), TestError> {
    let etype = KerberosEtype::from_etype_id(18).ok_or("aes256")?;
    let mut pepper = b"SPAKEsecret".to_vec();
    pepper.extend_from_slice(&1_i32.to_be_bytes());
    let wbytes = prf::fast_prf_plus(&prf::Key::new(etype, key.value()), &pepper, 32)?;
    let digits: [u8; 32] = wbytes.as_slice().try_into()?;
    Ok((wbytes.to_vec(), Scalar::from_bytes_mod_order(digits)))
}

/// `K'[number]` for AES256 in group 1 over `w`, `K`, `thash` and the body (RFC 9588 section 7).
///
/// # Errors
/// Returns the PRF errors.
fn derive(
    key: &EncryptionKey,
    inputs: &[&[u8]; 4],
    number: u32,
) -> Result<EncryptionKey, TestError> {
    let [wbytes, shared, thash, body] = inputs;
    let seed = sha256(&[
        b"SPAKEkey",
        &1_i32.to_be_bytes(),
        &18_i32.to_be_bytes(),
        wbytes,
        shared,
        thash,
        body,
        &number.to_be_bytes(),
        &[1_u8],
    ]);
    let etype = KerberosEtype::from_etype_id(18).ok_or("aes256")?;
    let derived = prf::krb_fx_cf2(
        &prf::CfInput::new(prf::Key::new(etype, key.value()), b"SPAKE"),
        &prf::CfInput::new(prf::Key::new(etype, &seed), b"keyderiv"),
    )?;
    Ok(EncryptionKey::new(18, derived.to_vec()))
}

/// Answer a PA-SPAKE request: a support message gets the challenge, a response
/// is checked and answered under `K'[0]`.
///
/// # Errors
/// Returns decoding errors and client protocol violations.
pub(super) fn answer(
    kdc: &mut Kdc,
    message: &rasn_kerberos::AsReq,
    spake: &PaData,
) -> Result<Vec<u8>, TestError> {
    let received = Message::decode(&spake.value)?;
    if let Message::Response { pubkey, factor } = &received {
        return response(kdc, message, pubkey, factor);
    }
    if !matches!(received, Message::Support { groups: _ }) {
        return Err(format!("unexpected client message {received:?}").into());
    }
    kdc.support = spake.value.to_vec();
    if kdc.script.fault == Fault::FailSupport {
        return krb_error(PREAUTH_FAILED, &[offer(PA_ENC_TIMESTAMP, Vec::new())]);
    }
    let value = match kdc.script.raw_challenge.clone() {
        Some(raw) => raw,
        None => challenge(kdc)?,
    };
    let mut offers = vec![offer(PA_SPAKE, value)];
    offers.extend(cookie_offer());
    krb_error(MORE_PREAUTH_DATA_REQUIRED, &offers)
}

/// The challenge: recorded for the transcript, returned as delivered.
///
/// # Errors
/// Returns the PRF and encoding errors.
pub(super) fn challenge(kdc: &mut Kdc) -> Result<Vec<u8>, TestError> {
    let (_, scalar) = multiplier(&kdc.key)?;
    let mask = constant(EDWARDS25519_M)?.mul(scalar);
    let public = if kdc.script.fault == Fault::Identity {
        mask
    } else {
        EdwardsPoint::mul_base(&Scalar::from_bytes_mod_order(PRIVATE))
            .mul_by_cofactor()
            .add(mask)
    };
    let pubkey = kdc
        .script
        .element
        .clone()
        .unwrap_or_else(|| public.compress().to_bytes().to_vec());
    let factors: Vec<SecondFactor> = kdc
        .script
        .factors
        .iter()
        .map(|(kind, data)| SecondFactor {
            kind: *kind,
            data: data.clone().map(OctetString::from),
        })
        .collect();
    let original = Challenge {
        group: kdc.script.group,
        pubkey: pubkey.into(),
        factors,
    };
    kdc.challenge = der::encode(&KdcMessage::Challenge(original.clone()))?;
    if kdc.script.fault == Fault::Tamper {
        let mut delivered = original;
        delivered.factors.push(SecondFactor {
            kind: 9,
            data: None,
        });
        return Ok(der::encode(&KdcMessage::Challenge(delivered))?);
    }
    Ok(kdc.challenge.clone())
}

/// Check the response with the KDC's own transcript and answer under `K'[0]`,
/// or with `PREAUTH_FAILED` when the factor does not open under `K'[1]`.
///
/// # Errors
/// Returns decoding, derivation and encoding errors.
fn response(
    kdc: &Kdc,
    message: &rasn_kerberos::AsReq,
    pubkey: &[u8],
    factor: &EncryptedData,
) -> Result<Vec<u8>, TestError> {
    let (wbytes, scalar) = multiplier(&kdc.key)?;
    let client_element = CompressedEdwardsY::from_slice(pubkey)?
        .decompress()
        .ok_or("client element")?;
    let unmasked = client_element.sub(constant(EDWARDS25519_N)?.mul(scalar));
    let shared = unmasked
        .mul(Scalar::from_bytes_mod_order(PRIVATE))
        .mul_by_cofactor()
        .compress()
        .to_bytes();
    let after = sha256(&[&[0_u8; 32], &kdc.support, &kdc.challenge]);
    let thash = sha256(&[&after, pubkey]);
    let body = der::encode(&message.0.req_body)?;
    let inputs: [&[u8]; 4] = [&wbytes, &shared, &thash, &body];
    let etype = KerberosEtype::from_etype_id(18).ok_or("aes256")?;
    let opened = etype.decrypt_message(
        derive(&kdc.key, &inputs, 1)?.value(),
        &factor.cipher,
        KEY_USAGE_SPAKE,
    );
    if opened.is_ok_and(|plaintext| plaintext == FACTOR_NONE) {
        as_rep(message, &derive(&kdc.key, &inputs, 0)?)
    } else {
        krb_error(PREAUTH_FAILED, &[])
    }
}
