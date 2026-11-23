//! The legacy per-message token formats.
//!
//! RFC 1964 tokens of DES3 contexts (the `des3-cbc-sha1-kd` profile of
//! draft-raeburn-cat-gssapi-krb5-3des) and RFC 4757 tokens of RC4 contexts, as
//! MIT 1.22.2 makes and reads them (`k5seal.c:68-264`,
//! `k5unsealiov.c:42-200`, `util_seqnum.c:30-93`, `util_crypt.c:263-275`,
//! `enc_rc4.c:37-120`, `kg_setup_keys` in `util_crypt.c`). They apply only to a
//! context whose key is DES3 or RC4 and whose enctype policy permits it
//! (`allow_des3`, `allow_rc4`); AES and Camellia contexts use RFC 4121 tokens
//! only. A token whose `SGN_ALG` or `SEAL_ALG` names single DES is refused with
//! [`RejectedFeature::SingleDes`] (D2).

use core::iter;
use std::time::SystemTime;

use hmac::{Hmac, KeyInit as _, Mac as _};
use md5::Md5;
use rc4::{Rc4, StreamCipher as _};
use zeroize::Zeroizing;

use super::{EncryptionKey, Error, EstablishedContext, Unwrapped, context};
use crate::{
    crypto::{Des3CbcSha1KdEtype, Use, kerb_checksum_hmac_md5},
    error::{Policy, RejectedFeature, RejectionReason},
};

/// The token ID of a legacy MIC token.
const TOK_MIC: [u8; 2] = [0x01, 0x01];
/// The token ID of a legacy Wrap token.
const TOK_WRAP: [u8; 2] = [0x02, 0x01];
/// `SEAL_ALG` of an integrity-only Wrap token and the MIC filler.
const SEAL_NONE: u16 = 0xffff;
/// `KG_USAGE_SIGN`.
const USAGE_SIGN: u32 = 23;
/// The RC4 MIC checksum usage (`k5seal.c:166-170`).
const USAGE_RC4_MIC: u32 = 15;
/// The confounder of both profiles.
const CONFOUNDER_LEN: usize = 8;
/// The DER form of the krb5 mechanism OID.
const KRB5_OID: [u8; 11] = [
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02,
];
/// The DER form of the Microsoft krb5 OID (`1.2.840.48018.1.2.2`).
const MS_KRB5_OID: [u8; 11] = [
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x82, 0xf7, 0x12, 0x01, 0x02, 0x02,
];
/// The longest legacy token, in bytes.
const MAX_TOKEN_LEN: usize = 0x100_0000;

/// A legacy profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Algorithm {
    /// RFC 1964 with DES3 (`SGN_ALG` 0x0004, `SEAL_ALG` 0x0002).
    Des3,
    /// RFC 4757 (`SGN_ALG` 0x0011, `SEAL_ALG` 0x0010).
    Rc4,
}

impl Algorithm {
    /// `SGN_ALG`.
    const fn sign(self) -> u16 {
        match self {
            Self::Des3 => 0x0004,
            Self::Rc4 => 0x0011,
        }
    }

    /// `SEAL_ALG`.
    const fn seal(self) -> u16 {
        match self {
            Self::Des3 => 0x0002,
            Self::Rc4 => 0x0010,
        }
    }

    /// The checksum length in the token.
    const fn checksum_len(self) -> usize {
        match self {
            Self::Des3 => 20,
            Self::Rc4 => 8,
        }
    }
}

/// The legacy profile of a context and its key, or `None` for an RFC 4121
/// context; a legacy key needs its enctype policy.
///
/// # Errors
///
/// Returns [`Error::UnexpectedStep`] before establishment,
/// [`Error::ContextExpired`] and the policy error of a legacy key.
pub(super) fn select(
    context: &EstablishedContext,
) -> Result<Option<(Algorithm, EncryptionKey)>, Error> {
    context::established(context)?;
    let key = context::key(context);
    let algorithm = match key.etype() {
        16_i32 => Algorithm::Des3,
        23_i32 => Algorithm::Rc4,
        _ => return Ok(None),
    };
    if SystemTime::now() > context.expires {
        return Err(Error::ContextExpired);
    }
    context
        .crypto_policy
        .check_use(key.etype(), Use::SessionKey)?;
    Ok(Some((algorithm, key.clone())))
}

/// `HMAC-MD5(key, data)`.
///
/// # Errors
///
/// Returns [`Error::NotNegotiated`] for a key HMAC refuses.
fn hmac_md5(key: &[u8], data: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
    let mut mac = <Hmac<Md5>>::new_from_slice(key)
        .map_err(|_length| Error::NotNegotiated("an HMAC key of the wrong length"))?;
    mac.update(data);
    Ok(Zeroizing::new(mac.finalize().into_bytes().to_vec()))
}

/// RC4 with the key RFC 4757 derives from `key` and `salt` for usage 0
/// (`krb5int_arcfour_gsscrypt`).
///
/// # Errors
///
/// Returns [`Error::NotNegotiated`] for a key RC4 refuses.
fn rc4_crypt(key: &[u8], salt: &[u8], data: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
    let usage = hmac_md5(key, &0_u32.to_le_bytes())?;
    let stream = hmac_md5(&usage, salt)?;
    let mut cipher = Rc4::new_from_slice(&stream)
        .map_err(|_length| Error::NotNegotiated("an RC4 key of the wrong length"))?;
    let mut out = Zeroizing::new(data.to_vec());
    cipher.apply_keystream(&mut out);
    Ok(out)
}

/// DES3-CBC of one or more blocks under the raw key with `iv`.
///
/// # Errors
///
/// Returns the cipher errors.
fn des3(key: &[u8], iv: &[u8], data: &[u8], seal: bool) -> Result<Zeroizing<Vec<u8>>, Error> {
    if seal {
        let mut first = Zeroizing::new(data.to_vec());
        first
            .iter_mut()
            .zip(iv)
            .for_each(|(byte, mask)| *byte ^= mask);
        Ok(Zeroizing::new(
            Des3CbcSha1KdEtype::encrypt_data(key, &first)?.1,
        ))
    } else {
        let mut plain = Zeroizing::new(Des3CbcSha1KdEtype::decrypt_data(key, data)?);
        plain
            .iter_mut()
            .zip(iv)
            .for_each(|(byte, mask)| *byte ^= mask);
        Ok(plain)
    }
}

/// The checksum of a token over its first eight bytes and `data`.
///
/// # Errors
///
/// Returns the checksum errors.
fn checksum(algorithm: Algorithm, key: &[u8], usage: u32, data: &[u8]) -> Result<Vec<u8>, Error> {
    Ok(match algorithm {
        Algorithm::Des3 => Des3CbcSha1KdEtype::checksum(key, data, usage)?,
        Algorithm::Rc4 => kerb_checksum_hmac_md5(key, data, usage)
            .into_iter()
            .take(Algorithm::Rc4.checksum_len())
            .collect(),
    })
}

/// The 8-byte encrypted sequence field (`kg_make_seq_num`,
/// `util_seqnum.c:30-52`).
///
/// # Errors
///
/// Returns the cipher errors.
fn seal_sequence(
    algorithm: Algorithm,
    key: &[u8],
    direction: u8,
    sequence: u32,
    sum: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let iv = sum.get(..8).unwrap_or_default();
    match algorithm {
        Algorithm::Des3 => {
            let plain = [sequence.to_le_bytes(), [direction; 4]].concat();
            des3(key, iv, &plain, true)
        }
        Algorithm::Rc4 => {
            let plain = [sequence.to_be_bytes(), [direction; 4]].concat();
            rc4_crypt(key, iv, &plain)
        }
    }
}

/// The direction and number of a sequence field (`kg_get_seq_num`,
/// `util_seqnum.c:54-93`).
///
/// # Errors
///
/// Returns [`Error::DefectiveToken`] for inconsistent direction bytes and the
/// cipher errors.
fn open_sequence(
    algorithm: Algorithm,
    key: &[u8],
    field: &[u8],
    sum: &[u8],
) -> Result<(u8, u32), Error> {
    let iv = sum.get(..8).unwrap_or_default();
    let plain = match algorithm {
        Algorithm::Des3 => des3(key, iv, field, false)?,
        Algorithm::Rc4 => rc4_crypt(key, iv, field)?,
    };
    let direction = plain
        .get(4..8)
        .ok_or(Error::DefectiveToken("a short sequence field"))?;
    let first = direction.first().copied().unwrap_or_default();
    if direction.iter().any(|byte| *byte != first) {
        return Err(Error::DefectiveToken(
            "a sequence field with mixed direction bytes",
        ));
    }
    let number = <[u8; 4]>::try_from(plain.get(..4).unwrap_or_default())
        .map_err(|_length| Error::DefectiveToken("a short sequence field"))?;
    Ok(match algorithm {
        Algorithm::Des3 => (first, u32::from_le_bytes(number)),
        Algorithm::Rc4 => (first, u32::from_be_bytes(number)),
    })
}

/// The DER length octets of `length`.
fn der_length(length: usize) -> Vec<u8> {
    if length < 0x80 {
        return vec![u8::try_from(length).unwrap_or_default()];
    }
    let bytes = length.to_be_bytes();
    let first = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len());
    let significant = bytes.get(first..).unwrap_or_default();
    let mut out = vec![0x80 | u8::try_from(significant.len()).unwrap_or_default()];
    out.extend_from_slice(significant);
    out
}

/// The RFC 2743 framing of `inner` under the krb5 OID.
fn frame(inner: &[u8]) -> Vec<u8> {
    let mut token = vec![0x60];
    token.extend(der_length(KRB5_OID.len().saturating_add(inner.len())));
    token.extend_from_slice(&KRB5_OID);
    token.extend_from_slice(inner);
    token
}

/// The body after the RFC 2743 framing of a krb5 token.
///
/// # Errors
///
/// Returns [`Error::DefectiveToken`] for a token without the framing, a length
/// that does not match, or another mechanism.
fn unframe(token: &[u8]) -> Result<&[u8], Error> {
    let defective = || Error::DefectiveToken("not a framed krb5 token");
    let (tag, after_tag) = token.split_first().ok_or_else(defective)?;
    let (first, after_first) = after_tag.split_first().ok_or_else(defective)?;
    if *tag != 0x60 {
        return Err(defective());
    }
    let (length, rest) = if *first < 0x80 {
        (usize::from(*first), after_first)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > 4 {
            return Err(defective());
        }
        let (octets, tail) = after_first.split_at_checked(count).ok_or_else(defective)?;
        let value = octets.iter().fold(0_usize, |total, octet| {
            total.wrapping_shl(8) | usize::from(*octet)
        });
        (value, tail)
    };
    if length != rest.len() {
        return Err(defective());
    }
    let (oid, body) = rest
        .split_at_checked(KRB5_OID.len())
        .ok_or_else(defective)?;
    if oid != KRB5_OID && oid != MS_KRB5_OID {
        return Err(defective());
    }
    Ok(body)
}

/// The direction byte this end sends: zero from the initiator (`k5seal.c:206`).
const fn direction(initiated: bool) -> u8 {
    if initiated { 0 } else { 0xff }
}

/// The send sequence number, as 32 bits (`k5seal.c:259-260`).
fn take_sequence(context: &mut EstablishedContext) -> u32 {
    let number = u32::try_from(context.send_sequence & 0xffff_ffff).unwrap_or_default();
    context.send_sequence = u64::from(number.wrapping_add(1));
    number
}

/// Whether two tags are equal, in time independent of where they differ.
fn same(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .fold(0_u8, |difference, (ours, theirs)| difference | (ours ^ theirs))
            == 0
}

/// The eight leading bytes of a token: token ID, `SGN_ALG`, `SEAL_ALG` and
/// filler.
fn metadata(token: [u8; 2], sign: u16, seal: u16) -> Vec<u8> {
    let mut out = token.to_vec();
    out.extend_from_slice(&sign.to_le_bytes());
    out.extend_from_slice(&seal.to_le_bytes());
    out.extend_from_slice(&[0xff, 0xff]);
    out
}

/// `gss_get_mic` of a legacy context.
///
/// # Errors
///
/// Returns the checksum and cipher errors.
pub(super) fn get_mic(
    context: &mut EstablishedContext,
    (algorithm, key): (Algorithm, EncryptionKey),
    message: &[u8],
) -> Result<Vec<u8>, Error> {
    let head = metadata(TOK_MIC, algorithm.sign(), SEAL_NONE);
    let usage = match algorithm {
        Algorithm::Des3 => USAGE_SIGN,
        Algorithm::Rc4 => USAGE_RC4_MIC,
    };
    let sum = checksum(
        algorithm,
        key.value(),
        usage,
        &[head.as_slice(), message].concat(),
    )?;
    let sequence = take_sequence(context);
    let field = seal_sequence(
        algorithm,
        key.value(),
        direction(context.initiated),
        sequence,
        &sum,
    )?;
    Ok(frame(&[head.as_slice(), &field, &sum].concat()))
}

/// `gss_wrap` of a legacy context.
///
/// # Errors
///
/// Returns the random-source, checksum and cipher errors.
pub(super) fn wrap(
    context: &mut EstablishedContext,
    (algorithm, key): (Algorithm, EncryptionKey),
    message: &[u8],
    confidential: bool,
) -> Result<Vec<u8>, Error> {
    let head = metadata(
        TOK_WRAP,
        algorithm.sign(),
        if confidential {
            algorithm.seal()
        } else {
            SEAL_NONE
        },
    );
    let mut plain = Zeroizing::new(vec![0; CONFOUNDER_LEN]);
    getrandom::fill(&mut plain).map_err(Error::Random)?;
    plain.extend_from_slice(message);
    let pad = match algorithm {
        Algorithm::Des3 => 8_u8.saturating_sub(u8::try_from(message.len() & 7).unwrap_or_default()),
        Algorithm::Rc4 => 1,
    };
    plain.extend(iter::repeat_n(pad, usize::from(pad)));
    let sum = checksum(
        algorithm,
        key.value(),
        USAGE_SIGN,
        &[head.as_slice(), &plain].concat(),
    )?;
    let sequence = take_sequence(context);
    let field = seal_sequence(
        algorithm,
        key.value(),
        direction(context.initiated),
        sequence,
        &sum,
    )?;
    let payload = if confidential {
        match algorithm {
            Algorithm::Des3 => des3(key.value(), &[0; 8], &plain, true)?,
            Algorithm::Rc4 => {
                let sealing: Zeroizing<Vec<u8>> =
                    Zeroizing::new(key.value().iter().map(|byte| byte ^ 0xf0).collect());
                rc4_crypt(&sealing, &sequence.to_be_bytes(), &plain)?
            }
        }
    } else {
        plain
    };
    Ok(frame(&[head.as_slice(), &field, &sum, &payload].concat()))
}

/// The checked parts of a received legacy token: `SEAL_ALG`, the sequence
/// number, the checksum and the payload.
struct Received<'token> {
    /// The leading eight bytes.
    head: &'token [u8],
    /// `SEAL_ALG`.
    seal: u16,
    /// The sequence number.
    sequence: u32,
    /// The checksum.
    sum: &'token [u8],
    /// The bytes after the checksum.
    payload: &'token [u8],
}

/// Parse and check a received legacy token of `kind`.
///
/// # Errors
///
/// Returns [`Error::Policy`] with [`RejectedFeature::SingleDes`] for single-DES
/// algorithm IDs, [`Error::DefectiveToken`] for another token type,
/// algorithm, filler or direction, and the cipher errors.
fn receive<'token>(
    context: &EstablishedContext,
    (algorithm, key): (Algorithm, &EncryptionKey),
    token: &'token [u8],
    kind: [u8; 2],
) -> Result<Received<'token>, Error> {
    if token.len() > MAX_TOKEN_LEN {
        return Err(Error::TokenTooLarge {
            maximum: MAX_TOKEN_LEN,
            actual: token.len(),
        });
    }
    let body = unframe(token)?;
    let defective = Error::DefectiveToken;
    let field = |at: usize| -> u16 {
        body.get(at..at.saturating_add(2))
            .and_then(|bytes| <[u8; 2]>::try_from(bytes).ok())
            .map_or(0, u16::from_le_bytes)
    };
    let (sign, seal) = (field(2), field(4));
    if body.len() < 16 {
        return Err(defective("a token shorter than its header"));
    }
    if matches!(sign, 0x0000..=0x0002) || seal == 0x0000 {
        return Err(Error::Policy(Policy::RejectedFeature {
            feature: RejectedFeature::SingleDes,
            reason: RejectionReason::RemovedAndInsecure,
        }));
    }
    if body.get(..2) != Some(&kind[..]) || body.get(6..8) != Some(&[0xff, 0xff][..]) {
        return Err(defective("not a legacy token of the expected type"));
    }
    let seal_ok = if kind == TOK_MIC {
        seal == SEAL_NONE
    } else {
        seal == SEAL_NONE || seal == algorithm.seal()
    };
    if !seal_ok || sign != algorithm.sign() {
        return Err(defective("an algorithm this context does not use"));
    }
    let end = 16_usize.saturating_add(algorithm.checksum_len());
    let sum = body
        .get(16..end)
        .ok_or_else(|| defective("a short checksum"))?;
    let (sent_by, sequence) = open_sequence(
        algorithm,
        key.value(),
        body.get(8..16).unwrap_or_default(),
        sum,
    )?;
    if sent_by != direction(!context.initiated) {
        return Err(defective("a token from this end of the context"));
    }
    Ok(Received {
        head: body.get(..8).unwrap_or_default(),
        seal,
        sequence,
        sum,
        payload: body.get(end..).unwrap_or_default(),
    })
}

/// `gss_verify_mic` of a legacy context.
///
/// # Errors
///
/// Returns the errors of [`receive`], [`Error::BadSignature`] and the window
/// errors.
pub(super) fn verify_mic(
    context: &mut EstablishedContext,
    (algorithm, key): (Algorithm, EncryptionKey),
    message: &[u8],
    token: &[u8],
) -> Result<(), Error> {
    let received = receive(context, (algorithm, &key), token, TOK_MIC)?;
    if !received.payload.is_empty() {
        return Err(Error::DefectiveToken("a MIC token with a payload"));
    }
    let usage = match algorithm {
        Algorithm::Des3 => USAGE_SIGN,
        Algorithm::Rc4 => USAGE_RC4_MIC,
    };
    let expected = checksum(
        algorithm,
        key.value(),
        usage,
        &[received.head, message].concat(),
    )?;
    if !same(&expected, received.sum) {
        return Err(Error::BadSignature);
    }
    context.window.admit(u64::from(received.sequence))
}

/// `gss_unwrap` of a legacy context.
///
/// # Errors
///
/// Returns the errors of [`receive`], [`Error::DefectiveToken`] for bad
/// padding, [`Error::BadSignature`] and the window errors.
pub(super) fn unwrap(
    context: &mut EstablishedContext,
    (algorithm, key): (Algorithm, EncryptionKey),
    token: &[u8],
) -> Result<Unwrapped, Error> {
    let received = receive(context, (algorithm, &key), token, TOK_WRAP)?;
    let confidential = received.seal != SEAL_NONE;
    let plain = if confidential {
        match algorithm {
            Algorithm::Des3 => des3(key.value(), &[0; 8], received.payload, false)?,
            Algorithm::Rc4 => {
                let sealing: Zeroizing<Vec<u8>> =
                    Zeroizing::new(key.value().iter().map(|byte| byte ^ 0xf0).collect());
                rc4_crypt(&sealing, &received.sequence.to_be_bytes(), received.payload)?
            }
        }
    } else {
        Zeroizing::new(received.payload.to_vec())
    };
    let pad = usize::from(plain.last().copied().unwrap_or_default());
    let pad_ok = match algorithm {
        Algorithm::Des3 => (1..=8).contains(&pad),
        Algorithm::Rc4 => pad == 1,
    };
    let message_end = plain
        .len()
        .checked_sub(pad)
        .filter(|end| *end >= CONFOUNDER_LEN);
    let Some(end) = message_end.filter(|_| pad_ok) else {
        return Err(Error::DefectiveToken("bad legacy padding"));
    };
    let expected = checksum(
        algorithm,
        key.value(),
        USAGE_SIGN,
        &[received.head, &plain].concat(),
    )?;
    if !same(&expected, received.sum) {
        return Err(Error::BadSignature);
    }
    context.window.admit(u64::from(received.sequence))?;
    Ok(Unwrapped {
        message: Zeroizing::new(plain.get(CONFOUNDER_LEN..end).unwrap_or_default().to_vec()),
        confidential,
    })
}
