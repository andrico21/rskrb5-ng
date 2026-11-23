//! The legacy per-message token formats.
//!
//! RFC 1964 tokens for opted-in DES3 contexts (`SGN_ALG` 0x0004
//! HMAC-SHA1-DES3-KD, `SEAL_ALG` 0x0002) and RFC 4757 tokens for opted-in RC4
//! contexts (`SGN_ALG` 0x0011 HMAC-MD5, `SEAL_ALG` 0x0010 RC4), as MIT 1.22.2
//! makes and reads them (`k5seal.c:68-264`, `k5unsealiov.c:42-200`,
//! `util_seqnum.c:30-93`, `util_crypt.c:263-275`). AES and Camellia contexts
//! never use these formats, and a token whose algorithm IDs denote single DES
//! is refused with `RejectedFeature::SingleDes` (D2).

use rskrb5_ng::{
    crypto::CryptoPolicy,
    error::{Gss, Policy, RejectedFeature, RejectionReason},
    gss::{IovBuffer, IovKind},
};

use super::{
    context::{Context as _, TestError},
    support::{DES3, Pair, RC4, establish, establish_with, legacy_policy, refused, sequenced},
};

/// The krb5 mechanism OID in a framed token.
const KRB5_OID: [u8; 11] = [
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02,
];

/// The offset of the token ID in a framed token of `token`.
fn body(token: &[u8]) -> Result<usize, TestError> {
    let at = token
        .windows(KRB5_OID.len())
        .position(|window| window == KRB5_OID)
        .context("the krb5 OID")?;
    Ok(at.saturating_add(KRB5_OID.len()))
}

/// The two bytes at `at`.
fn pair_at(token: &[u8], at: usize) -> Result<[u8; 2], TestError> {
    let bytes = token
        .get(at..at.saturating_add(2))
        .context("two bytes in the token")?;
    Ok(<[u8; 2]>::try_from(bytes)?)
}

/// A context pair with its `SGN_ALG` and `SEAL_ALG` bytes.
type Profile = (Pair, [u8; 2], [u8; 2]);

/// A DES3 and an RC4 context, both permitted by policy, with their
/// `SGN_ALG` and `SEAL_ALG` in token byte order.
fn legacy_contexts() -> Result<Vec<Profile>, TestError> {
    let policy = legacy_policy()?;
    Ok(vec![
        (
            establish_with(DES3, sequenced(), &policy)?,
            [0x04, 0x00],
            [0x02, 0x00],
        ),
        (
            establish_with(RC4, sequenced(), &policy)?,
            [0x11, 0x00],
            [0x10, 0x00],
        ),
    ])
}

/// MIC and Wrap tokens of opted-in DES3 and RC4 contexts use the RFC
/// 1964/4757 formats and verify in both directions, sealed and signed only.
#[test]
fn legacy_contexts_exchange_rfc_1964_and_4757_tokens() -> Result<(), TestError> {
    for (mut ends, sign, seal) in legacy_contexts()? {
        let mic = ends.initiator.get_mic(b"to the acceptor")?;
        assert_eq!(mic.first(), Some(&0x60));
        let at = body(&mic)?;
        assert_eq!(pair_at(&mic, at)?, [0x01, 0x01]);
        assert_eq!(pair_at(&mic, at.saturating_add(2))?, sign);
        assert_eq!(pair_at(&mic, at.saturating_add(4))?, [0xff, 0xff]);
        ends.acceptor.verify_mic(b"to the acceptor", &mic)?;
        let back = ends.acceptor.get_mic(b"to the initiator")?;
        ends.initiator.verify_mic(b"to the initiator", &back)?;
        for confidential in [true, false] {
            let token = ends.initiator.wrap(b"legacy payload", confidential)?;
            let start = body(&token)?;
            assert_eq!(pair_at(&token, start)?, [0x02, 0x01]);
            assert_eq!(pair_at(&token, start.saturating_add(2))?, sign);
            let expected_seal = if confidential { seal } else { [0xff, 0xff] };
            assert_eq!(pair_at(&token, start.saturating_add(4))?, expected_seal);
            assert_eq!(
                token
                    .windows(b"legacy payload".len())
                    .any(|window| window == b"legacy payload"),
                !confidential
            );
            let opened = ends.acceptor.unwrap(&token)?;
            assert_eq!(opened.message(), b"legacy payload");
            assert_eq!(opened.confidential(), confidential);
            let reply = ends.acceptor.wrap(b"reply", confidential)?;
            assert_eq!(ends.initiator.unwrap(&reply)?.message(), b"reply");
        }
    }
    Ok(())
}

/// Mutated, replayed and reflected legacy tokens are refused.
#[test]
fn defective_legacy_tokens_are_refused() -> Result<(), TestError> {
    for (mut ends, _, _) in legacy_contexts()? {
        let token = ends.initiator.wrap(b"guarded", true)?;
        for at in [0, 2, 13, 16, 24, 30, token.len().saturating_sub(1)] {
            let mut mutated = token.clone();
            if let Some(byte) = mutated.get_mut(at) {
                *byte ^= 0x01;
            }
            refused(ends.acceptor.unwrap(&mutated)).context(&format!("byte {at}"))?;
        }
        refused(ends.initiator.unwrap(&token))?;
        assert_eq!(ends.acceptor.unwrap(&token)?.message(), b"guarded");
        assert!(matches!(
            ends.acceptor.unwrap(&token),
            Err(Gss::DuplicateToken(_))
        ));
        let mic = ends.initiator.get_mic(b"signed")?;
        refused(ends.acceptor.verify_mic(b"altered", &mic))?;
        ends.acceptor.verify_mic(b"signed", &mic)?;
    }
    Ok(())
}

/// A DES3 context refuses an RFC 1964 token whose `SGN_ALG` or `SEAL_ALG`
/// names single DES with `RejectedFeature::SingleDes`.
#[test]
fn single_des_algorithm_ids_are_rejected_by_name() -> Result<(), TestError> {
    let policy = legacy_policy()?;
    let mut ends = establish_with(DES3, sequenced(), &policy)?;
    let token = ends.initiator.wrap(b"x", true)?;
    let at = body(&token)?;
    for (offset, value) in [(2, [0x00, 0x00]), (2, [0x02, 0x00]), (4, [0x00, 0x00])] {
        let mut forged = token.clone();
        if let Some(slot) = forged.get_mut(at.saturating_add(offset)..at.saturating_add(offset).saturating_add(2)) {
            slot.copy_from_slice(&value);
        }
        let outcome = ends.acceptor.unwrap(&forged);
        assert!(
            matches!(
                outcome,
                Err(Gss::Policy(Policy::RejectedFeature {
                    feature: RejectedFeature::SingleDes,
                    reason: RejectionReason::RemovedAndInsecure,
                }))
            ),
            "{offset}: {outcome:?}"
        );
    }
    let mic = ends.initiator.get_mic(b"m")?;
    let mic_at = body(&mic)?;
    let mut forged = mic;
    if let Some(slot) = forged.get_mut(mic_at.saturating_add(2)..mic_at.saturating_add(4)) {
        slot.copy_from_slice(&[0x01, 0x00]);
    }
    assert!(matches!(
        ends.acceptor.verify_mic(b"m", &forged),
        Err(Gss::Policy(Policy::RejectedFeature {
            feature: RejectedFeature::SingleDes,
            reason: RejectionReason::RemovedAndInsecure,
        }))
    ));
    Ok(())
}

/// AES contexts never use the legacy formats: their tokens are RFC 4121
/// tokens, and a legacy token presented to them is refused.
#[test]
fn aes_contexts_never_use_the_legacy_formats() -> Result<(), TestError> {
    let mut aes = establish(sequenced())?;
    let mic = aes.initiator.get_mic(b"aes")?;
    assert_eq!(mic.get(..2), Some(&[0x04, 0x04][..]));
    let wrap = aes.initiator.wrap(b"aes", true)?;
    assert_eq!(wrap.get(..2), Some(&[0x05, 0x04][..]));
    let mut des3 = establish_with(DES3, sequenced(), &legacy_policy()?)?;
    let legacy_mic = des3.initiator.get_mic(b"aes")?;
    let legacy_wrap = des3.initiator.wrap(b"aes", false)?;
    refused(aes.acceptor.verify_mic(b"aes", &legacy_mic))?;
    refused(aes.acceptor.unwrap(&legacy_wrap))?;
    Ok(())
}

/// IOV and AEAD tokens keep the RFC 4121 layout only: a legacy context
/// refuses them, and the default policy still refuses DES3 and RC4 contexts.
#[test]
fn legacy_contexts_have_no_iov_tokens() -> Result<(), TestError> {
    let mut ends = establish_with(RC4, sequenced(), &legacy_policy()?)?;
    let mut buffers = vec![
        IovBuffer::empty(IovKind::Header),
        IovBuffer::new(IovKind::Data, b"x".to_vec()),
    ];
    assert!(matches!(
        ends.initiator.wrap_iov(&mut buffers, true),
        Err(Gss::LegacyTokenFormat(23_i32))
    ));
    assert!(
        establish_with(DES3, sequenced(), &CryptoPolicy::default())
            .err()
            .is_some()
    );
    Ok(())
}
