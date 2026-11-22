//! Per-message tokens of an established context (RFC 4121 section 4.2) and the
//! sequence and replay windows that guard them.
//!
//! The window is MIT's 64-entry `g_seqstate` (`generic/util_seqstate.c:59-114`).
//! Where MIT reports a duplicate, an old, an out-of-sequence or a gap token as a
//! supplementary status and still returns the message, this module refuses it
//! (executor decision: security beats leniency); a refused token leaves the
//! window as it was.

use rskrb5_ng::{
    error::{Gss, Spnego},
    gss::{AcceptorOptions, ContextFlags, Credential, InitiatorOptions},
};

use super::{
    context::{Context as _, TestError},
    support::{HOST, Pair, cache, cached, establish, ticket_for},
};

/// A context pair negotiated with `flags`.
fn pair(flags: ContextFlags) -> Result<Pair, TestError> {
    let credential = Credential::from_ccache(cache(vec![cached(&ticket_for(HOST, &[])?)?]))?;
    establish(
        &credential,
        InitiatorOptions::new().with_flags(flags),
        (AcceptorOptions::new(), &[HOST], None),
    )
}

/// The flags of a context with sequencing and replay detection.
fn sequenced() -> ContextFlags {
    ContextFlags::MUTUAL
        | ContextFlags::SEQUENCE
        | ContextFlags::REPLAY
        | ContextFlags::CONF
        | ContextFlags::INTEG
}

/// MIC and Wrap tokens verify in both directions, sealed and integrity-only.
#[test]
fn mic_and_wrap_tokens_verify_in_both_directions() -> Result<(), TestError> {
    let mut ends = pair(sequenced())?;
    // Given an initiator MIC, the acceptor verifies it, and the other way round.
    let mic = ends.initiator.get_mic(b"to the acceptor")?;
    ends.acceptor.verify_mic(b"to the acceptor", &mic)?;
    let reply = ends.acceptor.get_mic(b"to the initiator")?;
    ends.initiator.verify_mic(b"to the initiator", &reply)?;
    // Given sealed and integrity-only Wrap tokens, each unwraps to the message
    // and reports whether it was confidential.
    for confidential in [true, false] {
        let sealed = ends.initiator.wrap(b"payload", confidential)?;
        let opened = ends.acceptor.unwrap(&sealed)?;
        assert_eq!(opened.message(), b"payload");
        assert_eq!(opened.confidential(), confidential);
        let back = ends.acceptor.wrap(b"answer", confidential)?;
        assert_eq!(ends.initiator.unwrap(&back)?.message(), b"answer");
    }
    Ok(())
}

/// A token presented twice is a duplicate.
#[test]
fn replayed_tokens_are_refused() -> Result<(), TestError> {
    let mut ends = pair(sequenced())?;
    let mic = ends.initiator.get_mic(b"once")?;
    ends.acceptor.verify_mic(b"once", &mic)?;
    // Given the same MIC again, it is a duplicate.
    assert!(matches!(
        ends.acceptor.verify_mic(b"once", &mic),
        Err(Gss::DuplicateToken(_))
    ));
    let sealed = ends.initiator.wrap(b"once", true)?;
    drop(ends.acceptor.unwrap(&sealed)?);
    assert!(matches!(
        ends.acceptor.unwrap(&sealed),
        Err(Gss::DuplicateToken(_))
    ));
    Ok(())
}

/// With sequencing, a token that skips one is refused and does not move the
/// window, so the skipped one and then the later one still verify.
#[test]
fn reordered_tokens_are_refused_under_sequencing() -> Result<(), TestError> {
    let mut ends = pair(sequenced())?;
    let first = ends.initiator.get_mic(b"first")?;
    let second = ends.initiator.get_mic(b"second")?;
    // Given the second token before the first, it is refused as a gap.
    assert!(matches!(
        ends.acceptor.verify_mic(b"second", &second),
        Err(Gss::GapToken(_))
    ));
    // Then the first and the second verify in order, and the first again is a duplicate.
    ends.acceptor.verify_mic(b"first", &first)?;
    ends.acceptor.verify_mic(b"second", &second)?;
    assert!(matches!(
        ends.acceptor.verify_mic(b"first", &first),
        Err(Gss::DuplicateToken(_))
    ));
    Ok(())
}

/// With replay detection only, reordering inside the window is accepted, a
/// duplicate is not, and a token older than the 64-entry window is refused.
#[test]
fn replay_window_without_sequencing() -> Result<(), TestError> {
    let flags = ContextFlags::MUTUAL | ContextFlags::REPLAY | ContextFlags::INTEG;
    let mut ends = pair(flags)?;
    let mut tokens = Vec::new();
    for index in 0_u8..70 {
        tokens.push(ends.initiator.get_mic(&[index])?);
    }
    let token = |index: usize| tokens.get(index).context("a token");
    // Given token 1 before token 0, both verify; token 0 again is a duplicate.
    ends.acceptor.verify_mic(&[1], token(1)?)?;
    ends.acceptor.verify_mic(&[0], token(0)?)?;
    assert!(matches!(
        ends.acceptor.verify_mic(&[0], token(0)?),
        Err(Gss::DuplicateToken(_))
    ));
    // Given token 69, token 2 is now more than 64 behind and is too old.
    ends.acceptor.verify_mic(&[69], token(69)?)?;
    assert!(matches!(
        ends.acceptor.verify_mic(&[2], token(2)?),
        Err(Gss::OldToken(_))
    ));
    Ok(())
}

/// Without sequencing or replay detection, a duplicate verifies (MIT
/// `g_seqstate_check` returns complete when neither is asked for).
#[test]
fn no_window_without_sequencing_or_replay_detection() -> Result<(), TestError> {
    let mut ends = pair(ContextFlags::MUTUAL | ContextFlags::INTEG)?;
    let mic = ends.initiator.get_mic(b"twice")?;
    ends.acceptor.verify_mic(b"twice", &mic)?;
    ends.acceptor.verify_mic(b"twice", &mic)?;
    Ok(())
}

/// A token reflected back to its sender, a tampered MIC and a MIC over other
/// bytes are refused.
#[test]
fn reflected_and_tampered_tokens_are_refused() -> Result<(), TestError> {
    let mut ends = pair(sequenced())?;
    let mic = ends.initiator.get_mic(b"mine")?;
    // Given the initiator's own MIC, the initiator refuses it as sent by the wrong side.
    assert!(matches!(
        ends.initiator.verify_mic(b"mine", &mic),
        Err(Gss::Spnego(Spnego::UnexpectedGssTokenSender { .. }))
    ));
    let sealed = ends.initiator.wrap(b"mine", true)?;
    assert!(matches!(
        ends.initiator.unwrap(&sealed),
        Err(Gss::Spnego(Spnego::UnexpectedGssTokenSender { .. }))
    ));
    // Given a MIC over other bytes, or with a flipped checksum byte, it does not verify.
    assert!(matches!(
        ends.acceptor.verify_mic(b"other", &mic),
        Err(Gss::Spnego(Spnego::GssChecksumMismatch))
    ));
    let mut flipped = mic.clone();
    let last = flipped.last_mut().context("a checksum byte")?;
    *last ^= 0x01;
    assert!(matches!(
        ends.acceptor.verify_mic(b"mine", &flipped),
        Err(Gss::Spnego(Spnego::GssChecksumMismatch))
    ));
    // The refusals did not consume the genuine token.
    ends.acceptor.verify_mic(b"mine", &mic)?;
    Ok(())
}

/// Confidentiality and integrity are always offered, as MIT's initiator adds
/// them unless the credential suppresses them (`init_sec_context.c:552-553`).
#[test]
fn confidentiality_and_integrity_are_always_offered() -> Result<(), TestError> {
    // Given an initiator that asks for mutual authentication only,
    let mut ends = pair(ContextFlags::MUTUAL)?;
    // then both ends hold CONF and INTEG, and a sealed token works.
    for context in [&ends.initiator, &ends.acceptor] {
        assert!(
            context
                .inquire()
                .flags()
                .contains(ContextFlags::CONF | ContextFlags::INTEG)
        );
    }
    let sealed = ends.initiator.wrap(b"secret", true)?;
    assert!(ends.acceptor.unwrap(&sealed)?.confidential());
    Ok(())
}
