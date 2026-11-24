//! The security rules of the `NegoEx` context.
//!
//! They are the `VERIFY` binding, replayed and reordered messages, the
//! mechanism policy and the key policy.

use alloc::sync::Arc;

use rskrb5_ng::{
    error::Negoex,
    extensions::{Extension, GssMechanism, Registry},
    gss::negoex::{Context, Mechanism, Request},
};

use super::{
    context::{Context as _, TestError},
    negoextest::{KeyPolicy, Knobs, OID_FIRST, OID_SECOND, Registered, TestMechanism},
};

/// A registry with both test mechanisms registered.
fn registry() -> Result<Registry, TestError> {
    let mut registry = Registry::new();
    for oid in [OID_FIRST, OID_SECOND] {
        registry.register(Extension::GssMechanism(Arc::new(Registered {
            id: format!("negoextest-{}", oid.last().copied().unwrap_or(0)),
            oid: oid.to_vec(),
        })))?;
    }
    Ok(registry)
}

/// An initiator and an acceptor of the first mechanism, `hops` hops, and the
/// first two tokens of their exchange.
fn first_tokens(hops: u8) -> Result<(Context, Context, Vec<u8>, Vec<u8>), TestError> {
    let registry = registry()?;
    let knobs = Knobs {
        hops,
        ..Knobs::default()
    };
    let mechanisms: Vec<Arc<dyn Mechanism>> = vec![TestMechanism::shared(&OID_FIRST, knobs)];
    let mut initiator = Context::initiator(&registry, &mechanisms, Request::new())?;
    let mut acceptor = Context::acceptor(&registry, &mechanisms, Request::new())?;
    let first = initiator
        .step(None)?
        .into_token()
        .context("a first token")?;
    let second = acceptor
        .step(Some(&first))?
        .into_token()
        .context("an acceptor token")?;
    Ok((initiator, acceptor, first, second))
}

/// The bytes of a `VERIFY` message holding the 12-byte HMAC-SHA1-96 checksum of
/// the mechanism's AES256 key: the 80-byte header and the checksum.
const VERIFY_LEN: usize = 80 + 12;

/// Flip the bit `mask` of the byte at `index`.
fn flip(token: &mut [u8], index: usize, mask: u8) -> Result<(), TestError> {
    *token.get_mut(index).context("a byte to damage")? ^= mask;
    Ok(())
}

/// QA failure scenario: a `VERIFY` message with a wrong checksum fails the
/// context, which then refuses every later step.
#[test]
fn a_verify_with_a_wrong_checksum_fails_the_context() -> Result<(), TestError> {
    let (mut initiator, _acceptor, _first, mut second) = first_tokens(1)?;
    // The checksum is the last byte range of the acceptor's token.
    let last = second.len() - 1;
    flip(&mut second, last, 0x01)?;
    let failure = initiator
        .step(Some(&second))
        .err()
        .context("a wrong checksum must fail")?;
    assert!(matches!(failure, Negoex::InvalidChecksum), "{failure}");
    assert!(!initiator.is_complete());
    assert!(initiator.selected().is_none());
    assert!(matches!(
        initiator.step(Some(&second)),
        Err(Negoex::UnexpectedStep(_))
    ));
    Ok(())
}

/// The checksum covers the whole transcript: a change in the acceptor's nonce, in
/// an earlier message the initiator sent, or in the acceptor's meta-data fails it.
#[test]
fn the_checksum_binds_the_whole_transcript() -> Result<(), TestError> {
    // ACCEPTOR_NEGO: header 40 + random at offset 40.
    let (mut initiator, _acceptor, _first, mut second) = first_tokens(1)?;
    flip(&mut second, 40, 0x80)?;
    assert!(matches!(
        initiator.step(Some(&second)),
        Err(Negoex::InvalidChecksum)
    ));
    // The initiator's INITIATOR_NEGO random reaches the acceptor's transcript.
    let registry = registry()?;
    let mechanisms: Vec<Arc<dyn Mechanism>> =
        vec![TestMechanism::shared(&OID_FIRST, Knobs::default())];
    let mut sender = Context::initiator(&registry, &mechanisms, Request::new())?;
    let mut receiver = Context::acceptor(&registry, &mechanisms, Request::new())?;
    let mut first = sender.step(None)?.into_token().context("a first token")?;
    flip(&mut first, 40, 0x01)?;
    assert!(matches!(
        receiver.step(Some(&first)),
        Err(Negoex::InvalidChecksum)
    ));
    Ok(())
}

/// A peer that sends no `VERIFY` message does not complete the negotiation.
#[test]
fn without_the_peers_verify_message_the_context_is_incomplete() -> Result<(), TestError> {
    let (mut initiator, _acceptor, _first, second) = first_tokens(1)?;
    let stripped = second
        .get(..second.len() - VERIFY_LEN)
        .context("the token holds a VERIFY message")?;
    let step = initiator.step(Some(stripped))?;
    assert!(!step.is_complete(), "no VERIFY, no completion");
    assert!(!initiator.is_complete());
    assert!(initiator.selected().is_none());
    assert!(initiator.into_session().is_err());
    Ok(())
}

/// A VERIFY message whose checksum type is not the key's keyed checksum is refused.
#[test]
fn a_checksum_type_the_key_does_not_define_is_refused() -> Result<(), TestError> {
    for (kind, original) in [(7_i32, 16_i32), (15_i32, 16_i32), (-138_i32, 16_i32)] {
        let (mut initiator, _acceptor, _first, mut second) = first_tokens(1)?;
        // The checksum type is 64 bytes into the VERIFY message.
        let at = second.len() - VERIFY_LEN + 64;
        assert_eq!(
            second.get(at..at + 4),
            Some(original.to_le_bytes().as_slice()),
            "the vector layout"
        );
        second
            .get_mut(at..at + 4)
            .context("the type field")?
            .copy_from_slice(&kind.to_le_bytes());
        assert!(
            matches!(initiator.step(Some(&second)), Err(Negoex::InvalidChecksum)),
            "type {kind}"
        );
    }
    Ok(())
}

/// A replayed token and a reordered token are refused and fail the context.
#[test]
fn replayed_and_reordered_tokens_are_refused() -> Result<(), TestError> {
    let (mut initiator, mut acceptor, first, second) = first_tokens(3)?;
    // The acceptor saw token 0 already: the replay is out of sequence.
    let replay = acceptor
        .step(Some(&first))
        .err()
        .context("a replayed token must fail")?;
    assert!(
        matches!(
            replay,
            Negoex::MessageOutOfSequence {
                expected: _,
                actual: _
            }
        ),
        "{replay}"
    );
    assert!(matches!(
        acceptor.step(Some(&first)),
        Err(Negoex::UnexpectedStep(_))
    ));
    // The initiator takes the acceptor's token, then the same token again.
    drop(initiator.step(Some(&second))?);
    let again = initiator
        .step(Some(&second))
        .err()
        .context("the same token twice must fail")?;
    assert!(
        matches!(
            again,
            Negoex::MessageOutOfSequence {
                expected: _,
                actual: _
            }
        ),
        "{again}"
    );
    Ok(())
}

/// The first initiator step takes no token, and an acceptor needs one.
#[test]
fn step_preconditions_are_enforced() -> Result<(), TestError> {
    let registry = registry()?;
    let mechanisms: Vec<Arc<dyn Mechanism>> =
        vec![TestMechanism::shared(&OID_FIRST, Knobs::default())];
    let mut initiator = Context::initiator(&registry, &mechanisms, Request::new())?;
    assert!(matches!(
        initiator.step(Some(b"token")),
        Err(Negoex::UnexpectedStep(_))
    ));
    let mut acceptor = Context::acceptor(&registry, &mechanisms, Request::new())?;
    assert!(matches!(
        acceptor.step(None),
        Err(Negoex::InvalidMessageSize)
    ));
    let mut fresh = Context::acceptor(&registry, &mechanisms, Request::new())?;
    assert!(matches!(
        fresh.step(Some(&[0; 40])),
        Err(Negoex::InvalidMessageSize)
    ));
    Ok(())
}

/// Only registered, non-NTLM mechanisms with distinct schemes are negotiated.
#[test]
fn the_mechanism_policy_is_explicit() -> Result<(), TestError> {
    let knobs = Knobs::default();
    // An unregistered mechanism.
    let empty = Registry::new();
    let one: Vec<Arc<dyn Mechanism>> = vec![TestMechanism::shared(&OID_FIRST, knobs.clone())];
    assert!(matches!(
        Context::initiator(&empty, &one, Request::new()),
        Err(Negoex::UnregisteredMechanism(_))
    ));
    // No mechanism at all.
    assert!(matches!(
        Context::initiator(&registry()?, &[], Request::new()),
        Err(Negoex::NoAvailableMechs)
    ));
    // NTLMSSP, 1.3.6.1.4.1.311.2.2.10, is refused by name even when registered.
    let ntlm = [0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a];
    let mut registry = registry()?;
    let registered: Arc<dyn GssMechanism> = Arc::new(Registered {
        id: "ntlm".to_owned(),
        oid: ntlm.to_vec(),
    });
    registry.register(Extension::GssMechanism(registered))?;
    let ntlm_mechanism: Vec<Arc<dyn Mechanism>> = vec![TestMechanism::shared(&ntlm, knobs.clone())];
    assert!(matches!(
        Context::acceptor(&registry, &ntlm_mechanism, Request::new()),
        Err(Negoex::RejectedMechanism(_))
    ));
    // The same mechanism twice shares its scheme.
    let twice: Vec<Arc<dyn Mechanism>> = vec![
        TestMechanism::shared(&OID_FIRST, knobs.clone()),
        TestMechanism::shared(&OID_FIRST, knobs),
    ];
    assert!(matches!(
        Context::initiator(&registry, &twice, Request::new()),
        Err(Negoex::DuplicateScheme(_))
    ));
    Ok(())
}

/// A mechanism key of an encryption type the permanent policy rejects (single
/// DES) or the runtime policy has not enabled (RC4) fails the context.
#[test]
fn weak_mechanism_keys_are_refused() -> Result<(), TestError> {
    for etype in [1_i32, 23_i32, 16_i32] {
        let registry = registry()?;
        let knobs = Knobs {
            etype,
            key: KeyPolicy::Always,
            ..Knobs::default()
        };
        let mechanisms: Vec<Arc<dyn Mechanism>> = vec![TestMechanism::shared(&OID_FIRST, knobs)];
        let mut initiator = Context::initiator(&registry, &mechanisms, Request::new())?;
        let failure = initiator
            .step(None)
            .err()
            .context("a weak key must fail the first step")?;
        assert!(
            matches!(failure, Negoex::Policy(_)),
            "etype {etype}: {failure}"
        );
    }
    Ok(())
}
