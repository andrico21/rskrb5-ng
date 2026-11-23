//! `NegoEx` under SPNEGO (RFC 4178): the `NegoEx` OID in the mechanism list, the
//! `NegoEx` messages in the mechanism tokens and the acceptor's states, as in
//! MIT 1.22.2 `spnego_mech.c` (`get_negotiable_mechs`, `acc_ctx_new`, `init_ctx_cont`).

use std::sync::Arc;

use rskrb5_ng::{
    error::{Gss, Negoex, Spnego},
    extensions::{Extension, Registry},
    gss::{
        InitStep,
        negoex::{Context, Mechanism, Request},
    },
    spnego::{
        NegState, NegTokenInit, NegTokenResp, Token,
        negoex::{AcceptStep, Acceptor, Initiator},
        oid::ObjectIdentifier,
    },
};

use super::{
    context::{Context as _, TestError},
    negoextest::{Knobs, OID_FIRST, OID_SECOND, Registered, TestMechanism},
};

/// `NegoEx` message signature.
const SIGNATURE: &[u8] = b"NEGOEXTS";

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

/// `NegoEx` contexts of `hops` hops, offering both mechanisms.
fn contexts(hops: u8) -> Result<(Context, Context), TestError> {
    let registry = registry()?;
    let knobs = Knobs {
        hops,
        ..Knobs::default()
    };
    let mechanisms: Vec<Arc<dyn Mechanism>> = vec![
        TestMechanism::new(&OID_FIRST, knobs.clone()),
        TestMechanism::new(&OID_SECOND, knobs),
    ];
    Ok((
        Context::initiator(&registry, &mechanisms, Request::new())?,
        Context::acceptor(&registry, &mechanisms, Request::new())?,
    ))
}

/// The first `NegTokenInit` of an initiator, decoded.
fn init_token(bytes: &[u8]) -> Result<NegTokenInit, TestError> {
    match Token::decode(bytes)? {
        Token::Init(init) => Ok(init),
        other => Err(format!("a NegTokenInit was expected, got {other:?}").into()),
    }
}

/// A `NegTokenResp`, decoded.
fn resp_token(bytes: &[u8]) -> Result<NegTokenResp, TestError> {
    Ok(NegTokenResp::decode(bytes)?)
}

/// One hop: the `NegoEx` OID is the offered mechanism list, the mechanism token
/// holds `NEGOEX` messages, the acceptor completes at once with `accept-completed`
/// and the `NegoEx` answer, and the initiator completes on it.
#[test]
fn one_hop_negotiation_completes() -> Result<(), TestError> {
    let (ours, theirs) = contexts(1)?;
    let mut initiator = Initiator::new(ours);
    let mut acceptor = Acceptor::new(theirs);
    let InitStep::Continue(first) = initiator.init_sec_context(None)? else {
        return Err("the initiator waits for the acceptor".into());
    };
    let init = init_token(&first)?;
    assert_eq!(init.mech_types(), &[ObjectIdentifier::negoex()]);
    assert!(
        init.mech_token().is_some_and(|token| token.starts_with(SIGNATURE)),
        "the mechanism token is the NegoEx INITIATOR_NEGO..VERIFY run"
    );
    let AcceptStep::Complete(accepted) = acceptor.accept_sec_context(&first)? else {
        return Err("one hop completes the acceptor".into());
    };
    let answer = accepted.output_token().context("an answer")?.to_vec();
    let resp = resp_token(&answer)?;
    assert_eq!(resp.neg_state(), Some(NegState::AcceptCompleted));
    assert_eq!(resp.supported_mech(), Some(&ObjectIdentifier::negoex()));
    assert!(resp.response_token().is_some_and(|token| token.starts_with(SIGNATURE)));
    assert_eq!(
        accepted.mechanism().oid().arcs(),
        &[2, 25, 1_414_534_758],
        "the first mechanism was selected"
    );
    let InitStep::Complete(None) = initiator.init_sec_context(Some(&answer))? else {
        return Err("the answer completes the initiator".into());
    };
    let _session = initiator.into_session()?;
    let _theirs = accepted.into_session();
    Ok(())
}

/// Three hops: each side's step carries a `NegTokenResp` with `accept-incomplete`
/// until the mechanism and the `VERIFY` exchange end; the acceptor's first reply
/// names the mechanism and the later ones do not.
#[test]
fn multi_hop_negotiation_continues() -> Result<(), TestError> {
    let (ours, theirs) = contexts(3)?;
    let mut initiator = Initiator::new(ours);
    let mut acceptor = Acceptor::new(theirs);
    let InitStep::Continue(mut token) = initiator.init_sec_context(None)? else {
        return Err("the first token".into());
    };
    let mut accepted = None;
    let mut replies = 0_usize;
    for _ in 0..10 {
        match acceptor.accept_sec_context(&token)? {
            AcceptStep::Continue(reply) => {
                let resp = resp_token(&reply)?;
                assert_eq!(resp.neg_state(), Some(NegState::AcceptIncomplete));
                assert_eq!(
                    resp.supported_mech().is_some(),
                    replies == 0,
                    "only the first reply names the mechanism"
                );
                replies += 1;
                token = reply;
            }
            AcceptStep::Complete(done) => {
                token = done.output_token().context("a final answer")?.to_vec();
                accepted = Some(done);
            }
            _ => return Err("an unexpected acceptor step".into()),
        }
        match initiator.init_sec_context(Some(&token))? {
            InitStep::Continue(next) => token = next,
            InitStep::Complete(None) => break,
            InitStep::Complete(Some(_)) | _ => return Err("unexpected initiator step".into()),
        }
    }
    assert!(accepted.is_some(), "the acceptor completed");
    let _session = initiator.into_session()?;
    Ok(())
}

/// The acceptor refuses an offer that lacks the `NegoEx` OID.
#[test]
fn an_offer_without_negoex_is_refused() -> Result<(), TestError> {
    let (_ours, theirs) = contexts(1)?;
    let mut acceptor = Acceptor::new(theirs);
    let kerberos_only = Token::Init(NegTokenInit::krb5(vec![1, 2, 3])).encode()?;
    let failure = acceptor
        .accept_sec_context(&kerberos_only)
        .err()
        .context("a Kerberos-only offer is not a NegoEx offer")?;
    assert!(
        matches!(failure, Gss::Spnego(Spnego::UnsupportedMechanism(_))),
        "{failure}"
    );
    Ok(())
}

/// A `NegoEx` OID listed after another mechanism is selected with `request-mic`
/// and no token, and the initiator's `NegTokenResp` carries the first `NegoEx` token.
#[test]
fn a_later_offer_requests_a_mic_and_reselects() -> Result<(), TestError> {
    let (ours, theirs) = contexts(1)?;
    let mut initiator = Initiator::new(ours);
    let mut acceptor = Acceptor::new(theirs);
    let InitStep::Continue(first) = initiator.init_sec_context(None)? else {
        return Err("the first token".into());
    };
    let mut init = init_token(&first)?;
    let nego = init.mech_token().context("the token")?.to_vec();
    init.set_mech_types(vec![ObjectIdentifier::krb5(), ObjectIdentifier::negoex()]);
    init.set_mech_token(Some(vec![0x60, 0x00].into()));
    let AcceptStep::Continue(reply) = acceptor.accept_sec_context(&Token::Init(init).encode()?)?
    else {
        return Err("a later selection waits for the initiator's token".into());
    };
    let resp = resp_token(&reply)?;
    assert_eq!(resp.neg_state(), Some(NegState::RequestMic));
    assert_eq!(resp.supported_mech(), Some(&ObjectIdentifier::negoex()));
    assert!(resp.response_token().is_none());
    let mut next = NegTokenResp::reject();
    next.set_neg_state(Some(NegState::AcceptIncomplete));
    next.set_supported_mech(None);
    next.set_response_token(Some(nego.into()));
    let AcceptStep::Complete(_) = acceptor.accept_sec_context(&next.encode()?)? else {
        return Err("the NegoEx token completes one hop".into());
    };
    Ok(())
}

/// A `NegTokenResp` that rejects, names another mechanism or reports an
/// incomplete state after completion is refused by the initiator.
#[test]
fn the_initiator_refuses_bad_answers() -> Result<(), TestError> {
    let (ours, _theirs) = contexts(1)?;
    let mut initiator = Initiator::new(ours);
    let InitStep::Continue(_first) = initiator.init_sec_context(None)? else {
        return Err("the first token".into());
    };
    let reject = NegTokenResp::reject().encode()?;
    assert!(initiator.init_sec_context(Some(&reject)).is_err(), "reject");
    let (ours, _theirs) = contexts(1)?;
    let mut initiator = Initiator::new(ours);
    drop(initiator.init_sec_context(None)?);
    let mut other = NegTokenResp::accept_completed();
    other.set_supported_mech(Some(ObjectIdentifier::krb5()));
    other.set_response_token(Some(vec![1].into()));
    let failure = initiator
        .init_sec_context(Some(&other.encode()?))
        .err()
        .context("another mechanism was not offered")?;
    assert!(
        matches!(failure, Gss::Spnego(Spnego::UnsupportedMechanism(_))),
        "{failure}"
    );
    Ok(())
}

/// QA failure scenario through SPNEGO: a `VERIFY` message with a wrong checksum in
/// the acceptor's response token fails the initiator's context.
#[test]
fn a_wrong_verify_checksum_fails_through_spnego() -> Result<(), TestError> {
    let (ours, theirs) = contexts(1)?;
    let mut initiator = Initiator::new(ours);
    let mut acceptor = Acceptor::new(theirs);
    let InitStep::Continue(first) = initiator.init_sec_context(None)? else {
        return Err("the first token".into());
    };
    let AcceptStep::Complete(accepted) = acceptor.accept_sec_context(&first)? else {
        return Err("one hop completes the acceptor".into());
    };
    let mut resp = resp_token(accepted.output_token().context("an answer")?)?;
    let mut token = resp.response_token().context("a token")?.to_vec();
    let last = token.len() - 1;
    *token.get_mut(last).context("a byte")? ^= 0x01;
    resp.set_response_token(Some(token.into()));
    let failure = initiator
        .init_sec_context(Some(&resp.encode()?))
        .err()
        .context("a wrong checksum must fail")?;
    assert!(matches!(failure, Gss::Negoex(Negoex::InvalidChecksum)), "{failure}");
    assert!(initiator.into_session().is_err(), "no session after a failure");
    Ok(())
}
