//! SPNEGO over the GSS Kerberos mechanism.
//!
//! SPNEGO (RFC 4178) over the GSS Kerberos mechanism: `spnego::Initiator` and
//! `spnego::Acceptor` wrap the GSS context tokens and yield GSS contexts.

use rskrb5_ng::{
    error::{Gss, Spnego},
    gss::{self, AcceptorOptions, Credential, InitStep, InitiatorOptions},
    spnego::{self, AcceptStep, NegTokenInit, NegTokenResp, Token, oid::ObjectIdentifier},
};

use super::{
    context::{Context as _, TestError},
    support::{HOST, cache, cached, keytab, target, ticket_for},
};

/// An initiator credential holding a ticket for the default service.
fn credential() -> Result<Credential, TestError> {
    Ok(Credential::from_ccache(cache(vec![cached(&ticket_for(
        HOST,
        &[],
    )?)?]))?)
}

/// A SPNEGO initiator and acceptor establish GSS contexts that protect
/// messages both ways; the first token is a SPNEGO `NegTokenInit`.
#[test]
fn spnego_contexts_are_gss_contexts() -> Result<(), TestError> {
    let credential = credential()?;
    let mut initiator =
        spnego::Initiator::new(gss::Initiator::new(target(HOST)?, InitiatorOptions::new()));
    // Given the initiator's first token,
    let InitStep::Continue(first) = initiator.init_sec_context(&credential, None)? else {
        return Err("mutual authentication waits for the acceptor".into());
    };
    assert!(
        matches!(Token::decode(&first)?, Token::Init(_)),
        "a NegTokenInit"
    );
    // when the SPNEGO acceptor takes it,
    let store = Credential::from_keytab(keytab(&[HOST]));
    let mut acceptor = spnego::Acceptor::new(gss::Acceptor::new(&store, AcceptorOptions::new())?);
    let AcceptStep::Complete(accepted) = acceptor.accept_sec_context(&first)? else {
        return Err("an optimistic token completes the acceptor".into());
    };
    // then its answer completes the initiator,
    let answer = accepted.output_token().context("an answer")?.to_vec();
    assert!(
        matches!(Token::decode(&answer)?, Token::Resp(_)),
        "a NegTokenResp"
    );
    let InitStep::Complete(None) = initiator.init_sec_context(&credential, Some(&answer))? else {
        return Err("the answer completes the initiator".into());
    };
    // and both contexts protect messages.
    let mut ours = initiator.into_established()?;
    let mut theirs = accepted.into_context();
    let sealed = ours.wrap(b"through spnego", true)?;
    assert_eq!(theirs.unwrap(&sealed)?.message(), b"through spnego");
    let mic = theirs.get_mic(b"back")?;
    ours.verify_mic(b"back", &mic)?;
    Ok(())
}

/// A `NegTokenInit` without an optimistic token is answered `accept-incomplete`,
/// and the initiator's `NegTokenResp` with the token completes the context.
#[test]
fn a_negotiation_without_an_optimistic_token_continues() -> Result<(), TestError> {
    let credential = credential()?;
    let mut mechanism = gss::Initiator::new(target(HOST)?, InitiatorOptions::new());
    let InitStep::Continue(krb5) = mechanism.init_sec_context(&credential, None)? else {
        return Err("mutual authentication waits for the acceptor".into());
    };
    let mut offer = NegTokenInit::krb5(Vec::new());
    offer.set_mech_token(None);
    let store = Credential::from_keytab(keytab(&[HOST]));
    let mut acceptor = spnego::Acceptor::new(gss::Acceptor::new(&store, AcceptorOptions::new())?);
    // Given an offer without a token, the acceptor asks for it.
    let AcceptStep::Continue(incomplete) =
        acceptor.accept_sec_context(&Token::Init(offer).encode()?)?
    else {
        return Err("the acceptor waits for the token".into());
    };
    let Token::Resp(asked) = Token::decode(&incomplete)? else {
        return Err("a NegTokenResp".into());
    };
    assert_eq!(asked.supported_mech(), Some(&ObjectIdentifier::krb5()));
    // Given the token in a NegTokenResp, the context completes with an AP-REP.
    let next =
        Token::Resp(NegTokenResp::accept_incomplete_krb5().with_response_token(krb5)).encode()?;
    let AcceptStep::Complete(accepted) = acceptor.accept_sec_context(&next)? else {
        return Err("the token completes the acceptor".into());
    };
    assert!(accepted.output_token().is_some());
    Ok(())
}

/// A continuation nothing waits for, and a non-first Kerberos selection
/// without a MIC, are refused.
#[test]
fn unexpected_continuations_and_missing_mics_are_refused() -> Result<(), TestError> {
    let store = Credential::from_keytab(keytab(&[HOST]));
    let mut acceptor = spnego::Acceptor::new(gss::Acceptor::new(&store, AcceptorOptions::new())?);
    // Given a NegTokenResp out of the blue, the negotiation needs state it does not have.
    let stray =
        Token::Resp(NegTokenResp::accept_incomplete_krb5().with_response_token(vec![0x60, 0x00]))
            .encode()?;
    assert!(matches!(
        acceptor.accept_sec_context(&stray),
        Err(Gss::Spnego(Spnego::NegotiationRequiresState))
    ));
    // Given NTLM first and Kerberos second without a MIC, the selection is refused.
    let credential = credential()?;
    let mut mechanism = gss::Initiator::new(target(HOST)?, InitiatorOptions::new());
    let InitStep::Continue(krb5) = mechanism.init_sec_context(&credential, None)? else {
        return Err("mutual authentication waits for the acceptor".into());
    };
    let mut offer = NegTokenInit::krb5(krb5);
    offer.set_mech_types(vec![
        ObjectIdentifier::from_arcs(vec![1, 3, 6, 1, 4, 1, 311, 2, 2, 10])?,
        ObjectIdentifier::krb5(),
    ]);
    assert!(matches!(
        acceptor.accept_sec_context(&Token::Init(offer).encode()?),
        Err(Gss::Spnego(Spnego::MissingMechListMic))
    ));
    Ok(())
}
