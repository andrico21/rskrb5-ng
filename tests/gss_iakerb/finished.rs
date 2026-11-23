//! The transcript checksum: the AP-REQ's authenticator carries an
//! `IAKERB-FINISHED` over every IAKERB token of the exchange, under the
//! initiator's subkey, which the acceptor verifies (MIT `iakerb.c:125-181`,
//! `accept_sec_context.c:381-394, 850-853`).

use rskrb5_ng::{
    error::Iakerb,
    gss::{
        Acceptor, AcceptorOptions, Credential,
        iakerb::{AcceptStep, IakerbContext, token::Token},
    },
};

use super::{
    context::{Context as _, TestError},
    kdc::{Kdc, service_key},
    support::{
        NoRelay, ap_req_token, establish_with, finished, keytab, password_credential, policy,
        subkey,
    },
};

/// Run a discovery exchange (two tokens), then hand the acceptor the AP-REQ
/// that `make` builds from the transcript those tokens form.
fn after_discovery(
    make: impl FnOnce(&[u8]) -> Result<Vec<u8>, TestError>,
) -> Result<Result<AcceptStep, Iakerb>, TestError> {
    let store = Credential::from_keytab(keytab());
    let mut acceptor = Acceptor::new(&store, AcceptorOptions::new())?;
    let mut context = IakerbContext::acceptor(policy()?);
    let mut relay = NoRelay::default();
    let discovery = Token::new("", None, Vec::new()).encode()?;
    let AcceptStep::Continue(answer) =
        context.accept_sec_context(&mut acceptor, &mut relay, &discovery)?
    else {
        return Err("discovery continues".into());
    };
    let transcript = [discovery, answer].concat();
    Ok(context.accept_sec_context(&mut acceptor, &mut relay, &make(&transcript)?))
}

/// An AP-REQ whose `IAKERB-FINISHED` covers the transcript under the subkey is
/// accepted: the checksum construction is MIT's, built here independently.
#[test]
fn a_finished_over_the_transcript_under_the_subkey_is_accepted() -> Result<(), TestError> {
    let outcome = after_discovery(|transcript| {
        ap_req_token(Some(&finished(&subkey(), transcript)?))
    })?;
    assert!(matches!(outcome, Ok(AcceptStep::Complete(_))), "{outcome:?}");
    Ok(())
}

/// A finished over another transcript, under the session key instead of the
/// subkey, or after tokens were left out is refused (`GSS_S_BAD_SIG`).
#[test]
fn a_finished_that_does_not_match_is_refused() -> Result<(), TestError> {
    let wrong_transcript = after_discovery(|transcript| {
        let shorter = transcript.get(1..).context("a transcript")?;
        ap_req_token(Some(&finished(&subkey(), shorter)?))
    })?;
    assert!(matches!(wrong_transcript, Err(Iakerb::BadFinished)), "{wrong_transcript:?}");
    let wrong_key = after_discovery(|transcript| {
        ap_req_token(Some(&finished(&service_key("session"), transcript)?))
    })?;
    assert!(matches!(wrong_key, Err(Iakerb::BadFinished)), "{wrong_key:?}");
    let garbage = after_discovery(|_transcript| ap_req_token(Some(&[0x30, 0x00])))?;
    assert!(matches!(garbage, Err(Iakerb::BadFinished)), "{garbage:?}");
    Ok(())
}

/// After IAKERB tokens an AP-REQ without a finished is refused (`GSS_S_BAD_SIG`).
#[test]
fn an_ap_req_without_a_finished_after_an_exchange_is_refused() -> Result<(), TestError> {
    let outcome = after_discovery(|_transcript| ap_req_token(None))?;
    assert!(matches!(outcome, Err(Iakerb::MissingFinished)), "{outcome:?}");
    Ok(())
}

/// Without an IAKERB exchange (a ticket the initiator already held), an
/// AP-REQ is accepted without a finished and refused with one (MIT
/// `KRB5KRB_AP_ERR_MSG_TYPE`).
#[test]
fn a_finished_without_an_exchange_is_refused_and_none_is_accepted() -> Result<(), TestError> {
    let store = Credential::from_keytab(keytab());
    for (extension, accepted) in [(None, true), (Some(finished(&subkey(), b"x")?), false)] {
        let mut acceptor = Acceptor::new(&store, AcceptorOptions::new())?;
        let outcome = IakerbContext::acceptor(policy()?).accept_sec_context(
            &mut acceptor,
            &mut NoRelay::default(),
            &ap_req_token(extension.as_deref())?,
        );
        if accepted {
            assert!(matches!(outcome, Ok(AcceptStep::Complete(_))), "{outcome:?}");
        } else {
            assert!(matches!(outcome, Err(Iakerb::UnexpectedFinished)), "{outcome:?}");
        }
    }
    Ok(())
}

/// A proxy token changed in flight (here: a cookie added to the acceptor's
/// first answer, which the initiator echoes) makes the two transcripts differ,
/// so the acceptor refuses the context at the AP-REQ.
#[test]
fn a_token_changed_in_flight_fails_the_finished_check() -> Result<(), TestError> {
    let kdc = Kdc::new();
    let outcome = establish_with(&password_credential(true)?, &kdc, policy()?, |turn, token| {
        if turn != 0 {
            return Ok(token);
        }
        let decoded = Token::decode(&token)?;
        Ok(Token::new(decoded.realm(), Some(b"injected".to_vec()), decoded.message().to_vec())
            .encode()?)
    });
    let error = outcome.err().context("the context must not establish")?;
    assert!(
        matches!(error.downcast_ref::<Iakerb>(), Some(Iakerb::BadFinished)),
        "{error}"
    );
    Ok(())
}
