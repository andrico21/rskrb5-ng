//! The relay policy: the acceptor relays only what its policy names, and never
//! for a request that is not an AS-REQ or TGS-REQ of the named realm.

use rskrb5_ng::{
    error::Iakerb,
    gss::{
        Acceptor, AcceptorOptions, Credential, InitStep, InitiatorOptions,
        iakerb::{AcceptStep, Context, KdcRelay, RelayFailure, RelayPolicy, token::Token},
    },
    krb_error,
};

use super::{
    context::TestError,
    kdc::{Kdc, REALM, Relay},
    support::{NoRelay, config, keytab, password_credential, policy, target},
};

/// The first token of a password initiator: a realm-less probe AS-REQ.
fn first_request() -> Result<Token, TestError> {
    let credential = password_credential(true)?;
    let mut initiator = Context::initiator(&config()?, target()?, InitiatorOptions::new())?;
    let InitStep::Continue(token) = initiator.init_sec_context(&credential, None)? else {
        return Err("the first step sends a relay token".into());
    };
    Ok(Token::decode(&token)?)
}

/// One acceptor step over `token` under `policy` and `relay`.
fn accept(
    policy: RelayPolicy,
    relay: &mut dyn KdcRelay,
    token: &[u8],
) -> Result<AcceptStep, Iakerb> {
    let store = Credential::from_keytab(keytab());
    let mut acceptor = Acceptor::new(&store, AcceptorOptions::new())
        .map_err(|_failure| Iakerb::UnexpectedStep("the acceptor is built"))?;
    Context::acceptor(policy).accept_sec_context(&mut acceptor, relay, token)
}

/// A request for a realm outside the policy is refused and never reaches the relay.
#[test]
fn a_relay_request_for_a_realm_outside_the_policy_is_refused() -> Result<(), TestError> {
    // Given a policy that names EXAMPLE.COM only and a valid AS-REQ,
    let request = first_request()?;
    let outside = Token::new("OTHER.EXAMPLE", None, request.message().to_vec()).encode()?;
    // when the initiator asks for another realm,
    let mut relay = NoRelay::default();
    let outcome = accept(policy()?, &mut relay, &outside);
    // then the acceptor refuses, naming the realm, and the relay is not called.
    assert!(
        matches!(&outcome, Err(Iakerb::RealmNotPermitted(realm)) if realm == "OTHER.EXAMPLE"),
        "{outcome:?}"
    );
    assert_eq!(relay.calls, 0);
    Ok(())
}

/// A realm the policy names is relayed, and the answer is a token for it.
#[test]
fn a_second_named_realm_is_relayed() -> Result<(), TestError> {
    // Given a policy naming a second realm, and a request whose body is for it,
    let request = first_request()?;
    let both = policy()?.with_realm("OTHER.EXAMPLE")?;
    assert!(both.permits("OTHER.EXAMPLE") && both.permits(REALM));
    // when the header names the second realm but the body is for EXAMPLE.COM,
    let mismatch = Token::new("OTHER.EXAMPLE", None, request.message().to_vec()).encode()?;
    let mut relay = NoRelay::default();
    // then the request is refused as not being for the realm of its header.
    assert!(matches!(
        accept(both, &mut relay, &mismatch),
        Err(Iakerb::RequestRefused(_))
    ));
    assert_eq!(relay.calls, 0);
    Ok(())
}

/// A message that is not an AS-REQ or TGS-REQ is not relayed, so the acceptor
/// cannot be used as an open proxy.
#[test]
fn a_request_that_is_not_a_kdc_request_is_refused() -> Result<(), TestError> {
    let mut relay = NoRelay::default();
    for message in [
        b"GET / HTTP/1.1\r\n\r\n".to_vec(),
        vec![0x6a, 0x03, 0x01],
        vec![0x6e, 0x00],
        vec![0x6a, 0x00],
    ] {
        let token = Token::new(REALM, None, message).encode()?;
        let outcome = accept(policy()?, &mut relay, &token);
        assert!(
            matches!(outcome, Err(Iakerb::RequestRefused(_))),
            "{outcome:?}"
        );
    }
    assert_eq!(relay.calls, 0);
    Ok(())
}

/// A token with a realm and no message, or a message and no realm, is
/// malformed (MIT `KRB5_BAD_MSIZE`).
#[test]
fn a_half_empty_token_is_malformed() -> Result<(), TestError> {
    let request = first_request()?;
    let mut relay = NoRelay::default();
    for token in [
        Token::new(REALM, None, Vec::new()),
        Token::new("", None, request.message().to_vec()),
    ] {
        let outcome = accept(policy()?, &mut relay, &token.encode()?);
        assert!(matches!(outcome, Err(Iakerb::BadToken(_))), "{outcome:?}");
    }
    Ok(())
}

/// A discovery token is answered with the acceptor's own realm, no relay.
#[test]
fn realm_discovery_answers_the_local_realm_without_relaying() -> Result<(), TestError> {
    let mut relay = NoRelay::default();
    let discovery = Token::new("", None, Vec::new()).encode()?;
    let AcceptStep::Continue(answer) = accept(policy()?, &mut relay, &discovery)? else {
        return Err("discovery continues".into());
    };
    let decoded = Token::decode(&answer)?;
    assert_eq!((decoded.realm(), decoded.message()), (REALM, &[][..]));
    assert_eq!(relay.calls, 0);
    Ok(())
}

/// The acceptor produces at most `max_rounds` tokens.
#[test]
fn rounds_are_bounded() -> Result<(), TestError> {
    let kdc = Kdc::new();
    let request = first_request()?.encode()?;
    let store = Credential::from_keytab(keytab());
    let mut acceptor = Acceptor::new(&store, AcceptorOptions::new())?;
    let mut context = Context::acceptor(policy()?.with_max_rounds(2));
    let mut relay = Relay::new(&kdc);
    for _round in 0_u8..2 {
        assert!(matches!(
            context.accept_sec_context(&mut acceptor, &mut relay, &request)?,
            AcceptStep::Continue(_)
        ));
    }
    let third = context.accept_sec_context(&mut acceptor, &mut relay, &request);
    assert!(
        matches!(third, Err(Iakerb::RoundLimit { maximum: 2 })),
        "{third:?}"
    );
    assert_eq!(relay.asked.len(), 2, "the third request was not relayed");
    Ok(())
}

/// A token above the message bound and a transcript above its bound are refused.
#[test]
fn bytes_are_bounded() -> Result<(), TestError> {
    let kdc = Kdc::new();
    let request = first_request()?.encode()?;
    let mut relay = Relay::new(&kdc);
    let small = policy()?.with_max_message_bytes(request.len().saturating_sub(1));
    assert!(matches!(
        accept(small, &mut relay, &request),
        Err(Iakerb::TokenTooLarge {
            maximum: _,
            actual: _
        })
    ));
    let tiny = policy()?.with_max_transcript_bytes(request.len());
    let outcome = accept(tiny, &mut relay, &request);
    assert!(
        matches!(outcome, Err(Iakerb::TranscriptTooLarge { maximum: _ })),
        "the request and its answer exceed the transcript bound: {outcome:?}"
    );
    Ok(())
}

/// A policy needs a realm, a short one, and at most sixteen.
#[test]
fn policies_reject_empty_long_and_too_many_realms() -> Result<(), TestError> {
    assert!(matches!(
        RelayPolicy::new(""),
        Err(Iakerb::InvalidPolicy(_))
    ));
    assert!(matches!(
        RelayPolicy::new(&"R".repeat(256)),
        Err(Iakerb::InvalidPolicy(_))
    ));
    let mut policy = RelayPolicy::new("A.EXAMPLE")?;
    for index in 1..RelayPolicy::MAX_REALMS {
        policy = policy.with_realm(&format!("R{index}.EXAMPLE"))?;
    }
    assert!(matches!(
        policy.clone().with_realm("EXTRA.EXAMPLE"),
        Err(Iakerb::InvalidPolicy(_))
    ));
    assert!(!policy.permits("example.com"), "realms match exactly");
    Ok(())
}

/// A KDC the relay cannot reach, or a realm it does not know, is answered with
/// MIT's IAKERB errors; any other failure ends the acceptor's step.
///
/// The initiator reports `KRB_AP_ERR_IAKERB_KDC_NO_RESPONSE` and
/// `KRB_AP_ERR_IAKERB_KDC_NOT_FOUND`.
#[test]
fn relay_failures_answer_with_iakerb_errors() -> Result<(), TestError> {
    let kdc = Kdc::new();
    let credential = password_credential(true)?;
    for (failure, expected) in [
        (RelayFailure::KdcUnreachable, 86_i32),
        (RelayFailure::RealmUnknown, 85_i32),
    ] {
        let mut initiator = Context::initiator(&config()?, target()?, InitiatorOptions::new())?;
        let InitStep::Continue(first) = initiator.init_sec_context(&credential, None)? else {
            return Err("the first step sends a relay token".into());
        };
        let mut relay = Relay::new(&kdc);
        relay.failure = Some(failure);
        let AcceptStep::Continue(answer) = accept(policy()?, &mut relay, &first)? else {
            return Err("the failure is answered, not raised".into());
        };
        let message = Token::decode(&answer)?;
        let error = krb_error::decode(message.message())?;
        assert_eq!(error.error_code, expected);
        let reported = initiator.init_sec_context(&credential, Some(&answer));
        assert!(
            matches!(
                (&reported, expected),
                (Err(Iakerb::KdcNoResponse), 86_i32) | (Err(Iakerb::KdcNotFound), 85_i32)
            ),
            "{reported:?}"
        );
    }
    let mut initiator = Context::initiator(&config()?, target()?, InitiatorOptions::new())?;
    let InitStep::Continue(first) = initiator.init_sec_context(&credential, None)? else {
        return Err("the first step sends a relay token".into());
    };
    let mut relay = Relay::new(&kdc);
    relay.failure = Some(RelayFailure::Other("boom".to_owned()));
    let failed = accept(policy()?, &mut relay, &first);
    assert!(
        matches!(&failed, Err(Iakerb::RelayFailed(text)) if text == "boom"),
        "{failed:?}"
    );
    Ok(())
}

/// A relay answer that is not a KDC reply is not passed to the initiator.
#[test]
fn a_relay_answer_that_is_not_a_kdc_reply_is_refused() -> Result<(), TestError> {
    /// A relay that answers with a web page.
    struct Junk;
    impl KdcRelay for Junk {
        fn relay(&mut self, _realm: &str, _request: &[u8]) -> Result<Vec<u8>, RelayFailure> {
            Ok(b"HTTP/1.1 200 OK\r\n\r\n".to_vec())
        }
    }
    let first = first_request()?.encode()?;
    let outcome = accept(policy()?, &mut Junk, &first);
    assert!(
        matches!(outcome, Err(Iakerb::BadRelayReply(_))),
        "{outcome:?}"
    );
    Ok(())
}
