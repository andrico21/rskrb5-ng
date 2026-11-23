//! Malformed, reordered and out-of-turn tokens are errors, never panics.

use rskrb5_ng::{
    error::Iakerb,
    gss::{
        Acceptor, AcceptorOptions, Credential, InitStep, InitiatorOptions,
        iakerb::{AcceptStep, IakerbContext, token::Token},
    },
};

use super::{
    context::TestError,
    kdc::{Kdc, REALM},
    support::{NoRelay, config, establish, keytab, password_credential, policy, target},
};

/// Inputs no IAKERB end accepts.
fn garbage() -> Vec<Vec<u8>> {
    vec![
        Vec::new(),
        vec![0],
        vec![0x60],
        vec![0x60, 0x00],
        vec![0x60, 0x80],
        vec![0x60, 0x84, 0xff, 0xff, 0xff, 0xff],
        vec![0x6e, 0x03, 0x01, 0x02, 0x03],
        b"GET / HTTP/1.1\r\n\r\n".to_vec(),
        vec![0xff; 64],
    ]
}

/// The acceptor and the initiator refuse every garbage input and every prefix
/// of a valid token.
#[test]
fn garbage_is_refused_by_both_ends() -> Result<(), TestError> {
    let kdc = Kdc::new();
    let credential = password_credential(true)?;
    let pair = establish(&credential, &kdc)?;
    let mut inputs = garbage();
    for token in &pair.tokens {
        inputs.extend((0..token.len()).map(|end| token.get(..end).unwrap_or_default().to_vec()));
    }
    let store = Credential::from_keytab(keytab());
    for input in &inputs {
        let mut acceptor = Acceptor::new(&store, AcceptorOptions::new())?;
        let outcome = IakerbContext::acceptor(policy()?).accept_sec_context(
            &mut acceptor,
            &mut NoRelay::default(),
            input,
        );
        assert!(
            !matches!(outcome, Ok(AcceptStep::Complete(_))),
            "the acceptor established a context from {} bytes",
            input.len()
        );
        let mut initiator =
            IakerbContext::initiator(&config()?, target()?, InitiatorOptions::new())?;
        drop(initiator.init_sec_context(&credential, None)?);
        assert!(
            initiator.init_sec_context(&credential, Some(input)).is_err(),
            "the initiator took {} bytes",
            input.len()
        );
    }
    Ok(())
}

/// A step out of turn is an error: a token before the first step, a first step
/// with a token, and anything after the context is established.
#[test]
fn steps_out_of_turn_are_errors() -> Result<(), TestError> {
    let kdc = Kdc::new();
    let credential = password_credential(true)?;
    let mut fresh = IakerbContext::initiator(&config()?, target()?, InitiatorOptions::new())?;
    let token = Token::new(REALM, None, vec![0x6b, 0x00]).encode()?;
    assert!(matches!(
        fresh.init_sec_context(&credential, Some(&token)),
        Err(Iakerb::UnexpectedStep(_))
    ));
    assert!(matches!(fresh.into_established(), Err(Iakerb::UnexpectedStep(_))));
    // Given a finished acceptor context,
    let store = Credential::from_keytab(keytab());
    let mut acceptor = Acceptor::new(&store, AcceptorOptions::new())?;
    let mut context = IakerbContext::acceptor(policy()?);
    let mut initiator = IakerbContext::initiator(&config()?, target()?, InitiatorOptions::new())?;
    let mut relay = super::kdc::Relay::new(&kdc);
    let InitStep::Continue(mut next) = initiator.init_sec_context(&credential, None)? else {
        return Err("the first step sends a relay token".into());
    };
    loop {
        match context.accept_sec_context(&mut acceptor, &mut relay, &next)? {
            AcceptStep::Continue(reply) => {
                next = match initiator.init_sec_context(&credential, Some(&reply))? {
                    InitStep::Continue(token) | InitStep::Complete(Some(token)) => token,
                    _ => return Err("the initiator keeps sending".into()),
                };
            }
            AcceptStep::Complete(_) => break,
            _ => return Err("an unknown step".into()),
        }
    }
    // then another token is out of turn, as is a second AP-REQ.
    let again = context.accept_sec_context(&mut acceptor, &mut relay, &next);
    assert!(matches!(again, Err(Iakerb::UnexpectedStep(_))), "{again:?}");
    let _unused = IakerbContext::acceptor(policy()?).is_established();
    Ok(())
}

/// A reply delivered to the wrong request is refused by the initiator's own
/// exchange: the second probe answer cannot stand in for the first.
#[test]
fn a_reordered_reply_is_refused() -> Result<(), TestError> {
    let kdc = Kdc::new();
    let credential = password_credential(true)?;
    let outcome = super::support::establish_with(&credential, &kdc, policy()?, |turn, token| {
        // Replace the first answer with a discovery-looking token without a message.
        if turn == 0 {
            return Ok(Token::new(REALM, None, Vec::new()).encode()?);
        }
        Ok(token)
    });
    assert!(outcome.is_err(), "a reply without a KDC message must not complete the exchange");
    Ok(())
}
