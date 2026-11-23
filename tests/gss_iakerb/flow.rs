//! Context establishment through the relay: the initiator has no route to the
//! KDC, the acceptor relays its AS and TGS requests (MIT `iakerb.c:380-457`,
//! `:571-706`).

use rskrb5_ng::gss::{
    ContextFlags,
    iakerb::{IakerbContext, token::Token},
};

use super::{
    context::{Context as _, TestError},
    kdc::{Kdc, REALM, USER},
    support::{HOST, establish, password_credential},
};

/// The password initiator completes: the probe, the preauthenticated AS
/// request and the TGS request are relayed, then the AP exchange.
#[test]
fn a_password_initiator_completes_through_the_relay() -> Result<(), TestError> {
    // Given a KDC only the acceptor's relay reaches,
    let kdc = Kdc::new();
    // when the initiator establishes a context for HTTP@host,
    let mut pair = establish(&password_credential(true)?, &kdc)?;
    // then three requests were relayed, all for the realm: two AS, one TGS,
    assert_eq!(
        kdc.log(),
        [
            (REALM.to_owned(), "AS"),
            (REALM.to_owned(), "AS"),
            (REALM.to_owned(), "TGS")
        ]
    );
    assert!(pair.relayed.iter().all(|(realm, _)| realm == REALM));
    // and every token but the AP-REQ and the AP-REP is an IAKERB proxy token,
    let (proxy, rest) = pair.tokens.split_at(6);
    assert!(proxy.iter().all(|token| Token::is_iakerb(token)));
    // and the AP-REQ and AP-REP keep the IAKERB mechanism in their frame,
    assert_eq!(rest.len(), 2, "an AP-REQ and an AP-REP");
    for token in rest {
        assert!(
            token.get(..12).is_some_and(|head| head
                .windows(8)
                .any(|window| window == [0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x02, 0x05])),
            "the frame names the IAKERB mechanism"
        );
        assert!(!Token::is_iakerb(token), "not a proxy token");
    }
    // and both ends name both principals and protect messages.
    for context in [&pair.initiator, &pair.acceptor] {
        let info = context.inquire();
        assert_eq!(info.source().display().0, format!("{USER}@{REALM}"));
        assert_eq!(info.target().display().0, format!("HTTP/{HOST}@{REALM}"));
        assert!(info.open());
        assert!(info.flags().contains(ContextFlags::MUTUAL));
    }
    let sealed = pair.initiator.wrap(b"hello iakerb", true)?;
    assert_eq!(pair.acceptor.unwrap(&sealed)?.message(), b"hello iakerb");
    assert_eq!(IakerbContext::mechanism().arcs(), [1, 3, 6, 1, 5, 2, 5]);
    Ok(())
}

/// A client without a realm asks the acceptor for its realm first (MIT
/// `iakerb.c:616-634`): the first token is a discovery token, and the AS
/// request that follows is for the discovered realm.
#[test]
fn realm_discovery_fills_the_client_realm() -> Result<(), TestError> {
    let kdc = Kdc::new();
    let pair = establish(&password_credential(false)?, &kdc)?;
    // Given a first token that is an empty-realm, empty-message discovery,
    let first = Token::decode(pair.tokens.first().context("a first token")?)?;
    assert_eq!((first.realm(), first.message()), ("", &[][..]));
    // then the acceptor answered with its realm,
    let answer = Token::decode(pair.tokens.get(1).context("an answer")?)?;
    assert_eq!((answer.realm(), answer.message()), (REALM, &[][..]));
    // and the context names the client in that realm, with the discovery
    // tokens part of the transcript the AP-REQ's checksum covers.
    assert_eq!(
        pair.initiator.inquire().source().display().0,
        format!("{USER}@{REALM}")
    );
    assert_eq!(pair.relayed.len(), 3);
    Ok(())
}
