//! Context establishment between the crate's GSS initiator and acceptor: one
//! AP-REQ and, with mutual authentication, one AP-REP (RFC 4121 section 4.1;
//! MIT `init_sec_context.c:470-688`, `accept_sec_context.c:665-1150`).

use rskrb5_ng::{
    error::{Gss, Service},
    gss::{
        Acceptor, AcceptorOptions, ContextFlags, Credential, InitStep, Initiator, InitiatorOptions,
        Name, NameType,
    },
    spnego::oid::ObjectIdentifier,
};

use super::{
    context::{Context as _, TestError},
    support::{HOST, REALM, USER, cache, cached, establish, keytab, target, ticket_for},
};

/// An initiator credential holding a ticket for the default service.
fn credential() -> Result<Credential, TestError> {
    Ok(Credential::from_ccache(cache(vec![cached(&ticket_for(
        HOST,
        &[],
    )?)?]))?)
}

/// A mutual context completes with one AP-REP; both ends name both principals,
/// the krb5 mechanism and the negotiated protections.
#[test]
fn mutual_contexts_establish_and_name_both_ends() -> Result<(), TestError> {
    // Given an initiator asking for mutual authentication, sequencing, replay
    // detection, confidentiality and integrity,
    let pair = establish(
        &credential()?,
        InitiatorOptions::new(),
        (AcceptorOptions::new(), &[HOST], None),
    )?;
    // then the acceptor answered with an AP-REP token,
    assert!(
        pair.reply.is_some(),
        "mutual authentication sends an AP-REP"
    );
    let client = format!("{USER}@{REALM}");
    let service = format!("HTTP/{HOST}@{REALM}");
    // and both ends describe the same context.
    for (context, initiated) in [(&pair.initiator, true), (&pair.acceptor, false)] {
        let info = context.inquire();
        assert_eq!(info.source().display().0, client);
        assert_eq!(info.target().display().0, service);
        assert_eq!(info.locally_initiated(), initiated);
        assert!(info.open(), "the context is established");
        assert_eq!(info.mechanism(), &ObjectIdentifier::krb5());
        assert!(info.flags().contains(
            ContextFlags::MUTUAL
                | ContextFlags::SEQUENCE
                | ContextFlags::REPLAY
                | ContextFlags::CONF
                | ContextFlags::INTEG
        ));
        assert!(
            !info.flags().contains(ContextFlags::DELEG),
            "nothing was delegated"
        );
        assert_eq!(info.key_etype(), 18, "the AES256 context key");
    }
    assert!(
        pair.initiator.inquire().expires() > std::time::SystemTime::now(),
        "the context lives as long as its ticket"
    );
    Ok(())
}

/// Without mutual authentication the first token completes both ends and the
/// acceptor sends nothing.
#[test]
fn contexts_without_mutual_authentication_take_one_token() -> Result<(), TestError> {
    // Given an initiator that does not ask for mutual authentication,
    let options = InitiatorOptions::new().with_flags(ContextFlags::INTEG | ContextFlags::CONF);
    let pair = establish(
        &credential()?,
        options,
        (AcceptorOptions::new(), &[HOST], None),
    )?;
    // then the acceptor sends no token and neither end reports mutual authentication.
    assert!(pair.reply.is_none());
    assert!(
        !pair
            .acceptor
            .inquire()
            .flags()
            .contains(ContextFlags::MUTUAL)
    );
    assert!(
        !pair
            .initiator
            .inquire()
            .flags()
            .contains(ContextFlags::MUTUAL)
    );
    Ok(())
}

/// The initiator refuses a credential without a ticket for the target, and a
/// host-based target without a host.
#[test]
fn initiators_need_a_ticket_and_a_host() -> Result<(), TestError> {
    // Given a credential holding a ticket for another host,
    let other =
        Credential::from_ccache(cache(vec![cached(&ticket_for("other.example.com", &[])?)?]))?;
    let mut initiator = Initiator::new(target(HOST)?, InitiatorOptions::new());
    // when the context starts, then there is no credential for the target.
    assert!(matches!(
        initiator.init_sec_context(&other, None),
        Err(Gss::NoCredential(_))
    ));
    // Given a host-based target with no host, it is a bad name.
    let mut hostless = Initiator::new(
        Name::import(b"HTTP", NameType::HostbasedService)?,
        InitiatorOptions::new(),
    );
    assert!(matches!(
        hostless.init_sec_context(&credential()?, None),
        Err(Gss::BadName(_))
    ));
    Ok(())
}

/// Steps out of order are refused: an established initiator takes no token
/// and an unfinished one cannot yield a context.
#[test]
fn steps_out_of_order_are_refused() -> Result<(), TestError> {
    let credential = credential()?;
    let mut initiator = Initiator::new(target(HOST)?, InitiatorOptions::new());
    // Given an initiator that has not started, an input token is unexpected.
    assert!(matches!(
        initiator.init_sec_context(&credential, Some(&[0x60, 0x00])),
        Err(Gss::UnexpectedStep(_))
    ));
    // Given an initiator waiting for the AP-REP, it is not established yet,
    let InitStep::Continue(_) = initiator.init_sec_context(&credential, None)? else {
        return Err("mutual authentication waits for the acceptor".into());
    };
    assert!(!initiator.is_established());
    // and a second first step is unexpected.
    assert!(matches!(
        initiator.init_sec_context(&credential, None),
        Err(Gss::UnexpectedStep(_))
    ));
    assert!(matches!(
        initiator.into_established(),
        Err(Gss::UnexpectedStep(_))
    ));
    Ok(())
}

/// The acceptor refuses defective tokens and a replayed AP-REQ.
#[test]
fn acceptors_refuse_defective_and_replayed_tokens() -> Result<(), TestError> {
    let credential = credential()?;
    let mut initiator = Initiator::new(target(HOST)?, InitiatorOptions::new());
    let InitStep::Continue(first) = initiator.init_sec_context(&credential, None)? else {
        return Err("mutual authentication waits for the acceptor".into());
    };
    let store = Credential::from_keytab(keytab(&[HOST]));
    let mut acceptor = Acceptor::new(&store, AcceptorOptions::new())?;
    // Given garbage, it is a defective token.
    assert!(matches!(
        acceptor.accept_sec_context(&[0x30, 0x00]),
        Err(Gss::Spnego(_) | Gss::DefectiveToken(_))
    ));
    // Given the token with one authenticator byte flipped, the AP-REQ does not validate.
    let mut tampered = first.clone();
    let last = tampered.last_mut().context("a token byte")?;
    *last ^= 0x01;
    assert!(matches!(
        acceptor.accept_sec_context(&tampered),
        Err(Gss::Service(_))
    ));
    // Given the genuine token twice, the second is a replay.
    drop(acceptor.accept_sec_context(&first)?);
    assert!(matches!(
        acceptor.accept_sec_context(&first),
        Err(Gss::Service(Service::Replay))
    ));
    Ok(())
}

/// A named acceptor takes only tickets for its own name; the keytab must hold
/// a key for that name.
#[test]
fn named_acceptors_take_only_their_own_tickets() -> Result<(), TestError> {
    // Given an acceptor named for another host of the same keytab,
    let other = Name::import(b"HTTP@other.example.com", NameType::HostbasedService)?;
    let refused = establish(
        &credential()?,
        InitiatorOptions::new(),
        (
            AcceptorOptions::new(),
            &[HOST, "other.example.com"],
            Some(other),
        ),
    );
    // then a ticket for the default host is the wrong principal.
    assert!(
        matches!(
            refused
                .as_ref()
                .err()
                .and_then(|error| error.downcast_ref::<Gss>()),
            Some(Gss::Service(Service::WrongPrincipal { .. }))
        ),
        "{refused:?}"
    );
    // Given an acceptor named for the service on any host, the ticket is accepted.
    let any = Name::import(b"HTTP", NameType::HostbasedService)?;
    drop(establish(
        &credential()?,
        InitiatorOptions::new(),
        (
            AcceptorOptions::new(),
            &[HOST, "other.example.com"],
            Some(any),
        ),
    )?);
    // Given a name the keytab has no key for, there is no acceptor credential.
    let absent = Name::import(b"HTTP@absent.example.com", NameType::HostbasedService)?;
    assert!(matches!(
        Credential::from_keytab(keytab(&[HOST])).with_name(absent),
        Err(Gss::NoCredential(_))
    ));
    Ok(())
}
