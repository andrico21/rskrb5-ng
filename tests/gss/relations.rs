//! The configuration relations the mechanism consumes.
//!
//! The `[libdefaults]` relations the GSS mechanism makes effective:
//! `client_aware_channel_bindings` and `enforce_ok_as_delegate` on the
//! initiator, `ignore_acceptor_hostname` on the acceptor (MIT `init_ctx.c:234-242`,
//! `init_sec_context.c:537-541`, `mk_req_ext.c:296-316,385-393`,
//! `sname_match.c:30-58`).

use rskrb5_ng::{
    config::{Config, ParseMode},
    error::Gss,
    gss::{
        AcceptorOptions, ChannelBindings, ContextFlags, Credential, InitiatorOptions, Name,
        NameType,
    },
};

use super::{
    context::TestError,
    support::{FORWARDABLE, HOST, cache, cached, establish, tgt, ticket_for},
};

/// A strict-mode profile with one `[libdefaults]` assignment.
fn strict(assignment: &str) -> Result<Config, TestError> {
    Ok(Config::parse_with_mode(
        &format!("[libdefaults]\n {assignment}\n"),
        ParseMode::Strict,
    )?)
}

/// `client_aware_channel_bindings = true` makes the initiator send
/// `KERB_AP_OPTIONS_CBT`, so an acceptor with bindings refuses it without them.
#[test]
fn client_aware_channel_bindings_reaches_the_initiator() -> Result<(), TestError> {
    // Given the relation in a strict profile, it is accepted as effective,
    let config = strict("client_aware_channel_bindings = true")?;
    let options = InitiatorOptions::from_config(&config);
    assert!(options.client_aware_channel_bindings());
    // and an initiator built from it, without bindings, is refused by an acceptor with bindings.
    let credential = Credential::from_ccache(cache(vec![cached(&ticket_for(HOST, &[])?)?]))?;
    let bound = AcceptorOptions::new()
        .with_channel_bindings(ChannelBindings::tls_server_end_point(&[7; 32])?);
    let failure = establish(&credential, options, (bound, &[HOST], None))
        .err()
        .and_then(|error| error.downcast::<Gss>().ok());
    assert!(
        matches!(failure.as_deref(), Some(Gss::BadBindings)),
        "{failure:?}"
    );
    // The default leaves the initiator unaware.
    assert!(
        !InitiatorOptions::from_config(&strict("client_aware_channel_bindings = false")?)
            .client_aware_channel_bindings()
    );
    Ok(())
}

/// `enforce_ok_as_delegate = true` delegates only to OK-AS-DELEGATE services.
#[test]
fn enforce_ok_as_delegate_reaches_the_initiator() -> Result<(), TestError> {
    // Given the relation in a strict profile and an initiator asking for delegation,
    let config = strict("enforce_ok_as_delegate = true")?;
    let options = InitiatorOptions::from_config(&config)
        .with_flags(InitiatorOptions::new().flags() | ContextFlags::DELEG);
    assert!(options.enforce_ok_as_delegate());
    let credential = Credential::from_ccache(cache(vec![
        tgt(&[FORWARDABLE])?,
        cached(&ticket_for(HOST, &[])?)?,
    ]))?;
    // when the service ticket lacks OK-AS-DELEGATE, then nothing is delegated.
    let pair = establish(
        &credential,
        options,
        (AcceptorOptions::new(), &[HOST], None),
    )?;
    assert!(pair.acceptor.delegated_credential().is_none());
    Ok(())
}

/// `ignore_acceptor_hostname = true` lets a named acceptor take a ticket for
/// another host of its service, as MIT's `krb5_sname_match` does.
#[test]
fn ignore_acceptor_hostname_reaches_the_acceptor() -> Result<(), TestError> {
    let credential = Credential::from_ccache(cache(vec![cached(&ticket_for(HOST, &[])?)?]))?;
    let other = Name::import(b"HTTP@other.example.com", NameType::HostbasedService)?;
    // Given the relation in a strict profile, the acceptor options carry it,
    let config = strict("ignore_acceptor_hostname = true")?;
    let relaxed = AcceptorOptions::from_config(&config);
    assert!(relaxed.ignore_acceptor_hostname());
    // and an acceptor named for another host accepts the ticket for this host.
    let hosts = [HOST, "other.example.com"];
    drop(establish(
        &credential,
        InitiatorOptions::new(),
        (relaxed, &hosts, Some(other.clone())),
    )?);
    // Without it, the same acceptor refuses the ticket.
    let strict_options = AcceptorOptions::from_config(&strict("ignore_acceptor_hostname = false")?);
    let refused = establish(
        &credential,
        InitiatorOptions::new(),
        (strict_options, &hosts, Some(other)),
    );
    assert!(refused.is_err(), "a named acceptor refuses another host");
    Ok(())
}

/// The SPNEGO header initiator, which the HTTP Negotiate clients use, sends
/// `KERB_AP_OPTIONS_CBT` when asked, so an acceptor with bindings refuses it.
#[test]
fn client_aware_channel_bindings_reaches_the_spnego_header_initiator() -> Result<(), TestError> {
    use rskrb5_ng::spnego::{self, InitiatorContextOptions, Token};

    let ticket = ticket_for(HOST, &[])?;
    let bound = || -> Result<AcceptorOptions, TestError> {
        Ok(AcceptorOptions::new()
            .with_channel_bindings(ChannelBindings::tls_server_end_point(&[7; 32])?))
    };
    let store = Credential::from_keytab(super::support::keytab(&[HOST]));
    for (aware, refused) in [(true, true), (false, false)] {
        // Given a SPNEGO header built with or without the assertion,
        let context = spnego::init_sec_context(
            &ticket,
            InitiatorContextOptions::new().with_client_aware_channel_bindings(aware),
        )?;
        let Token::Init(init) = spnego::parse_negotiate_header(context.header_ref())? else {
            return Err("a NegTokenInit".into());
        };
        let token = init.mech_token().ok_or("an optimistic token")?.to_vec();
        // when an acceptor with bindings takes its Kerberos token,
        let mut acceptor = rskrb5_ng::gss::Acceptor::new(&store, bound()?)?;
        let result = acceptor.accept_sec_context(&token);
        // then it is refused exactly when the initiator asserted CBT.
        assert_eq!(
            matches!(result, Err(Gss::BadBindings)),
            refused,
            "aware={aware}: {result:?}"
        );
    }
    Ok(())
}
