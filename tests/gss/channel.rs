//! The acceptor's channel-binding policy (RFC 4121 section 4.1.1.2, RFC 5554;
//! MIT `accept_sec_context.c:406-621` and `doc/appdev/gssapi.rst:427-461`).
//!
//! A zero digest means the initiator sent no bindings: it is absent, never a
//! match. MIT accepts such a token without `GSS_C_CHANNEL_BOUND_FLAG`; an
//! acceptor that requires bindings refuses it.

use rskrb5_ng::{
    error::Gss,
    gss::{AcceptorOptions, ChannelBindings, ContextFlags, Credential, InitiatorOptions},
};

use super::{
    context::TestError,
    support::{HOST, Pair, cache, cached, establish, ticket_for},
};

/// The bindings of one TLS channel.
fn channel(byte: u8) -> Result<ChannelBindings, TestError> {
    Ok(ChannelBindings::tls_server_end_point(&[byte; 32])?)
}

/// A context established with initiator and acceptor options.
fn run(initiator: InitiatorOptions, acceptor: AcceptorOptions) -> Result<Pair, TestError> {
    let credential = Credential::from_ccache(cache(vec![cached(&ticket_for(HOST, &[])?)?]))?;
    establish(&credential, initiator, (acceptor, &[HOST], None))
}

/// The `Gss` error of a failed establishment.
fn refusal(result: Result<Pair, TestError>) -> Option<Gss> {
    result.err()?.downcast::<Gss>().ok().map(|error| *error)
}

/// Matching bindings complete the context and mark it channel-bound.
#[test]
fn matching_bindings_mark_the_context_channel_bound() -> Result<(), TestError> {
    // Given the same bindings on both ends,
    let pair = run(
        InitiatorOptions::new().with_channel_bindings(channel(1)?),
        AcceptorOptions::new().with_channel_bindings(channel(1)?),
    )?;
    // then the acceptor reports a channel-bound context.
    assert!(
        pair.acceptor
            .inquire()
            .flags()
            .contains(ContextFlags::CHANNEL_BOUND)
    );
    Ok(())
}

/// Bindings that differ are refused.
#[test]
fn mismatched_bindings_are_refused() -> Result<(), TestError> {
    // Given different bindings on each end, the acceptor refuses the token.
    let failure = refusal(run(
        InitiatorOptions::new().with_channel_bindings(channel(1)?),
        AcceptorOptions::new().with_channel_bindings(channel(2)?),
    ));
    assert!(matches!(failure, Some(Gss::BadBindings)), "{failure:?}");
    Ok(())
}

/// A token without bindings is absent, not a match: accepted without the
/// channel-bound flag, as MIT does.
#[test]
fn a_zero_digest_is_absent_never_a_match() -> Result<(), TestError> {
    // Given an initiator without bindings and an acceptor with them,
    let pair = run(
        InitiatorOptions::new(),
        AcceptorOptions::new().with_channel_bindings(channel(1)?),
    )?;
    // then the context is not channel-bound.
    assert!(
        !pair
            .acceptor
            .inquire()
            .flags()
            .contains(ContextFlags::CHANNEL_BOUND)
    );
    // Given bindings only on the initiator, the context is not channel-bound either.
    let one_sided = run(
        InitiatorOptions::new().with_channel_bindings(channel(1)?),
        AcceptorOptions::new(),
    )?;
    assert!(
        !one_sided
            .acceptor
            .inquire()
            .flags()
            .contains(ContextFlags::CHANNEL_BOUND)
    );
    Ok(())
}

/// An acceptor that requires channel bindings refuses a token without them.
#[test]
fn an_acceptor_requiring_bindings_refuses_a_token_without_them() -> Result<(), TestError> {
    // Given an acceptor that requires bindings and an initiator that sends none,
    let failure = refusal(run(
        InitiatorOptions::new(),
        AcceptorOptions::new()
            .with_channel_bindings(channel(1)?)
            .require_channel_bindings(true),
    ));
    // then the token is refused for missing bindings.
    assert!(matches!(failure, Some(Gss::MissingBindings)), "{failure:?}");
    // Given matching bindings, the same acceptor accepts.
    drop(run(
        InitiatorOptions::new().with_channel_bindings(channel(1)?),
        AcceptorOptions::new()
            .with_channel_bindings(channel(1)?)
            .require_channel_bindings(true),
    )?);
    Ok(())
}

/// An acceptor cannot require bindings it does not have.
#[test]
fn requiring_bindings_needs_the_acceptor_bindings() -> Result<(), TestError> {
    let failure = refusal(run(
        InitiatorOptions::new().with_channel_bindings(channel(1)?),
        AcceptorOptions::new().require_channel_bindings(true),
    ));
    assert!(matches!(failure, Some(Gss::MissingBindings)), "{failure:?}");
    Ok(())
}

/// An initiator that asks for the channel-bound flag sends MS-KILE
/// `KERB_AP_OPTIONS_CBT`, and an acceptor with bindings then refuses a token
/// without matching ones.
#[test]
fn channel_bound_initiators_make_the_acceptor_strict() -> Result<(), TestError> {
    // Given a CBT-aware initiator without bindings and an acceptor with bindings,
    let strict = InitiatorOptions::new()
        .with_flags(InitiatorOptions::new().flags() | ContextFlags::CHANNEL_BOUND);
    let failure = refusal(run(
        strict.clone(),
        AcceptorOptions::new().with_channel_bindings(channel(1)?),
    ));
    // then the acceptor refuses it.
    assert!(matches!(failure, Some(Gss::BadBindings)), "{failure:?}");
    // Given an acceptor without bindings, the same initiator is accepted.
    drop(run(strict, AcceptorOptions::new())?);
    Ok(())
}
