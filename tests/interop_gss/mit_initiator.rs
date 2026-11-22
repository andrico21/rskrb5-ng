//! MIT initiators against the Rust GSS and SPNEGO acceptors, and a TGT a Rust
//! initiator delegates to the Rust acceptor.

use core::error::Error;

use rskrb5_ng::{
    error::Gss,
    gss::{
        self, AcceptorOptions, ContextFlags, CredStore, Credential, CredentialUsage, InitStep,
        InitiatorOptions, Name, NameType,
    },
    spnego::{self, AcceptStep},
};

use super::{
    CHANNEL_BOUND, DELEG, KRB5, MIT_KDC, PEER, SPNEGO, STANDARD_FLAGS, assert_krb5, bindings,
    config, connect, exchange, initiator_cred, mit_target, password_credential, rust_to_mit, user,
};
use crate::{
    harness,
    peer::{cred::Name as PeerName, types::InitRequest},
};

/// The Rust acceptor's host-based name, `peer@rust.test.rskrb5`.
fn rust_target() -> Result<Name, Box<dyn Error>> {
    let principal = harness::var("INTEROP_MIT_PEER_RUST_SERVICE")?;
    let (service, host) = principal
        .split_once('/')
        .ok_or("the Rust service is service/host")?;
    Ok(Name::import(
        format!("{service}@{host}").as_bytes(),
        NameType::HostbasedService,
    )?)
}

/// The Rust acceptor credential from the keytab MIT exported, named.
fn rust_acceptor() -> Result<Credential, Box<dyn Error>> {
    let store = CredStore::new().with(
        "keytab",
        &format!("FILE:{}", harness::var("INTEROP_MIT_PEER_RUST_KEYTAB")?),
    )?;
    Ok(Credential::acquire_cred_from(
        Some(&rust_target()?),
        CredentialUsage::Accept,
        &store,
    )?)
}

/// The adapter's init request for the Rust acceptor with `mech`.
fn mit_init(mech: &str) -> Result<InitRequest, Box<dyn Error>> {
    let target = format!(
        "{}@{}",
        harness::var("INTEROP_MIT_PEER_RUST_SERVICE")?,
        harness::var("INTEROP_MIT_REALM")?
    );
    Ok(InitRequest::new(PeerName::principal(&target))
        .with_mech(mech)
        .with_flags(STANDARD_FLAGS))
}

/// One MIT krb5 initiator run against the Rust acceptor with `options`; on
/// success the AP-REP completes MIT's context and messages flow both ways.
fn mit_to_rust(
    initiator_bindings: Option<&[u8]>,
    options: AcceptorOptions,
) -> Result<Result<ContextFlags, Gss>, Box<dyn Error>> {
    let mut adapter = connect()?;
    let mut init = mit_init(KRB5)?.with_cred(initiator_cred(&mut adapter, KRB5)?);
    if let Some(data) = initiator_bindings {
        init = init.with_bindings(data);
    }
    let first = adapter.init_step(&init)?;
    assert!(first.continue_needed(), "MIT waits for the AP-REP");
    let store = rust_acceptor()?;
    let mut acceptor = gss::Acceptor::new(&store, options)?;
    let accepted = match acceptor.accept_sec_context(first.token()) {
        Ok(accepted) => accepted,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let reply = accepted.output_token().ok_or("an AP-REP")?.to_vec();
    let mut context = accepted.into_context();
    let info = context.inquire();
    assert_eq!(
        info.source().display().0,
        format!(
            "{}@{}",
            harness::var("INTEROP_MIT_PEER_USER")?,
            harness::var("INTEROP_MIT_REALM")?
        )
    );
    let last = adapter.init_step(&init.continuing(first.context(), &reply))?;
    assert!(
        !last.continue_needed(),
        "the Rust AP-REP completes MIT's context"
    );
    assert_krb5(last.mech())?;
    exchange(&mut context, &mut adapter, last.context())?;
    Ok(Ok(info.flags()))
}

/// MIT's initiator is accepted by the Rust GSS acceptor, bound or not.
///
/// Matching bindings mark the context channel-bound, a mismatch is refused,
/// and an acceptor that requires bindings refuses MIT's token without them.
#[test]
fn mit_gss_initiator_is_accepted_by_the_rust_acceptor() -> Result<(), Box<dyn Error>> {
    if !harness::require(
        "mit_gss_initiator_is_accepted_by_the_rust_acceptor",
        &[MIT_KDC, PEER],
    )? {
        return Ok(());
    }
    let blob = b"tls-server-end-point:mit-to-rust".as_slice();
    let plain = mit_to_rust(None, AcceptorOptions::new())??;
    assert!(!plain.contains(ContextFlags::from_bits(CHANNEL_BOUND)));
    let bound = mit_to_rust(
        Some(blob),
        AcceptorOptions::new().with_channel_bindings(bindings(blob)?),
    )??;
    assert!(
        bound.contains(ContextFlags::CHANNEL_BOUND),
        "matching bindings"
    );
    let mismatch = mit_to_rust(
        Some(blob),
        AcceptorOptions::new().with_channel_bindings(bindings(b"tls-server-end-point:other")?),
    )?;
    assert!(matches!(mismatch, Err(Gss::BadBindings)), "{mismatch:?}");
    let missing = mit_to_rust(
        None,
        AcceptorOptions::new()
            .with_channel_bindings(bindings(blob)?)
            .require_channel_bindings(true),
    )?;
    assert!(matches!(missing, Err(Gss::MissingBindings)), "{missing:?}");
    Ok(())
}

/// MIT's SPNEGO initiator negotiates krb5 with the Rust SPNEGO acceptor over
/// the GSS contexts; the context protects messages both ways.
#[test]
fn mit_spnego_initiator_is_accepted_by_the_rust_spnego_acceptor() -> Result<(), Box<dyn Error>> {
    if !harness::require(
        "mit_spnego_initiator_is_accepted_by_the_rust_spnego_acceptor",
        &[MIT_KDC, PEER],
    )? {
        return Ok(());
    }
    let mut adapter = connect()?;
    let init = mit_init(SPNEGO)?.with_cred(initiator_cred(&mut adapter, SPNEGO)?);
    let first = adapter.init_step(&init)?;
    let store = rust_acceptor()?;
    let mut acceptor = spnego::Acceptor::new(gss::Acceptor::new(&store, AcceptorOptions::new())?);
    let AcceptStep::Complete(accepted) = acceptor.accept_sec_context(first.token())? else {
        return Err("MIT's optimistic token completes the SPNEGO acceptor".into());
    };
    let answer = accepted.output_token().ok_or("a NegTokenResp")?.to_vec();
    let mut context = accepted.into_context();
    let last = adapter.init_step(&init.continuing(first.context(), &answer))?;
    assert!(
        !last.continue_needed(),
        "the NegTokenResp completes MIT's context"
    );
    assert_krb5(last.mech())?;
    exchange(&mut context, &mut adapter, last.context())
}

/// A Rust initiator delegates its forwardable TGT from the MIT KDC to the Rust
/// acceptor, which uses the delegated credential to reach MIT's acceptor as
/// the user.
#[test]
fn a_delegated_mit_tgt_serves_the_rust_acceptor() -> Result<(), Box<dyn Error>> {
    if !harness::require(
        "a_delegated_mit_tgt_serves_the_rust_acceptor",
        &[MIT_KDC, PEER],
    )? {
        return Ok(());
    }
    let config = config(" forwardable = true\n")?;
    let credential = password_credential(&rust_target()?, &config)?;
    let options = InitiatorOptions::new()
        .with_flags(InitiatorOptions::new().flags() | ContextFlags::from_bits(DELEG));
    let mut initiator = gss::Initiator::new(rust_target()?, options);
    let InitStep::Continue(token) = initiator.init_sec_context(&credential, None)? else {
        return Err("mutual authentication waits".into());
    };
    let store = rust_acceptor()?;
    let mut acceptor = gss::Acceptor::new(&store, AcceptorOptions::new())?;
    let accepted = acceptor.accept_sec_context(&token)?;
    let mut context = accepted.into_context();
    assert!(
        context.inquire().flags().contains(ContextFlags::DELEG),
        "delegated"
    );
    let mut delegated = context
        .take_delegated_credential()
        .ok_or("the acceptor holds the delegated TGT")?;
    assert_eq!(
        delegated.inquire().name().ok_or("a name")?.display().0,
        user()?
    );
    super::runtime()?.block_on(delegated.acquire_service_ticket(&mit_target()?, &config))?;
    rust_to_mit(&delegated, InitiatorOptions::new(), None)??;
    Ok(())
}
