//! The crate's `NegoEx` under SPNEGO against MIT's, both ways.
//!
//! MIT's side is the adapter peer with `GSS_MECH_CONFIG=negoextest`: SPNEGO
//! negotiates the two `negoextest` mechanisms through `NegoEx` (the krb5
//! mechanism has no credentials in the adapter). The crate's side runs the
//! test-only `negoextest` mechanism of `tests/gss_negoex/negoextest.rs`.

use alloc::sync::Arc;
use core::error::Error;
use std::net::TcpStream;

use rskrb5_ng::{
    error::{Gss, Negoex},
    extensions::{Extension, Registry},
    gss::{
        InitStep,
        negoex::{Context, Mechanism, RandomSource, Request},
    },
    spnego::{
        NegTokenInit, Token,
        negoex::{AcceptStep, Acceptor, Initiator},
        oid::ObjectIdentifier,
    },
};
use zeroize::Zeroizing;

use crate::{
    context::Context as _,
    harness::{self, Fixture},
    negoextest::{KeyPolicy, Knobs, OID_FIRST, OID_SECOND, Registered, TestMechanism},
    peer::{
        Peer,
        cred::Name,
        frame,
        types::{AcceptRequest, InitRequest, PeerError},
    },
};

/// The adapter container with a route to the KDC.
const PEER: Fixture = Fixture::new("mit-peer", "INTEROP_MIT_PEER_ADDR");

/// The KDC fixture, which the peer container needs.
const MIT_KDC: Fixture = Fixture::new("mit-kdc", "INTEROP_MIT_KDC");

/// The SPNEGO mechanism.
const SPNEGO: &str = "1.3.6.1.5.5.2";

/// The arcs of the first `negoextest` mechanism, which both sides prefer.
///
/// The mechanism is pinned on the crate's side, through the mechanism the
/// crate's context reports as selected: MIT's `negoextest` plugin never sets
/// the `actual_mech` output of `gss_init_sec_context` and
/// `gss_accept_sec_context` (`src/plugins/gssapi/negoextest/main.c`, 1.22.2),
/// so the adapter reports an empty mechanism for MIT's side, and MIT's side
/// can only complete the context with a `VERIFY` over the keys of the
/// mechanism both sides selected.
const FIRST_ARCS: &[u32] = &[2, 25, 1_414_534_758];

/// `GSS_C_MUTUAL_FLAG | REPLAY | SEQUENCE | CONF | INTEG`.
const STANDARD_FLAGS: u32 = 2 | 4 | 8 | 16 | 32;

/// `GSS_S_BAD_SIG`, the major status of a `VERIFY` message that does not verify.
const GSS_S_BAD_SIG: u32 = 6 << 16;

/// Most round trips before a scenario gives up.
const ROUNDS: u8 = 8;

/// A fixed random source, so that the crate's tokens are reproducible.
struct Fixed;

impl RandomSource for Fixed {
    fn fill(&self, bytes: &mut [u8]) -> Result<(), Negoex> {
        bytes.fill(0x42);
        Ok(())
    }
}

/// A connection to the adapter with the `negoextest` mechanisms loaded.
fn adapter(knobs: &[(String, String)]) -> Result<Peer<TcpStream>, Box<dyn Error>> {
    let mut peer = frame::connect(&harness::var("INTEROP_MIT_PEER_ADDR")?)?;
    peer.set_env("GSS_MECH_CONFIG", "negoextest")?;
    for (name, value) in knobs {
        peer.set_env(name, value)?;
    }
    Ok(peer)
}

/// A registry with both `negoextest` mechanisms registered as GSS mechanisms.
fn registry() -> Result<Registry, Box<dyn Error>> {
    let mut registry = Registry::new();
    for oid in [OID_FIRST, OID_SECOND] {
        registry.register(Extension::GssMechanism(Arc::new(Registered {
            id: format!("negoextest-{}", oid.last().copied().unwrap_or(0)),
            oid: oid.to_vec(),
        })))?;
    }
    Ok(registry)
}

/// MIT's `KEY` variable for `key`, none for the default.
const fn key_variable(key: KeyPolicy) -> Option<&'static str> {
    match key {
        KeyPolicy::Established | KeyPolicy::Never => None,
        KeyPolicy::Always => Some("always"),
        KeyPolicy::InitAlways => Some("init-always"),
        KeyPolicy::AcceptAlways => Some("accept-always"),
    }
}

/// The adapter knobs of `hops` hops (an initiator's) and the key policy.
fn adapter_knobs(hops: u8, key: KeyPolicy) -> Vec<(String, String)> {
    let mut knobs = vec![("HOPS".to_owned(), hops.to_string())];
    if let Some(value) = key_variable(key) {
        knobs.push(("KEY".to_owned(), value.to_owned()));
    }
    knobs
}

/// A context for the crate's side offering both mechanisms with `hops` hops.
fn context(initiator: bool, hops: u8, key: KeyPolicy) -> Result<Context, Box<dyn Error>> {
    let registry = registry()?;
    let knobs = Knobs {
        hops,
        key,
        ..Knobs::default()
    };
    let mechanisms: Vec<Arc<dyn Mechanism>> = vec![
        TestMechanism::shared(&OID_FIRST, knobs.clone()),
        TestMechanism::shared(&OID_SECOND, knobs),
    ];
    let context = if initiator {
        Context::initiator(&registry, &mechanisms, Request::new())?
    } else {
        Context::acceptor(&registry, &mechanisms, Request::new())?
    };
    Ok(context.with_random_source(Arc::new(Fixed)))
}

/// The `NegTokenInit` of `token`, which must offer exactly the `NegoEx` OID.
fn offered_negoex(token: &[u8]) -> Result<NegTokenInit, Box<dyn Error>> {
    let Token::Init(init) = Token::decode(token)? else {
        return Err("the first token is a NegTokenInit".into());
    };
    assert_eq!(init.mech_types(), &[ObjectIdentifier::negoex()]);
    Ok(init)
}

/// The crate's initiator against MIT's acceptor, with `hops` hops.
fn rust_initiates(hops: u8, key: KeyPolicy) -> Result<(), Box<dyn Error>> {
    let mut acceptor = adapter(&adapter_knobs(hops, key))?;
    let mut initiator = Initiator::new(context(true, hops, key)?);
    let InitStep::Continue(mut token) = initiator.init_sec_context(None)? else {
        return Err("the initiator waits for the acceptor".into());
    };
    drop(offered_negoex(&token)?);
    let request = AcceptRequest::new(b"");
    let mut handle = None;
    let mut mit_completed = false;
    for _round in 0..ROUNDS {
        let step = acceptor.accept_step(&request.stepping(handle, &token))?;
        handle = Some(step.context());
        if !step.continue_needed() {
            mit_completed = true;
        }
        if step.token().is_empty() {
            break;
        }
        match initiator.init_sec_context(Some(step.token()))? {
            InitStep::Continue(next) => token = next,
            InitStep::Complete(_) => break,
            _ => return Err("an unexpected initiator step".into()),
        }
    }
    assert!(mit_completed, "MIT's acceptor completed");
    let selected = initiator.selected().context("the initiator completed")?;
    assert_eq!(selected.oid().arcs(), FIRST_ARCS);
    drop(initiator.into_session()?);
    Ok(())
}

/// MIT's initiator against the crate's acceptor, with `hops` hops.
fn mit_initiates(hops: u8, key: KeyPolicy) -> Result<(), Box<dyn Error>> {
    let mut initiator = adapter(&adapter_knobs(hops, key))?;
    let mut acceptor = Acceptor::new(context(false, hops, key)?);
    let request = InitRequest::new(Name::hostbased(&harness::var("INTEROP_MIT_PEER_SERVICE")?))
        .with_mech(SPNEGO)
        .with_flags(STANDARD_FLAGS);
    let mut step = initiator.init_step(&request)?;
    let handle = step.context();
    let mut accepted = None;
    for _round in 0..ROUNDS {
        match acceptor.accept_sec_context(step.token())? {
            AcceptStep::Continue(reply) => {
                step = initiator.init_step(&request.clone().continuing(handle, &reply))?;
            }
            AcceptStep::Complete(done) => {
                step = initiator
                    .init_step(&request.clone().continuing(handle, done.output_token()))?;
                accepted = Some(done);
                break;
            }
            _ => return Err("an unexpected acceptor step".into()),
        }
    }
    let done = accepted.context("the Rust acceptor completed")?;
    assert!(!step.continue_needed(), "MIT's initiator completed");
    assert_eq!(done.mechanism().oid().arcs(), FIRST_ARCS);
    drop(done.into_session());
    Ok(())
}

/// The crate's initiator negotiates the first `negoextest` mechanism with
/// MIT's acceptor in one, two and three hops, through `NegoEx` under SPNEGO.
#[test]
fn rust_initiator_and_mit_acceptor_negotiate_negoex() -> Result<(), Box<dyn Error>> {
    if !harness::require(
        "rust_initiator_and_mit_acceptor_negotiate_negoex",
        &[PEER, MIT_KDC],
    )? {
        return Ok(());
    }
    for hops in 1..=3 {
        rust_initiates(hops, KeyPolicy::Established)?;
    }
    Ok(())
}

/// MIT's initiator negotiates the first `negoextest` mechanism with the
/// crate's acceptor in one, two and three hops, through `NegoEx` under SPNEGO.
#[test]
fn mit_initiator_and_rust_acceptor_negotiate_negoex() -> Result<(), Box<dyn Error>> {
    if !harness::require(
        "mit_initiator_and_rust_acceptor_negotiate_negoex",
        &[PEER, MIT_KDC],
    )? {
        return Ok(());
    }
    for hops in 1..=3 {
        mit_initiates(hops, KeyPolicy::Established)?;
    }
    Ok(())
}

/// `token` (a `NegTokenInit`) with the last byte of its mechanism token, the
/// `VERIFY` checksum, changed.
fn damaged(token: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut init = offered_negoex(token)?;
    let mut bytes = init.mech_token().context("a mechanism token")?.to_vec();
    let end = bytes.len().saturating_sub(1);
    *bytes.get_mut(end).context("a byte")? ^= 0x01;
    init.set_mech_token(Some(Zeroizing::new(bytes)));
    Ok(Token::Init(init).encode()?)
}

/// Keys that exist early and the alerts they cause interoperate: with early
/// keys the `VERIFY` messages go out before the mechanism ends, and an end
/// without the peer's key sends a `VERIFY_NO_KEY` alert, in both directions.
#[test]
fn early_keys_and_alerts_interoperate() -> Result<(), Box<dyn Error>> {
    if !harness::require("early_keys_and_alerts_interoperate", &[PEER, MIT_KDC])? {
        return Ok(());
    }
    for (hops, key) in [
        (3, KeyPolicy::Always),
        (4, KeyPolicy::Always),
        (3, KeyPolicy::InitAlways),
        (4, KeyPolicy::AcceptAlways),
    ] {
        rust_initiates(hops, key)?;
        mit_initiates(hops, key)?;
    }
    Ok(())
}

/// A `VERIFY` message with a wrong checksum fails the context in both
/// directions: MIT's acceptor refuses the crate's first token with
/// `GSS_S_BAD_SIG`, and the crate's acceptor refuses MIT's with
/// [`Negoex::InvalidChecksum`].
#[test]
fn a_wrong_verify_checksum_fails_both_ways() -> Result<(), Box<dyn Error>> {
    if !harness::require("a_wrong_verify_checksum_fails_both_ways", &[PEER, MIT_KDC])? {
        return Ok(());
    }
    let mut initiator = Initiator::new(context(true, 1, KeyPolicy::Established)?);
    let InitStep::Continue(token) = initiator.init_sec_context(None)? else {
        return Err("the initiator waits for the acceptor".into());
    };
    let mut acceptor = adapter(&[])?;
    match acceptor.accept_step(&AcceptRequest::new(&damaged(&token)?)) {
        Err(PeerError::Gss {
            major,
            minor: _,
            text: _,
        }) => assert_eq!(major, GSS_S_BAD_SIG, "MIT reports the checksum as BAD_SIG"),
        other => return Err(format!("MIT's acceptor must refuse: {other:?}").into()),
    }
    let mut peer = adapter(&adapter_knobs(1, KeyPolicy::Established))?;
    let request = InitRequest::new(Name::hostbased(&harness::var("INTEROP_MIT_PEER_SERVICE")?))
        .with_mech(SPNEGO)
        .with_flags(STANDARD_FLAGS);
    let step = peer.init_step(&request)?;
    let mut rust = Acceptor::new(context(false, 1, KeyPolicy::Established)?);
    let failure = rust
        .accept_sec_context(&damaged(step.token())?)
        .err()
        .context("the crate's acceptor must refuse")?;
    assert!(
        matches!(failure, Gss::Negoex(Negoex::InvalidChecksum)),
        "{failure}"
    );
    Ok(())
}
