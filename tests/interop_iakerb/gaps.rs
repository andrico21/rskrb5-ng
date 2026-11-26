//! IAKERB scenarios of the wave-11 gaps: client keytabs in both directions and
//! a delegation the Rust initiator requests.

use core::error::Error;
use std::{net::TcpStream, path::Path};

use rskrb5_ng::{
    config::Config,
    gss::{
        ContextFlags, CredStore, Credential, CredentialUsage, EstablishedContext, InitStep,
        InitiatorOptions, Name, NameType,
        iakerb::{Context, RelayPolicy},
    },
};

use crate::{
    acceptor::{Secret, mit_to_rust_with},
    common::{
        IAKERB, MIT_KDC, PEER, PEER_ISO, ROUNDS, acceptor_cred, assert_mechanism,
        blocked_config_with, connect_main, exchange, mit_target, realm, user_principal,
    },
    harness,
    peer::{
        Peer,
        cred::Name as PeerName,
        types::{AcceptRequest, ContextHandle},
    },
};

/// `GSS_C_DELEG_FLAG`.
const DELEG_FLAG: u32 = 1;

/// A Rust IAKERB context against MIT's IAKERB acceptor, once established.
struct RustToMit {
    /// The adapter connection that holds MIT's context.
    adapter: Peer<TcpStream>,
    /// MIT's context.
    handle: ContextHandle,
    /// The `ret_flags` of MIT's last accept step.
    mit_flags: u32,
    /// The accept steps MIT took.
    steps: usize,
    /// The Rust context.
    context: EstablishedContext,
}

/// Establish a context from `credential` with the Rust IAKERB initiator
/// against MIT's IAKERB acceptor, the initiator's own KDC path blocked by
/// `config`.
fn rust_to_mit(
    config: &Config,
    credential: &Credential,
    options: InitiatorOptions,
) -> Result<RustToMit, Box<dyn Error>> {
    let mut initiator = Context::initiator(config, mit_target()?, options)?;
    let mut adapter = connect_main()?;
    let accept = AcceptRequest::new(b"").with_cred(acceptor_cred(&mut adapter)?);
    let InitStep::Continue(mut token) = initiator.init_sec_context(credential, None)? else {
        return Err("the first step sends a relay request".into());
    };
    let mut handle = None;
    for steps in 1..=ROUNDS {
        let step = adapter.accept_step(&accept.stepping(handle, &token))?;
        handle = Some(step.context());
        match initiator.init_sec_context(credential, Some(step.token()))? {
            InitStep::Continue(next) => token = next,
            InitStep::Complete(None) => {
                assert!(!step.continue_needed(), "MIT completed on the AP-REQ");
                assert_mechanism(IAKERB, step.mech())?;
                return Ok(RustToMit {
                    adapter,
                    handle: handle.ok_or("the adapter never ran")?,
                    mit_flags: step.flags(),
                    steps,
                    context: initiator.into_established()?,
                });
            }
            InitStep::Complete(Some(_)) | _ => return Err("the AP-REP ends the exchange".into()),
        }
    }
    Err("the exchange did not complete".into())
}

/// The user's client keytab on the host: the fixture exports it next to the
/// Rust service's keytab (`scripts/interop/peer-mit/fixture.sh`).
fn user_keytab() -> Result<Credential, Box<dyn Error>> {
    let rust_keytab = harness::var("INTEROP_MIT_PEER_RUST_KEYTAB")?;
    let path = Path::new(&rust_keytab).with_file_name("peeruser.keytab");
    let store = CredStore::new().with("client_keytab", &format!("FILE:{}", path.display()))?;
    let name = Name::import(user_principal()?.as_bytes(), NameType::Principal)?;
    Ok(Credential::acquire_cred_from(
        Some(&name),
        CredentialUsage::Initiate,
        &store,
    )?)
}

/// The Rust IAKERB initiator with a client keytab completes against MIT's
/// IAKERB acceptor, its own KDC path blocked: the keytab AS exchange is relayed.
#[test]
fn rust_iakerb_initiator_with_a_client_keytab_completes_against_mit() -> Result<(), Box<dyn Error>>
{
    if !harness::require(
        "rust_iakerb_initiator_with_a_client_keytab_completes_against_mit",
        &[MIT_KDC, PEER],
    )? {
        return Ok(());
    }
    // Given a credential that holds only the user's client keytab,
    let credential = user_keytab()?;
    // when the IAKERB context runs through MIT's acceptor,
    let mut outcome = rust_to_mit(
        &blocked_config_with("")?,
        &credential,
        InitiatorOptions::new(),
    )?;
    // then MIT relayed the AS and TGS exchanges and authenticated the user,
    assert!(outcome.steps >= 4, "{} steps", outcome.steps);
    let inquiry = outcome.adapter.inquire(outcome.handle)?;
    assert_mechanism(IAKERB, inquiry.mech())?;
    assert_eq!(inquiry.source(), user_principal()?);
    // and both ends report IAKERB and protect messages both ways.
    assert_eq!(outcome.context.inquire().mechanism(), &Context::mechanism());
    exchange(&mut outcome.context, &mut outcome.adapter, outcome.handle)?;
    Ok(())
}

/// The MIT IAKERB initiator with a client keytab, in the container without a
/// KDC route, completes against the Rust acceptor's relay.
#[test]
fn mit_iakerb_initiator_with_a_client_keytab_completes_against_the_rust_acceptor()
-> Result<(), Box<dyn Error>> {
    if !harness::require(
        "mit_iakerb_initiator_with_a_client_keytab_completes_against_the_rust_acceptor",
        &[MIT_KDC, PEER_ISO],
    )? {
        return Ok(());
    }
    let (outcome, relay) = mit_to_rust_with(
        PeerName::principal(&user_principal()?),
        RelayPolicy::new(&realm()?)?,
        Secret::Keytab,
    )?;
    let context = outcome?;
    assert!(relay.relayed >= 3, "relayed {}", relay.relayed);
    let info = context.inquire();
    assert_eq!(info.source().display().0, user_principal()?);
    assert_eq!(info.mechanism(), &Context::mechanism());
    Ok(())
}

/// A delegation the Rust IAKERB initiator requests reaches MIT.
///
/// The forwardable TGT acquired through the relay travels in the AP-REQ's
/// KRB-CRED, which MIT stores (`GSS_C_DELEG_FLAG` in its result,
/// `accept_sec_context.c:556-578`); without the request MIT receives none.
#[test]
fn rust_iakerb_initiator_delegates_to_mit_only_when_requested() -> Result<(), Box<dyn Error>> {
    if !harness::require(
        "rust_iakerb_initiator_delegates_to_mit_only_when_requested",
        &[MIT_KDC, PEER],
    )? {
        return Ok(());
    }
    let config = blocked_config_with("forwardable = true")?;
    let credential = user_keytab()?;
    let requested = InitiatorOptions::new();
    let flags = requested.flags() | ContextFlags::DELEG;
    let delegated = rust_to_mit(&config, &credential, requested.with_flags(flags))?;
    assert!(
        delegated.mit_flags & DELEG_FLAG != 0,
        "MIT stored the delegated TGT: {:#x}",
        delegated.mit_flags
    );
    assert!(
        delegated
            .context
            .inquire()
            .flags()
            .contains(ContextFlags::DELEG)
    );
    let plain = rust_to_mit(&config, &credential, InitiatorOptions::new())?;
    assert_eq!(plain.mit_flags & DELEG_FLAG, 0, "{:#x}", plain.mit_flags);
    Ok(())
}
