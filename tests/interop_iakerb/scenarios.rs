//! IAKERB against the MIT peer adapter.

use core::{error::Error, time::Duration};
use std::time::Instant;

use rskrb5_ng::{
    error::Iakerb,
    gss::{
        ContextFlags, CredStore, Credential, CredentialUsage, InitStep, InitiatorOptions, Name,
        NameType,
        iakerb::{Context, RelayPolicy},
    },
    spnego::oid::ObjectIdentifier,
};
use tokio::time::timeout;

use crate::{
    acceptor::mit_to_rust,
    common::{
        IAKERB, KRB5, MIT_KDC, PEER, PEER_ISO, ROUNDS, acceptor_cred, arcs, assert_mechanism,
        blocked_config, connect_iso, connect_main, exchange, mit_target, realm, runtime,
        user_principal,
    },
    harness,
    peer::{
        cred::{CredRequest, Name as PeerName, Usage},
        types::{AcceptRequest, PeerError},
    },
};

/// The Rust IAKERB initiator completes against MIT's IAKERB acceptor.
///
/// Its direct path to the KDC is blocked: a direct AS exchange of the same
/// profile and credential fails, and the AS and TGS exchanges of the initiator
/// go through the acceptor, which has the route.
#[test]
fn rust_iakerb_initiator_completes_against_mit_with_the_direct_kdc_path_blocked()
-> Result<(), Box<dyn Error>> {
    if !harness::require(
        "rust_iakerb_initiator_completes_against_mit_with_the_direct_kdc_path_blocked",
        &[MIT_KDC, PEER],
    )? {
        return Ok(());
    }
    let config = blocked_config()?;
    let store =
        CredStore::new().with("password", &harness::var("INTEROP_MIT_PEER_USER_PASSWORD")?)?;
    let name = Name::import(user_principal()?.as_bytes(), NameType::Principal)?;
    let mut credential =
        Credential::acquire_cred_from(Some(&name), CredentialUsage::Initiate, &store)?;
    // Given the block: the same credential cannot get a ticket the direct way,
    let target = mit_target()?;
    let direct = runtime()?.block_on(async {
        timeout(
            Duration::from_secs(30),
            credential.acquire_service_ticket(&target, &config),
        )
        .await
    })?;
    assert!(
        direct.is_err(),
        "a direct AS exchange reaches no KDC through the blocked profile: {direct:?}"
    );
    // when the IAKERB initiator talks to the MIT acceptor through the test,
    let mut initiator = Context::initiator(&config, mit_target()?, InitiatorOptions::new())?;
    let mut adapter = connect_main()?;
    let accept = AcceptRequest::new(b"").with_cred(acceptor_cred(&mut adapter)?);
    let InitStep::Continue(mut token) = initiator.init_sec_context(&credential, None)? else {
        return Err("the first step sends a relay request".into());
    };
    let mut context = None;
    let mut steps = 0_usize;
    for _round in 0..ROUNDS {
        let step = adapter.accept_step(&accept.stepping(context, &token))?;
        steps += 1;
        context = Some(step.context());
        match initiator.init_sec_context(&credential, Some(step.token()))? {
            InitStep::Continue(next) => token = next,
            InitStep::Complete(None) => {
                assert!(!step.continue_needed(), "MIT completed on the AP-REQ");
                assert_mechanism(IAKERB, step.mech())?;
                break;
            }
            InitStep::Complete(Some(_)) | _ => return Err("the AP-REP ends the exchange".into()),
        }
    }
    // then MIT proxied the AS and TGS exchanges before the AP exchange,
    assert!(
        steps >= 4,
        "two AS requests, a TGS request and the AP-REQ: {steps} steps"
    );
    let handle = context.ok_or("the adapter never ran")?;
    assert_mechanism(IAKERB, adapter.inquire(handle)?.mech())?;
    assert_eq!(adapter.inquire(handle)?.source(), user_principal()?);
    // and the context protects messages both ways.
    let mut established = initiator.into_established()?;
    assert!(established.inquire().flags().contains(ContextFlags::MUTUAL));
    exchange(&mut established, &mut adapter, handle)?;
    Ok(())
}

/// The MIT IAKERB initiator in the container that cannot reach the KDC completes.
///
/// The Rust acceptor's relay carries the AS and TGS exchanges; a krb5
/// credential in the same container fails.
#[test]
fn mit_iakerb_initiator_without_a_kdc_route_completes_against_the_rust_acceptor()
-> Result<(), Box<dyn Error>> {
    if !harness::require(
        "mit_iakerb_initiator_without_a_kdc_route_completes_against_the_rust_acceptor",
        &[MIT_KDC, PEER_ISO],
    )? {
        return Ok(());
    }
    // Given the block: a krb5 credential of the same user needs the KDC and fails there,
    let mut probe = connect_iso()?;
    let started = Instant::now();
    let blocked = probe.acquire(
        &CredRequest::new(Usage::Initiate)
            .named(PeerName::principal(&user_principal()?))
            .with_mechs(&[KRB5])
            .with_keytab(&harness::var("INTEROP_MIT_PEER_USER_KEYTAB_ID")?),
    );
    assert!(
        matches!(
            blocked,
            Err(PeerError::Gss {
                major: _,
                minor: _,
                text: _
            })
        ),
        "the isolated container reaches no KDC: {blocked:?}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(9),
        "the block fails fast"
    );
    // when IAKERB runs through the Rust acceptor and its relay,
    let (outcome, relay) = mit_to_rust(
        PeerName::principal(&user_principal()?),
        RelayPolicy::new(&realm()?)?,
    )?;
    // then the context stands, the relay carried the AS and TGS requests for the realm,
    let context = outcome?;
    assert!(
        relay.relayed >= 3,
        "AS probe, AS request and TGS request: {}",
        relay.relayed
    );
    assert!(
        relay
            .realms
            .iter()
            .all(|asked| *asked == realm().unwrap_or_default())
    );
    // and the Rust acceptor sees the user MIT authenticated through the KDC.
    let info = context.inquire();
    assert_eq!(info.source().display().0, user_principal()?);
    assert_eq!(
        Context::mechanism(),
        ObjectIdentifier::from_arcs(arcs(IAKERB)?)?
    );
    Ok(())
}

/// A name without a realm makes MIT's IAKERB initiator ask the acceptor for its
/// realm first (`iakerb.c:616-634`); the Rust acceptor answers it and the
/// context completes.
#[test]
fn mit_realm_discovery_completes_against_the_rust_acceptor() -> Result<(), Box<dyn Error>> {
    if !harness::require(
        "mit_realm_discovery_completes_against_the_rust_acceptor",
        &[MIT_KDC, PEER_ISO],
    )? {
        return Ok(());
    }
    let (outcome, relay) = mit_to_rust(
        PeerName::enterprise(&harness::var("INTEROP_MIT_PEER_USER")?),
        RelayPolicy::new(&realm()?)?,
    )?;
    let context = outcome?;
    assert!(
        relay.relayed >= 3,
        "the exchanges were relayed: {}",
        relay.relayed
    );
    assert_eq!(context.inquire().source().display().0, user_principal()?);
    Ok(())
}

/// A relay request for a realm the acceptor's policy does not name is refused and
/// never reaches the KDC.
#[test]
fn a_relay_request_for_a_realm_outside_the_policy_is_refused_live() -> Result<(), Box<dyn Error>> {
    if !harness::require(
        "a_relay_request_for_a_realm_outside_the_policy_is_refused_live",
        &[MIT_KDC, PEER_ISO],
    )? {
        return Ok(());
    }
    // Given a policy that names another realm only,
    let policy = RelayPolicy::new("OTHER.RSKRB5")?;
    let (outcome, relay) = mit_to_rust(PeerName::principal(&user_principal()?), policy)?;
    // then the MIT initiator's request for the fixture's realm is refused,
    let refusal = outcome.err().ok_or("the relay request must be refused")?;
    assert!(
        matches!(&refusal, Iakerb::RealmNotPermitted(asked) if *asked == realm().unwrap_or_default()),
        "{refusal}"
    );
    // and the relay was never called.
    assert_eq!(relay.relayed, 0);
    Ok(())
}

/// The scenarios of client keytabs and requested delegation (plan 2 todo 28).
#[path = "gaps.rs"]
mod gaps;
