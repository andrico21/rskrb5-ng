//! IAKERB against the MIT peer adapter.

use core::{error::Error, fmt::Display, time::Duration};
use std::{
    io::{Read as _, Write as _},
    net::{TcpStream, ToSocketAddrs as _},
    time::Instant,
};

use rskrb5_ng::{
    config::Config,
    error::Iakerb,
    gss::{
        self, AcceptorOptions, ContextFlags, CredStore, Credential, CredentialUsage,
        EstablishedContext, InitStep, InitiatorOptions, Name, NameType,
        iakerb::{AcceptStep, Context, KdcRelay, RelayFailure, RelayPolicy},
    },
    spnego::oid::ObjectIdentifier,
};
use tokio::{
    runtime::{Builder, Runtime},
    time::timeout,
};

use crate::{
    closed_port,
    harness::{self, Fixture},
    peer::{
        Peer,
        cred::{CredRequest, Name as PeerName, Usage},
        frame,
        reply::Protection,
        types::{AcceptRequest, ContextHandle, CredHandle, InitRequest, PeerError},
    },
};

/// The KDC fixture, which only the acceptors reach.
const MIT_KDC: Fixture = Fixture::new("mit-kdc", "INTEROP_MIT_KDC");

/// The adapter container with a route to the KDC.
const PEER: Fixture = Fixture::new("mit-peer", "INTEROP_MIT_PEER_ADDR");

/// The adapter container without a route to the KDC.
const PEER_ISO: Fixture = Fixture::new("mit-peer-iso", "INTEROP_MIT_PEER_ISO_ADDR");

/// The krb5 mechanism.
const KRB5: &str = "1.2.840.113554.1.2.2";

/// The IAKERB mechanism.
const IAKERB: &str = "1.3.6.1.5.2.5";

/// Mutual, replay, sequence, confidentiality and integrity.
const STANDARD_FLAGS: u32 = 0x3e;

/// Most steps of one exchange: AS probe and request, TGS, the AP exchange and slack.
const ROUNDS: usize = 12;

/// The current-thread Tokio runtime the scenarios run on.
fn runtime() -> Result<Runtime, Box<dyn Error>> {
    Ok(Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()?)
}

/// The realm of the fixture.
fn realm() -> Result<String, Box<dyn Error>> {
    harness::var("INTEROP_MIT_REALM")
}

/// A profile whose only KDC is a refused loopback port.
///
/// The client's direct path to the KDC is blocked. The realm offers SPAKE
/// realm-wide, and the exchanges here relay the ordinary AS exchange, so SPAKE
/// is pinned off: the encrypted timestamp answers.
fn blocked_config() -> Result<Config, Box<dyn Error>> {
    let realm = realm()?;
    let refused = closed_port::reserve_closed_tcp_port()?;
    Ok(Config::parse(&format!(
        "
[libdefaults]
 default_realm = {realm}
 dns_lookup_kdc = false
 dns_lookup_realm = false
 rdns = false
 dns_canonicalize_hostname = false
 spake_preauth_groups =

[realms]
 {realm} = {{
  kdc = 127.0.0.1:{refused}
 }}

[domain_realm]
 .test.rskrb5 = {realm}
"
    ))?)
}

/// The dotted OID `text` as arcs.
fn arcs(text: &str) -> Result<Vec<u32>, Box<dyn Error>> {
    Ok(text
        .split('.')
        .map(str::parse::<u32>)
        .collect::<Result<_, _>>()?)
}

/// Asserts that the adapter negotiated the mechanism `expected`.
fn assert_mechanism(expected: &str, actual: &str) -> Result<(), Box<dyn Error>> {
    Ok(harness::assert_negotiated_mechanism(
        &arcs(expected)?,
        &arcs(actual)?,
    )?)
}

/// `peeruser@TEST.RSKRB5`.
fn user_principal() -> Result<String, Box<dyn Error>> {
    Ok(format!(
        "{}@{}",
        harness::var("INTEROP_MIT_PEER_USER")?,
        realm()?
    ))
}

/// A connection to the adapter container with a KDC route.
fn connect_main() -> Result<Peer<TcpStream>, Box<dyn Error>> {
    Ok(frame::connect(&harness::var("INTEROP_MIT_PEER_ADDR")?)?)
}

/// A connection to the adapter container without a KDC route.
fn connect_iso() -> Result<Peer<TcpStream>, Box<dyn Error>> {
    Ok(frame::connect(&harness::var("INTEROP_MIT_PEER_ISO_ADDR")?)?)
}

/// The MIT acceptor's host-based name, `peer@mit-peer.test.rskrb5`.
fn mit_target() -> Result<Name, Box<dyn Error>> {
    Ok(Name::import(
        harness::var("INTEROP_MIT_PEER_SERVICE")?.as_bytes(),
        NameType::HostbasedService,
    )?)
}

/// An adapter acceptor credential for the IAKERB mechanism.
fn acceptor_cred(adapter: &mut Peer<TcpStream>) -> Result<CredHandle, Box<dyn Error>> {
    let request = CredRequest::new(Usage::Accept)
        .named(PeerName::hostbased(&harness::var(
            "INTEROP_MIT_PEER_SERVICE",
        )?))
        .with_mechs(&[IAKERB])
        .with_keytab(&harness::var("INTEROP_MIT_PEER_ACCEPTOR_KEYTAB_ID")?);
    Ok(adapter.acquire(&request)?.0)
}

/// Per-message tokens both ways between `context` and the adapter's `handle`.
fn exchange(
    context: &mut EstablishedContext,
    adapter: &mut Peer<TcpStream>,
    handle: ContextHandle,
) -> Result<(), Box<dyn Error>> {
    let sealed = adapter.wrap(handle, Protection::new(true), b"sealed by mit")?;
    assert_eq!(context.unwrap(sealed.token())?.message(), b"sealed by mit");
    let ours = context.wrap(b"sealed by rust", true)?;
    let theirs = adapter.unwrap(handle, &ours)?;
    assert_eq!(theirs.message(), b"sealed by rust");
    assert!(theirs.confidential(), "MIT sees a sealed message");
    let mic = context.get_mic(b"signed by rust")?;
    let _qop: u32 = adapter.verify_mic(handle, b"signed by rust", &mic)?;
    let their_mic = adapter.get_mic(handle, b"signed by mit")?;
    context.verify_mic(b"signed by mit", &their_mic)?;
    Ok(())
}

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

/// The application's relay: a plain TCP client of the KDC (RFC 4120 section 7.2.2
/// record marking), the only path the isolated initiator has to it.
struct TcpRelay {
    /// The KDC's `host:port`.
    kdc: String,
    /// How many requests were relayed.
    relayed: usize,
    /// The realms asked for.
    realms: Vec<String>,
}

impl KdcRelay for TcpRelay {
    fn relay(&mut self, realm: &str, request: &[u8]) -> Result<Vec<u8>, RelayFailure> {
        self.relayed = self.relayed.saturating_add(1);
        self.realms.push(realm.to_owned());
        let other = |cause: &dyn Display| RelayFailure::Other(cause.to_string());
        let address = self
            .kdc
            .to_socket_addrs()
            .map_err(|cause| other(&cause))?
            .next()
            .ok_or(RelayFailure::RealmUnknown)?;
        let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(5))
            .map_err(|_unreachable| RelayFailure::KdcUnreachable)?;
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(|cause| other(&cause))?;
        let length = u32::try_from(request.len()).map_err(|cause| other(&cause))?;
        stream
            .write_all(&[&length.to_be_bytes(), request].concat())
            .map_err(|cause| other(&cause))?;
        let mut mark = [0_u8; 4];
        stream
            .read_exact(&mut mark)
            .map_err(|_silent| RelayFailure::KdcUnreachable)?;
        let size = usize::try_from(u32::from_be_bytes(mark)).map_err(|cause| other(&cause))?;
        if size > 0x10_0000 {
            return Err(RelayFailure::Other("the KDC reply is too long".to_owned()));
        }
        let mut reply = vec![0_u8; size];
        stream
            .read_exact(&mut reply)
            .map_err(|cause| other(&cause))?;
        Ok(reply)
    }
}

/// The Rust acceptor credential from the keytab MIT exported.
fn rust_acceptor() -> Result<Credential, Box<dyn Error>> {
    let principal = harness::var("INTEROP_MIT_PEER_RUST_SERVICE")?;
    let (service, host) = principal
        .split_once('/')
        .ok_or("the Rust service is service/host")?;
    let target = Name::import(
        format!("{service}@{host}").as_bytes(),
        NameType::HostbasedService,
    )?;
    let store = CredStore::new().with(
        "keytab",
        &format!("FILE:{}", harness::var("INTEROP_MIT_PEER_RUST_KEYTAB")?),
    )?;
    Ok(Credential::acquire_cred_from(
        Some(&target),
        CredentialUsage::Accept,
        &store,
    )?)
}

/// The isolated MIT initiator's first request for the Rust acceptor: its
/// credential is the user's password, its mechanism IAKERB.
fn iso_request(
    adapter: &mut Peer<TcpStream>,
    name: PeerName,
) -> Result<InitRequest, Box<dyn Error>> {
    let credential = adapter.acquire(
        &CredRequest::new(Usage::Initiate)
            .named(name)
            .with_mechs(&[IAKERB])
            .with_password(harness::var("INTEROP_MIT_PEER_USER_PASSWORD")?.as_bytes()),
    )?;
    let target = format!(
        "{}@{}",
        harness::var("INTEROP_MIT_PEER_RUST_SERVICE")?,
        realm()?
    );
    Ok(InitRequest::new(PeerName::principal(&target))
        .with_cred(credential.0)
        .with_mech(IAKERB)
        .with_flags(STANDARD_FLAGS))
}

/// One MIT IAKERB initiator in the container without a KDC route against the
/// Rust acceptor under `policy`; the relay is the acceptor's only way to the KDC.
fn mit_to_rust(
    name: PeerName,
    policy: RelayPolicy,
) -> Result<(Result<EstablishedContext, Iakerb>, TcpRelay), Box<dyn Error>> {
    let mut adapter = connect_iso()?;
    let init = iso_request(&mut adapter, name)?;
    let store = rust_acceptor()?;
    let mut acceptor = gss::Acceptor::new(&store, AcceptorOptions::new())?;
    let mut context = Context::acceptor(policy);
    let mut relay = TcpRelay {
        kdc: harness::var("INTEROP_MIT_KDC")?,
        relayed: 0,
        realms: Vec::new(),
    };
    let mut step = adapter.init_step(&init)?;
    let handle = step.context();
    for _round in 0..ROUNDS {
        match context.accept_sec_context(&mut acceptor, &mut relay, step.token()) {
            Err(refusal) => return Ok((Err(refusal), relay)),
            Ok(AcceptStep::Continue(reply)) => {
                step = adapter.init_step(&init.clone().continuing(handle, &reply))?;
            }
            Ok(AcceptStep::Complete(accepted)) => {
                let answer = accepted.output_token().ok_or("an AP-REP")?.to_vec();
                let last = adapter.init_step(&init.clone().continuing(handle, &answer))?;
                assert!(
                    !last.continue_needed(),
                    "the AP-REP completes MIT's context"
                );
                assert_mechanism(IAKERB, last.mech())?;
                let mut established = accepted.into_context();
                let sealed = adapter.wrap(handle, Protection::new(true), b"sealed by mit")?;
                assert_eq!(
                    established.unwrap(sealed.token())?.message(),
                    b"sealed by mit"
                );
                return Ok((Ok(established), relay));
            }
            Ok(_) => return Err("an unknown acceptor step".into()),
        }
    }
    Err("the exchange did not complete".into())
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
