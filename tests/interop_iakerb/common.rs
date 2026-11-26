//! Fixtures, constants and helpers shared by the IAKERB scenarios.

use core::error::Error;
use std::net::TcpStream;

use rskrb5_ng::{
    config::Config,
    gss::{EstablishedContext, Name, NameType},
};
use tokio::runtime::{Builder, Runtime};

use crate::{
    closed_port,
    harness::{self, Fixture},
    peer::{
        Peer,
        cred::{CredRequest, Name as PeerName, Usage},
        frame,
        reply::Protection,
        types::{ContextHandle, CredHandle},
    },
};

/// The KDC fixture, which only the acceptors reach.
pub(super) const MIT_KDC: Fixture = Fixture::new("mit-kdc", "INTEROP_MIT_KDC");

/// The adapter container with a route to the KDC.
pub(super) const PEER: Fixture = Fixture::new("mit-peer", "INTEROP_MIT_PEER_ADDR");

/// The adapter container without a route to the KDC.
pub(super) const PEER_ISO: Fixture = Fixture::new("mit-peer-iso", "INTEROP_MIT_PEER_ISO_ADDR");

/// The krb5 mechanism.
pub(super) const KRB5: &str = "1.2.840.113554.1.2.2";

/// The IAKERB mechanism.
pub(super) const IAKERB: &str = "1.3.6.1.5.2.5";

/// Mutual, replay, sequence, confidentiality and integrity.
pub(super) const STANDARD_FLAGS: u32 = 0x3e;

/// Most steps of one exchange: AS probe and request, TGS, the AP exchange and slack.
pub(super) const ROUNDS: usize = 12;

/// The current-thread Tokio runtime the scenarios run on.
pub(super) fn runtime() -> Result<Runtime, Box<dyn Error>> {
    Ok(Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()?)
}

/// The realm of the fixture.
pub(super) fn realm() -> Result<String, Box<dyn Error>> {
    harness::var("INTEROP_MIT_REALM")
}

/// A profile whose only KDC is a refused loopback port.
///
/// The client's direct path to the KDC is blocked. The realm offers SPAKE
/// realm-wide, and the exchanges here relay the ordinary AS exchange, so SPAKE
/// is pinned off: the encrypted timestamp answers.
pub(super) fn blocked_config() -> Result<Config, Box<dyn Error>> {
    blocked_config_with("")
}

/// [`blocked_config`] with `extra` `[libdefaults]` relations.
pub(super) fn blocked_config_with(extra: &str) -> Result<Config, Box<dyn Error>> {
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
 {extra}

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
pub(super) fn arcs(text: &str) -> Result<Vec<u32>, Box<dyn Error>> {
    Ok(text
        .split('.')
        .map(str::parse::<u32>)
        .collect::<Result<_, _>>()?)
}

/// Asserts that the adapter negotiated the mechanism `expected`.
pub(super) fn assert_mechanism(expected: &str, actual: &str) -> Result<(), Box<dyn Error>> {
    Ok(harness::assert_negotiated_mechanism(
        &arcs(expected)?,
        &arcs(actual)?,
    )?)
}

/// `peeruser@TEST.RSKRB5`.
pub(super) fn user_principal() -> Result<String, Box<dyn Error>> {
    Ok(format!(
        "{}@{}",
        harness::var("INTEROP_MIT_PEER_USER")?,
        realm()?
    ))
}

/// A connection to the adapter container with a KDC route.
pub(super) fn connect_main() -> Result<Peer<TcpStream>, Box<dyn Error>> {
    Ok(frame::connect(&harness::var("INTEROP_MIT_PEER_ADDR")?)?)
}

/// A connection to the adapter container without a KDC route.
pub(super) fn connect_iso() -> Result<Peer<TcpStream>, Box<dyn Error>> {
    Ok(frame::connect(&harness::var("INTEROP_MIT_PEER_ISO_ADDR")?)?)
}

/// The MIT acceptor's host-based name, `peer@mit-peer.test.rskrb5`.
pub(super) fn mit_target() -> Result<Name, Box<dyn Error>> {
    Ok(Name::import(
        harness::var("INTEROP_MIT_PEER_SERVICE")?.as_bytes(),
        NameType::HostbasedService,
    )?)
}

/// An adapter acceptor credential for the IAKERB mechanism.
pub(super) fn acceptor_cred(adapter: &mut Peer<TcpStream>) -> Result<CredHandle, Box<dyn Error>> {
    let request = CredRequest::new(Usage::Accept)
        .named(PeerName::hostbased(&harness::var(
            "INTEROP_MIT_PEER_SERVICE",
        )?))
        .with_mechs(&[IAKERB])
        .with_keytab(&harness::var("INTEROP_MIT_PEER_ACCEPTOR_KEYTAB_ID")?);
    Ok(adapter.acquire(&request)?.0)
}

/// Per-message tokens both ways between `context` and the adapter's `handle`.
pub(super) fn exchange(
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
