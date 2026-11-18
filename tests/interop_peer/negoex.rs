//! The `negoextest` mechanism under SPNEGO/NegoEx.
//!
//! MIT's test mechanism (`plugins/gssapi/negoextest`) is loaded through the GSS
//! mechanism configuration the fixture ships; the adapter selects it per
//! connection. The two ends are adapter peers; the mechanism's environment
//! knobs (`HOPS`, `KEY`, `INIT_FAIL`, `GSS_INIT_BINDING`, ...) are set per
//! connection, and the NegoEx messages are read back from each side's trace.

use core::error::Error;
use std::net::TcpStream;

use super::{
    Established, PEER, SPNEGO, STANDARD_FLAGS, connect_main, establish, harness, service_name,
};
use crate::peer::{
    Peer,
    types::{AcceptRequest, InitRequest, PeerError},
};

/// `GSS_S_UNAVAILABLE`, the major status of the missing `NegoEx` verify key.
const GSS_S_UNAVAILABLE: u32 = 0x0010_0000;

/// GUID of the first negoextest mechanism (OID `2.25.1414534758`).
const GUID_FIRST: &str = "c0a28569-66ac-0000-0000-000000000000";

/// GUID of the second negoextest mechanism (OID `2.25.1175737388`).
const GUID_SECOND: &str = "d1b08469-2ca8-0000-0000-000000000000";

/// A connection to the adapter with the negoextest mechanisms loaded and `knobs` set.
fn negoex_peer(knobs: &[(&str, &str)]) -> Result<Peer<TcpStream>, Box<dyn Error>> {
    let mut adapter = connect_main()?;
    adapter.set_env("GSS_MECH_CONFIG", "negoextest")?;
    for (name, value) in knobs {
        adapter.set_env(name, value)?;
    }
    Ok(adapter)
}

/// Runs SPNEGO between two adapter connections; the krb5 mechanism has no
/// credentials in the adapter, so only the negoextest mechanisms can complete.
fn run(
    initiator: &mut Peer<TcpStream>,
    acceptor: &mut Peer<TcpStream>,
    bindings: Option<(&[u8], &[u8])>,
) -> Result<Established, Box<dyn Error>> {
    let mut init = InitRequest::new(service_name()?)
        .with_mech(SPNEGO)
        .with_flags(STANDARD_FLAGS);
    let mut accept = AcceptRequest::new(b"");
    if let Some((initiator_data, acceptor_data)) = bindings {
        init = init.with_bindings(initiator_data);
        accept = accept.with_bindings(acceptor_data);
    }
    establish(initiator, acceptor, &init, &accept)
}

/// Asserts that `trace` contains every fragment of `lines`.
fn assert_trace(side: &str, trace: &str, lines: &[&str]) {
    for line in lines {
        assert!(
            trace.contains(line),
            "the {side} trace lacks `{line}`; trace:\n{trace}"
        );
    }
}

/// Both negoextest mechanisms are listed by the GSS mechanism configuration, SPNEGO
/// negotiates them through `NegoEx` (the krb5 mechanism has no credentials), and the
/// two-hop exchange shows in both traces.
#[test]
fn negoextest_is_negotiated_under_spnego() -> Result<(), Box<dyn Error>> {
    if !harness::require("negoextest_is_negotiated_under_spnego", &[PEER])? {
        return Ok(());
    }
    let (mut initiator, mut acceptor) = (negoex_peer(&[("HOPS", "2")])?, negoex_peer(&[])?);
    let listed = initiator.mechs()?;
    for oid in harness::var("INTEROP_MIT_PEER_NEGOEX_OIDS")?.split(',') {
        assert!(
            listed.iter().any(|mech| mech == oid),
            "the GSS mechanism configuration lists {oid}: {listed:?}"
        );
    }
    let _pair = run(&mut initiator, &mut acceptor, None)?;
    assert_trace(
        "initiator",
        &initiator.trace()?,
        &[
            &format!("NegoEx sending [0]INITIATOR_NEGO: {GUID_FIRST} {GUID_SECOND}"),
            "NegoEx sending [3]AP_REQUEST: c0a28569-66ac",
            "NegoEx received [7]CHALLENGE: c0a28569-66ac",
            "NegoEx sending [9]VERIFY: c0a28569-66ac",
        ],
    );
    assert_trace(
        "acceptor",
        &acceptor.trace()?,
        &[
            &format!("NegoEx received [0]INITIATOR_NEGO: {GUID_FIRST} {GUID_SECOND}"),
            "NegoEx sending [7]CHALLENGE: c0a28569-66ac",
            "NegoEx received [9]VERIFY: c0a28569-66ac",
        ],
    );
    Ok(())
}

/// Channel bindings supplied to the adapter reach the mechanism: the test mechanism
/// asserts (and aborts the adapter otherwise) that its application data is what the
/// test passed.
#[test]
fn negoex_channel_bindings_reach_the_mechanism() -> Result<(), Box<dyn Error>> {
    if !harness::require("negoex_channel_bindings_reach_the_mechanism", &[PEER])? {
        return Ok(());
    }
    let mut initiator = negoex_peer(&[("HOPS", "1"), ("GSS_INIT_BINDING", "a")])?;
    let mut acceptor = negoex_peer(&[("GSS_ACCEPT_BINDING", "b")])?;
    let _pair = run(&mut initiator, &mut acceptor, Some((b"a", b"b")))?;
    assert_trace(
        "initiator",
        &initiator.trace()?,
        &[&format!(
            "NegoEx sending [0]INITIATOR_NEGO: {GUID_FIRST} {GUID_SECOND}"
        )],
    );
    Ok(())
}

/// When the first mechanism fails in the initiator the offer is only the second one;
/// without `NegoEx` keys the exchange fails with `GSS_S_UNAVAILABLE`.
#[test]
fn negoex_skips_a_failing_mechanism_and_needs_keys() -> Result<(), Box<dyn Error>> {
    if !harness::require("negoex_skips_a_failing_mechanism_and_needs_keys", &[PEER])? {
        return Ok(());
    }
    let mut initiator = negoex_peer(&[("INIT_FAIL", "102")])?;
    let mut acceptor = negoex_peer(&[])?;
    let _pair = run(&mut initiator, &mut acceptor, None)?;
    let trace = initiator.trace()?;
    assert_trace(
        "initiator",
        &trace,
        &[&format!("NegoEx sending [0]INITIATOR_NEGO: {GUID_SECOND}")],
    );
    assert!(
        !trace.contains(&format!("INITIATOR_NEGO: {GUID_FIRST}")),
        "the failing first mechanism is not offered"
    );

    let mut keyless = negoex_peer(&[("KEY", "never")])?;
    let mut counterpart = negoex_peer(&[("KEY", "never")])?;
    let failure = run(&mut keyless, &mut counterpart, None)
        .err()
        .ok_or("an exchange without NegoEx keys must fail")?;
    assert!(
        matches!(
            failure.downcast_ref::<PeerError>(),
            Some(PeerError::Gss { major, minor: _, text: _ }) if *major == GSS_S_UNAVAILABLE
        ),
        "MIT reports the missing NegoEx verify key as GSS_S_UNAVAILABLE, got: {failure}"
    );
    Ok(())
}
