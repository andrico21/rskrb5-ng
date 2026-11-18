//! Shared setup of the adapter scenarios: fixtures, names, credentials and the
//! helper that runs an initiator and an acceptor to an established context.

use core::error::Error;
use std::net::TcpStream;

use crate::{
    harness::{self, Fixture},
    peer::{
        Peer,
        cred::{CredRequest, Name, Usage},
        frame,
        reply::Step,
        types::{AcceptRequest, ContextHandle, CredHandle, InitRequest, PeerError},
    },
};

/// Framing limits, krb5, SPNEGO and DCE contexts between two adapter peers.
#[path = "adapter.rs"]
mod adapter;

/// Message operations of an established context.
#[path = "messages.rs"]
mod messages;

/// IAKERB with the KDC blocked from the initiator.
#[path = "iakerb.rs"]
mod iakerb;

/// The negoextest mechanism under SPNEGO/NegoEx.
#[path = "negoex.rs"]
mod negoex;

/// The crate's SPNEGO machinery against the adapter.
#[cfg(feature = "spnego")]
#[path = "rust.rs"]
mod rust;

/// The KDC fixture, which only the crate's own initiator and acceptor reach.
#[cfg(feature = "spnego")]
const MIT_KDC: Fixture = Fixture::new("mit-kdc", "INTEROP_MIT_KDC");

/// The adapter container with a route to the KDC.
const PEER: Fixture = Fixture::new("mit-peer", "INTEROP_MIT_PEER_ADDR");

/// The adapter container without a route to the KDC.
const PEER_ISO: Fixture = Fixture::new("mit-peer-iso", "INTEROP_MIT_PEER_ISO_ADDR");

/// The krb5 mechanism.
const KRB5: &str = "1.2.840.113554.1.2.2";

/// The SPNEGO mechanism.
const SPNEGO: &str = "1.3.6.1.5.5.2";

/// The IAKERB mechanism.
const IAKERB: &str = "1.3.6.1.5.2.5";

/// `GSS_C_MUTUAL_FLAG`.
const MUTUAL: u32 = 2;

/// `GSS_C_REPLAY_FLAG`.
const REPLAY: u32 = 4;

/// `GSS_C_SEQUENCE_FLAG`.
const SEQUENCE: u32 = 8;

/// `GSS_C_CONF_FLAG`.
const CONF: u32 = 16;

/// `GSS_C_INTEG_FLAG`.
const INTEG: u32 = 32;

/// `GSS_C_DCE_STYLE`.
const DCE_STYLE: u32 = 0x1000;

/// The flags every scenario asks for unless it says otherwise.
const STANDARD_FLAGS: u32 = MUTUAL | REPLAY | SEQUENCE | CONF | INTEG;

/// Most init/accept rounds before a scenario gives up.
const ROUNDS: usize = 8;

/// Connects to the adapter at the env-file key `key`.
fn connect(key: &str) -> Result<Peer<TcpStream>, Box<dyn Error>> {
    Ok(frame::connect(&harness::var(key)?)?)
}

/// A connection to the adapter container with a KDC route.
fn connect_main() -> Result<Peer<TcpStream>, Box<dyn Error>> {
    connect("INTEROP_MIT_PEER_ADDR")
}

/// A connection to the adapter container without a KDC route.
fn connect_iso() -> Result<Peer<TcpStream>, Box<dyn Error>> {
    connect("INTEROP_MIT_PEER_ISO_ADDR")
}

/// The initiator's principal, `peeruser@TEST.RSKRB5`.
fn user_principal() -> Result<String, Box<dyn Error>> {
    Ok(format!(
        "{}@{}",
        harness::var("INTEROP_MIT_PEER_USER")?,
        harness::var("INTEROP_MIT_REALM")?
    ))
}

/// The acceptor's principal, `peer/mit-peer.test.rskrb5@TEST.RSKRB5`.
fn service_principal() -> Result<String, Box<dyn Error>> {
    Ok(format!(
        "{}@{}",
        harness::var("INTEROP_MIT_PEER_SERVICE_PRINCIPAL")?,
        harness::var("INTEROP_MIT_REALM")?
    ))
}

/// The acceptor's host-based name, `peer@mit-peer.test.rskrb5`.
fn service_name() -> Result<Name, Box<dyn Error>> {
    Ok(Name::hostbased(&harness::var("INTEROP_MIT_PEER_SERVICE")?))
}

/// An acceptor credential for the adapter's service from its keytab.
fn acceptor_cred(
    adapter: &mut Peer<TcpStream>,
    mechs: &[&str],
) -> Result<CredHandle, Box<dyn Error>> {
    let request = CredRequest::new(Usage::Accept)
        .named(service_name()?)
        .with_mechs(mechs)
        .with_keytab(&harness::var("INTEROP_MIT_PEER_ACCEPTOR_KEYTAB_ID")?);
    Ok(adapter.acquire(&request)?.0)
}

/// An initiator credential of `peeruser` from its client keytab.
fn initiator_cred(
    adapter: &mut Peer<TcpStream>,
    mechs: &[&str],
) -> Result<CredHandle, Box<dyn Error>> {
    let request = CredRequest::new(Usage::Initiate)
        .named(Name::principal(&user_principal()?))
        .with_mechs(mechs)
        .with_keytab(&harness::var("INTEROP_MIT_PEER_USER_KEYTAB_ID")?);
    Ok(adapter.acquire(&request)?.0)
}

/// Two contexts that completed, with each side's last step.
#[derive(Debug)]
struct Established {
    /// The initiator's context handle.
    init_ctx: ContextHandle,
    /// The acceptor's context handle.
    accept_ctx: ContextHandle,
    /// The initiator's last step.
    init: Step,
    /// The acceptor's last step.
    accept: Step,
    /// The initiator's first token (what went on the wire first).
    first_token: Vec<u8>,
    /// How many accept steps ran.
    accept_steps: usize,
}

/// Runs `init` on `initiator` and `accept` on `acceptor` until both complete,
/// carrying each side's token to the other.
///
/// # Errors
///
/// Returns the adapter's error of a failed step, or a message when the exchange
/// stalls or does not complete within [`ROUNDS`] rounds.
fn establish(
    initiator: &mut Peer<TcpStream>,
    acceptor: &mut Peer<TcpStream>,
    init: &InitRequest,
    accept: &AcceptRequest,
) -> Result<Established, Box<dyn Error>> {
    let mut init_step = initiator.init_step(init)?;
    let init_ctx = init_step.context();
    let first_token = init_step.token().to_vec();
    let mut pending = first_token.clone();
    let mut init_done = !init_step.continue_needed();
    let mut accept_step: Option<Step> = None;
    let mut accept_steps = 0_usize;
    for _round in 0..ROUNDS {
        let mut reply = Vec::new();
        if !pending.is_empty() {
            let context = accept_step.as_ref().map(Step::context);
            let step = acceptor.accept_step(&accept.stepping(context, &pending))?;
            reply = step.token().to_vec();
            accept_step = Some(step);
            accept_steps = accept_steps.saturating_add(1);
            pending.clear();
        }
        if !init_done {
            if reply.is_empty() {
                return Err("the initiator waits for a token the acceptor did not send".into());
            }
            init_step = initiator.init_step(&init.clone().continuing(init_ctx, &reply))?;
            init_done = !init_step.continue_needed();
            pending = init_step.token().to_vec();
        }
        if init_done && pending.is_empty() {
            break;
        }
    }
    let accept_last = accept_step.ok_or("the acceptor never ran")?;
    if !init_done || accept_last.continue_needed() {
        return Err("the exchange did not complete".into());
    }
    Ok(Established {
        init_ctx,
        accept_ctx: accept_last.context(),
        init: init_step,
        accept: accept_last,
        first_token,
        accept_steps,
    })
}

/// The DER encoding of the SPNEGO mechanism OID, `1.3.6.1.5.5.2`, with its tag and length.
const SPNEGO_OID_DER: [u8; 8] = [0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];

/// Whether `token` is a SPNEGO token: it names the SPNEGO OID right after its
/// GSS wrapper header (the krb5 mechanism would name its own OID there).
fn is_spnego_token(token: &[u8]) -> bool {
    token
        .windows(SPNEGO_OID_DER.len())
        .take(8)
        .any(|window| window == SPNEGO_OID_DER)
}

/// The arcs of a dotted OID, for the harness's mechanism assertion.
fn arcs(oid: &str) -> Result<Vec<u32>, Box<dyn Error>> {
    oid.split('.')
        .map(|arc| arc.parse::<u32>().map_err(Into::into))
        .collect()
}

/// Asserts that the mechanism `actual` is the dotted OID `expected`.
///
/// # Errors
///
/// Returns the harness's `NotNegotiated` naming both mechanisms.
fn assert_mechanism(expected: &str, actual: &str) -> Result<(), Box<dyn Error>> {
    Ok(harness::assert_negotiated_mechanism(
        &arcs(expected)?,
        &arcs(actual)?,
    )?)
}

/// Whether `result` is a GSS error reported by the adapter.
fn is_gss_error<T>(result: &Result<T, PeerError>) -> bool {
    matches!(
        result,
        Err(PeerError::Gss {
            major: _,
            minor: _,
            text: _
        })
    )
}
