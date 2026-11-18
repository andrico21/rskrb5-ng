//! The crate's SPNEGO machinery against the adapter, as far as the current crate goes.
//!
//! The crate's initiator is ticket-based (`spnego::init_sec_context`) and its
//! acceptor validates an AP-REQ against a keytab (`spnego::accept_sec_context_header`);
//! it has no GSS context object yet (todo 18), so these scenarios exchange the
//! SPNEGO tokens and the AP-REP, and assert the negotiated mechanism and the peer
//! principal. Wrap, MIC, IOV, AEAD, PRF and export between Rust and MIT come with
//! the GSS core (todos 18 and 19): the adapter already offers them.

use core::{error::Error, time::Duration};
use std::{io, time::SystemTime};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use rskrb5_ng::{
    client::{
        Tokio,
        principal::Principal,
        transport::{KdcProtocol, Tokio as TokioKdcTransport},
    },
    config::Config,
    keytab::Keytab,
    service::{ApRepOptions, Principal as ServicePrincipal, Validator},
    spnego::{self, InitiatorContextOptions, oid::ObjectIdentifier},
};
use tokio::runtime::{Builder, Runtime};

use super::{
    KRB5, MIT_KDC, PEER, SPNEGO, STANDARD_FLAGS, acceptor_cred, assert_mechanism, connect_main,
    initiator_cred, is_spnego_token, service_principal,
};
use crate::{
    harness::{self, assert_negotiated_mechanism},
    peer::{
        cred::Name,
        types::{AcceptRequest, InitRequest},
    },
};

/// The `AP-OPTIONS` bit `mutual-required` of RFC 4120.
const AP_OPTION_MUTUAL_REQUIRED: u32 = 0x2000_0000;

/// The current-thread Tokio runtime the scenarios run on.
fn runtime() -> io::Result<Runtime> {
    Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
}

/// A configuration naming the fixture's KDC.
fn config() -> Result<Config, Box<dyn Error>> {
    let realm = harness::var("INTEROP_MIT_REALM")?;
    let kdc = harness::var("INTEROP_MIT_KDC")?;
    Ok(Config::parse(&format!(
        "
[libdefaults]
 default_realm = {realm}
 dns_lookup_kdc = false

[realms]
 {realm} = {{
  kdc = {kdc}
 }}
"
    ))?)
}

/// The `Negotiate` header carrying `token`.
fn header_of(token: &[u8]) -> String {
    format!("Negotiate {}", STANDARD.encode(token))
}

/// The token bytes inside a `Negotiate` header.
fn token_of(header: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let encoded = header
        .strip_prefix("Negotiate ")
        .ok_or("the header is not a Negotiate header")?;
    Ok(STANDARD.decode(encoded)?)
}

/// The crate's SPNEGO initiator (a ticket of the MIT KDC for the adapter's service)
/// is accepted by the adapter's MIT acceptor: the krb5 mechanism is negotiated
/// under SPNEGO, the adapter sees the test user, and the adapter's AP-REP
/// verifies on the Rust side.
#[test]
fn rust_spnego_initiator_is_accepted_by_the_adapter() -> Result<(), Box<dyn Error>> {
    if !harness::require(
        "rust_spnego_initiator_is_accepted_by_the_adapter",
        &[MIT_KDC, PEER],
    )? {
        return Ok(());
    }
    let realm = harness::var("INTEROP_MIT_REALM")?;
    let service = harness::var("INTEROP_MIT_PEER_SERVICE_PRINCIPAL")?;
    let (ticket_client_token, context) = runtime()?.block_on(async {
        let mut client = Tokio::with_password(
            config()?,
            KdcProtocol::Auto,
            Principal::user(realm.clone(), harness::var("INTEROP_MIT_USER")?),
            harness::var("INTEROP_MIT_USER_PASSWORD")?.into_bytes(),
        )
        .with_transport(TokioKdcTransport::new().with_timeout(Duration::from_secs(10)));
        let ticket = client
            .get_service_ticket(Principal::new(realm.clone(), 2, service.split('/')))
            .await?;
        // Mutual authentication: the MUTUAL-REQUIRED AP option makes MIT answer with an AP-REP.
        let options = InitiatorContextOptions::new()
            .with_context_flags(vec![
                spnego::CONTEXT_FLAG_MUTUAL,
                spnego::CONTEXT_FLAG_INTEG,
                spnego::CONTEXT_FLAG_CONF,
            ])
            .with_ap_option_bits(AP_OPTION_MUTUAL_REQUIRED);
        let context = spnego::init_sec_context(&ticket, options)
            .map_err(|error| format!("the initiator could not build the token: {error}"))?;
        Ok::<_, Box<dyn Error>>((token_of(context.header_ref())?, context))
    })?;

    assert!(
        is_spnego_token(&ticket_client_token),
        "the Rust initiator sends a SPNEGO token"
    );
    let mut adapter = connect_main()?;
    let cred = acceptor_cred(&mut adapter, &[SPNEGO])?;
    let step = adapter.accept_step(&AcceptRequest::new(&ticket_client_token).with_cred(cred))?;
    assert!(
        !step.continue_needed(),
        "the adapter completes on the AP-REQ"
    );
    assert_eq!(
        step.source(),
        format!("{}@{realm}", harness::var("INTEROP_MIT_USER")?),
        "the adapter sees the Rust initiator's principal"
    );
    assert_mechanism(KRB5, step.mech())?;
    let info = adapter.inquire(step.context())?;
    assert_mechanism(KRB5, info.mech())?;
    assert_eq!(
        info.target(),
        service_principal()?,
        "the adapter accepted for its own service principal"
    );
    let verified = context
        .verify_ap_rep_response_header(&header_of(step.token()))
        .map_err(|error| format!("the initiator refused the adapter's AP-REP: {error}"))?;
    assert_eq!(
        verified.ctime(),
        context.authenticator_ctime(),
        "the AP-REP answers this authenticator"
    );
    Ok(())
}

/// The adapter's MIT SPNEGO initiator is accepted by the crate's acceptor with a
/// keytab MIT exported: the krb5 mechanism is selected, the acceptor sees the
/// adapter's principal, and the acceptor's AP-REP completes the adapter's context.
#[test]
fn adapter_spnego_initiator_is_accepted_by_the_rust_acceptor() -> Result<(), Box<dyn Error>> {
    if !harness::require(
        "adapter_spnego_initiator_is_accepted_by_the_rust_acceptor",
        &[MIT_KDC, PEER],
    )? {
        return Ok(());
    }
    let realm = harness::var("INTEROP_MIT_REALM")?;
    let mut adapter = connect_main()?;
    let cred = initiator_cred(&mut adapter, &[SPNEGO])?;
    let target = format!("{}@{realm}", harness::var("INTEROP_MIT_PEER_RUST_SERVICE")?);
    let init = InitRequest::new(Name::principal(&target))
        .with_cred(cred)
        .with_mech(SPNEGO)
        .with_flags(STANDARD_FLAGS);
    let first = adapter.init_step(&init)?;
    assert!(
        first.continue_needed(),
        "mutual authentication waits for the AP-REP"
    );

    let keytab = Keytab::load(harness::var("INTEROP_MIT_PEER_RUST_KEYTAB")?)?;
    let mut validator = Validator::new(&keytab).with_now(SystemTime::now());
    let accepted = spnego::accept_sec_context_header(&mut validator, &header_of(first.token()))
        .map_err(|error| format!("the acceptor refused the adapter's token: {error}"))?;
    assert_negotiated_mechanism(
        ObjectIdentifier::krb5().arcs(),
        accepted.selected_mechanism().arcs(),
    )?;
    assert_eq!(
        accepted.ap_req().client().clone(),
        ServicePrincipal::new(realm, 1, vec![harness::var("INTEROP_MIT_PEER_USER")?]),
        "the acceptor sees the adapter's principal"
    );
    let answer = accepted.ap_rep_response_header(&ApRepOptions::default())?;
    let last = adapter.init_step(&init.continuing(first.context(), &token_of(&answer)?))?;
    assert!(
        !last.continue_needed(),
        "the Rust acceptor's AP-REP completes the adapter's context"
    );
    assert_mechanism(KRB5, adapter.inquire(last.context())?.mech())?;
    Ok(())
}
