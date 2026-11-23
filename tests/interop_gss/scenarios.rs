//! Rust GSS contexts against the MIT peer adapter.

use core::{error::Error, time::Duration};
use std::{io, net::TcpStream};

use rskrb5_ng::{
    config::Config,
    error::Gss,
    gss::{
        self, ChannelBindings, ContextFlags, CredStore, Credential, CredentialUsage,
        EstablishedContext, InitStep, InitiatorOptions, Name, NameType,
    },
    spnego::{self, oid::ObjectIdentifier},
};
use tokio::{
    runtime::{Builder, Runtime},
    time::timeout,
};

use crate::{
    harness::{self, Fixture},
    peer::{
        Peer,
        cred::{CredRequest, Name as PeerName, Usage},
        frame,
        reply::Protection,
        types::{AcceptRequest, ContextHandle, CredHandle, PeerError},
    },
};

/// The scenarios with the MIT initiator.
#[path = "mit_initiator.rs"]
mod mit_initiator;

/// The KDC fixture.
const MIT_KDC: Fixture = Fixture::new("mit-kdc", "INTEROP_MIT_KDC");

/// The adapter container with a KDC route.
const PEER: Fixture = Fixture::new("mit-peer", "INTEROP_MIT_PEER_ADDR");

/// The krb5 mechanism.
const KRB5: &str = "1.2.840.113554.1.2.2";

/// The SPNEGO mechanism.
const SPNEGO: &str = "1.3.6.1.5.5.2";

/// Mutual, replay, sequence, confidentiality and integrity.
const STANDARD_FLAGS: u32 = 0x3e;

/// `GSS_C_DELEG_FLAG`.
const DELEG: u32 = 1;

/// `GSS_C_CHANNEL_BOUND_FLAG`.
const CHANNEL_BOUND: u32 = 0x800;

/// `GSS_C_AF_NULLADDR`, the address type the adapter gives application-data
/// bindings (`scripts/interop/peer-mit/peer/peer_ctx.c`).
const NULLADDR: u32 = 255;

/// The routine-error field of `GSS_S_BAD_BINDINGS`.
const BAD_BINDINGS: u32 = 0x0004_0000;

/// The current-thread Tokio runtime the scenarios run on.
fn runtime() -> io::Result<Runtime> {
    Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
}

/// A configuration naming the fixture's KDC, with `extra` `[libdefaults]` lines.
fn config(extra: &str) -> Result<Config, Box<dyn Error>> {
    let realm = harness::var("INTEROP_MIT_REALM")?;
    let kdc = harness::var("INTEROP_MIT_KDC")?;
    Ok(Config::parse(&format!(
        "
[libdefaults]
 default_realm = {realm}
 dns_lookup_kdc = false
 dns_lookup_realm = false
 rdns = false
 dns_canonicalize_hostname = false
{extra}
[realms]
 {realm} = {{
  kdc = {kdc}
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

/// Asserts that the adapter negotiated the krb5 mechanism.
fn assert_krb5(actual: &str) -> Result<(), Box<dyn Error>> {
    Ok(harness::assert_negotiated_mechanism(
        ObjectIdentifier::krb5().arcs(),
        &arcs(actual)?,
    )?)
}

/// A connection to the adapter.
fn connect() -> Result<Peer<TcpStream>, Box<dyn Error>> {
    Ok(frame::connect(&harness::var("INTEROP_MIT_PEER_ADDR")?)?)
}

/// An adapter acceptor credential for `peer@mit-peer.test.rskrb5`.
fn acceptor_cred(adapter: &mut Peer<TcpStream>, mech: &str) -> Result<CredHandle, Box<dyn Error>> {
    let request = CredRequest::new(Usage::Accept)
        .named(PeerName::hostbased(&harness::var(
            "INTEROP_MIT_PEER_SERVICE",
        )?))
        .with_mechs(&[mech])
        .with_keytab(&harness::var("INTEROP_MIT_PEER_ACCEPTOR_KEYTAB_ID")?);
    Ok(adapter.acquire(&request)?.0)
}

/// An adapter initiator credential of `peeruser`.
fn initiator_cred(adapter: &mut Peer<TcpStream>, mech: &str) -> Result<CredHandle, Box<dyn Error>> {
    let user = format!(
        "{}@{}",
        harness::var("INTEROP_MIT_PEER_USER")?,
        harness::var("INTEROP_MIT_REALM")?
    );
    let request = CredRequest::new(Usage::Initiate)
        .named(PeerName::principal(&user))
        .with_mechs(&[mech])
        .with_keytab(&harness::var("INTEROP_MIT_PEER_USER_KEYTAB_ID")?);
    Ok(adapter.acquire(&request)?.0)
}

/// Application-data bindings as the adapter builds them.
fn bindings(data: &[u8]) -> Result<ChannelBindings, Box<dyn Error>> {
    Ok(ChannelBindings::new(data.to_vec())?
        .with_initiator_address(NULLADDR, Vec::new())?
        .with_acceptor_address(NULLADDR, Vec::new())?)
}

/// `testuser1@TEST.RSKRB5`.
fn user() -> Result<String, Box<dyn Error>> {
    Ok(format!(
        "{}@{}",
        harness::var("INTEROP_MIT_USER")?,
        harness::var("INTEROP_MIT_REALM")?
    ))
}

/// The MIT acceptor's host-based name.
fn mit_target() -> Result<Name, Box<dyn Error>> {
    Ok(Name::import(
        harness::var("INTEROP_MIT_PEER_SERVICE")?.as_bytes(),
        NameType::HostbasedService,
    )?)
}

/// A credential of the test user from `store`, holding a ticket for `target`.
fn acquired(
    store: &CredStore,
    target: &Name,
    config: &Config,
) -> Result<Credential, Box<dyn Error>> {
    let name = Name::import(user()?.as_bytes(), NameType::Principal)?;
    let mut credential =
        Credential::acquire_cred_from(Some(&name), CredentialUsage::Initiate, store)?;
    runtime()?.block_on(async {
        timeout(
            Duration::from_secs(30),
            credential.acquire_service_ticket(target, config),
        )
        .await
    })??;
    Ok(credential)
}

/// A password credential of the test user holding a ticket for `target`.
fn password_credential(target: &Name, config: &Config) -> Result<Credential, Box<dyn Error>> {
    let store = CredStore::new().with("password", &harness::var("INTEROP_MIT_USER_PASSWORD")?)?;
    acquired(&store, target, config)
}

/// Per-message tokens both ways between `context` and the adapter's `handle`.
fn exchange(
    context: &mut EstablishedContext,
    adapter: &mut Peer<TcpStream>,
    handle: ContextHandle,
) -> Result<(), Box<dyn Error>> {
    let sealed = adapter.wrap(handle, Protection::new(true), b"sealed by mit")?;
    let opened = context.unwrap(sealed.token())?;
    assert_eq!(opened.message(), b"sealed by mit");
    assert!(opened.confidential(), "MIT sealed the message");
    let ours = context.wrap(b"sealed by rust", true)?;
    let theirs = adapter.unwrap(handle, &ours)?;
    assert_eq!(theirs.message(), b"sealed by rust");
    assert!(theirs.confidential(), "MIT sees a sealed message");
    let plain = context.wrap(b"integrity only", false)?;
    assert!(!adapter.unwrap(handle, &plain)?.confidential());
    let mic = context.get_mic(b"signed by rust")?;
    let _qop: u32 = adapter.verify_mic(handle, b"signed by rust", &mic)?;
    let their_mic = adapter.get_mic(handle, b"signed by mit")?;
    context.verify_mic(b"signed by mit", &their_mic)?;
    assert!(
        matches!(
            context.verify_mic(b"signed by mit", &their_mic),
            Err(Gss::DuplicateToken(_))
        ),
        "a replayed MIT token is refused"
    );
    Ok(())
}

/// One Rust initiator run against the MIT acceptor: the adapter's answer or
/// its refusal, and the established context on success.
fn rust_to_mit(
    credential: &Credential,
    options: InitiatorOptions,
    acceptor_bindings: Option<&[u8]>,
) -> Result<Result<(), PeerError>, Box<dyn Error>> {
    let mut initiator = gss::Initiator::new(mit_target()?, options);
    let InitStep::Continue(token) = initiator.init_sec_context(credential, None)? else {
        return Err("mutual authentication waits for the AP-REP".into());
    };
    let mut adapter = connect()?;
    let mut request = AcceptRequest::new(&token).with_cred(acceptor_cred(&mut adapter, KRB5)?);
    if let Some(data) = acceptor_bindings {
        request = request.with_bindings(data);
    }
    let step = match adapter.accept_step(&request) {
        Ok(step) => step,
        Err(refusal) => return Ok(Err(refusal)),
    };
    assert_krb5(step.mech())?;
    assert_eq!(step.source(), user()?, "MIT sees the Rust initiator");
    let bound = step.flags() & CHANNEL_BOUND != 0;
    let InitStep::Complete(None) = initiator.init_sec_context(credential, Some(step.token()))?
    else {
        return Err("the MIT AP-REP completes the Rust initiator".into());
    };
    let mut context = initiator.into_established()?;
    assert!(context.inquire().flags().contains(ContextFlags::MUTUAL));
    exchange(&mut context, &mut adapter, step.context())?;
    assert_eq!(
        bound,
        acceptor_bindings.is_some(),
        "MIT reports a channel-bound context exactly when both ends bound it"
    );
    Ok(Ok(()))
}

/// The Rust GSS initiator is accepted by MIT's acceptor, bound or not.
///
/// The credential comes from the `password` store key; per-message tokens work
/// both ways, and MIT refuses mismatched bindings with `GSS_S_BAD_BINDINGS`.
#[test]
fn rust_gss_initiator_is_accepted_by_the_mit_acceptor() -> Result<(), Box<dyn Error>> {
    if !harness::require(
        "rust_gss_initiator_is_accepted_by_the_mit_acceptor",
        &[MIT_KDC, PEER],
    )? {
        return Ok(());
    }
    let credential = password_credential(&mit_target()?, &config("")?)?;
    let blob = b"tls-server-end-point:rust-to-mit".as_slice();
    rust_to_mit(&credential, InitiatorOptions::new(), None)??;
    rust_to_mit(
        &credential,
        InitiatorOptions::new().with_channel_bindings(bindings(blob)?),
        Some(blob),
    )??;
    let refused = rust_to_mit(
        &credential,
        InitiatorOptions::new().with_channel_bindings(bindings(blob)?),
        Some(b"tls-server-end-point:another-channel"),
    )?;
    assert!(
        matches!(refused, Err(PeerError::Gss { major, minor: _, text: _ }) if major & 0x00ff_0000 == BAD_BINDINGS),
        "MIT refuses mismatched bindings: {refused:?}"
    );
    Ok(())
}

/// MIT enforces the CBT assertion of a client-aware Rust initiator.
///
/// `client_aware_channel_bindings` makes the Rust initiator send MS-KILE
/// `KERB_AP_OPTIONS_CBT`; MIT's acceptor with bindings then refuses a token
/// without them (MIT `accept_sec_context.c:604-617`) and accepts the same
/// initiator when it has no bindings.
#[test]
fn mit_enforces_the_cbt_assertion_of_a_client_aware_rust_initiator() -> Result<(), Box<dyn Error>> {
    if !harness::require(
        "mit_enforces_the_cbt_assertion_of_a_client_aware_rust_initiator",
        &[MIT_KDC, PEER],
    )? {
        return Ok(());
    }
    let config = config(" client_aware_channel_bindings = true\n")?;
    let credential = password_credential(&mit_target()?, &config)?;
    let aware = InitiatorOptions::from_config(&config);
    assert!(aware.client_aware_channel_bindings());
    let refused = rust_to_mit(&credential, aware.clone(), Some(b"tls-server-end-point:x"))?;
    assert!(
        matches!(refused, Err(PeerError::Gss { major, minor: _, text: _ }) if major & 0x00ff_0000 == BAD_BINDINGS),
        "MIT requires bindings of a CBT-aware initiator: {refused:?}"
    );
    rust_to_mit(&credential, aware, None)??;
    Ok(())
}

/// A client keytab credential (`client_keytab` store key) acquires its initial
/// ticket and the service ticket from the KDC and is accepted by MIT.
#[test]
fn a_client_keytab_credential_acquires_its_tickets() -> Result<(), Box<dyn Error>> {
    if !harness::require(
        "a_client_keytab_credential_acquires_its_tickets",
        &[MIT_KDC, PEER],
    )? {
        return Ok(());
    }
    let store = CredStore::new().with(
        "client_keytab",
        &format!("FILE:{}", harness::var("INTEROP_MIT_USER_KEYTAB")?),
    )?;
    let credential = acquired(&store, &mit_target()?, &config("")?)?;
    assert!(
        credential.inquire().expires().is_some(),
        "the credential holds its acquired tickets"
    );
    rust_to_mit(&credential, InitiatorOptions::new(), None)??;
    Ok(())
}

/// The Rust SPNEGO initiator over the GSS contexts negotiates krb5 with MIT's
/// SPNEGO acceptor, and the context protects messages both ways.
#[test]
fn rust_spnego_over_gss_negotiates_with_the_mit_acceptor() -> Result<(), Box<dyn Error>> {
    if !harness::require(
        "rust_spnego_over_gss_negotiates_with_the_mit_acceptor",
        &[MIT_KDC, PEER],
    )? {
        return Ok(());
    }
    let credential = password_credential(&mit_target()?, &config("")?)?;
    let mut initiator =
        spnego::Initiator::new(gss::Initiator::new(mit_target()?, InitiatorOptions::new()));
    let InitStep::Continue(offer) = initiator.init_sec_context(&credential, None)? else {
        return Err("mutual authentication waits".into());
    };
    let mut adapter = connect()?;
    let cred = acceptor_cred(&mut adapter, SPNEGO)?;
    let step = adapter.accept_step(&AcceptRequest::new(&offer).with_cred(cred))?;
    assert_krb5(step.mech())?;
    let InitStep::Complete(None) = initiator.init_sec_context(&credential, Some(step.token()))?
    else {
        return Err("MIT's NegTokenResp completes the SPNEGO initiator".into());
    };
    let mut context = initiator.into_established()?;
    exchange(&mut context, &mut adapter, step.context())
}
