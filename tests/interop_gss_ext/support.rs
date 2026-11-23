//! Shared helpers of the GSS-API II scenarios.
//!
//! The fixture's names and credentials, established Rust/MIT context pairs,
//! and the adapter requests the typed client does not wrap (an IOV unwrap of
//! Rust-made buffers and the accept step that keeps a delegated credential).

use core::{error::Error, time::Duration};
use std::{io, net::TcpStream};

use rskrb5_ng::{
    config::Config,
    gss::{
        self, AcceptorOptions, ContextFlags, CredStore, Credential, CredentialUsage, InitStep,
        InitiatorOptions, IovBuffer, IovKind, Name, NameType,
    },
    spnego::oid::ObjectIdentifier,
};
use tokio::{
    runtime::{Builder, Runtime},
    time::timeout,
};

use super::{DelegAccept, Pair};
use crate::{
    harness::{self, Fixture},
    peer::{
        Peer,
        cred::{CredRequest, Name as PeerName, Usage},
        frame::{self, Fields},
        reply::{Protection, Unsealed},
        types::{AcceptRequest, CredHandle, InitRequest, PeerError},
    },
};

/// The KDC fixture.
pub(super) const MIT_KDC: Fixture = Fixture::new("mit-kdc", "INTEROP_MIT_KDC");

/// The adapter container with a KDC route.
pub(super) const PEER: Fixture = Fixture::new("mit-peer", "INTEROP_MIT_PEER_ADDR");

/// The krb5 mechanism.
pub(super) const KRB5: &str = "1.2.840.113554.1.2.2";

/// Mutual, replay, sequence, confidentiality and integrity.
pub(super) const STANDARD_FLAGS: u32 = 0x3e;

/// `GSS_C_DELEG_FLAG`.
pub(super) const DELEG: u32 = 1;

/// `GSS_C_DCE_STYLE`.
pub(super) const DCE: u32 = 0x1000;

/// The current-thread Tokio runtime the scenarios run on.
pub(super) fn runtime() -> io::Result<Runtime> {
    Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
}

/// A configuration naming the fixture's KDC, with `extra` `[libdefaults]` lines.
pub(super) fn config(extra: &str) -> Result<Config, Box<dyn Error>> {
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

/// Asserts that the adapter negotiated the krb5 mechanism.
pub(super) fn assert_krb5(actual: &str) -> Result<(), Box<dyn Error>> {
    let arcs = actual
        .split('.')
        .map(str::parse::<u32>)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(harness::assert_negotiated_mechanism(
        ObjectIdentifier::krb5().arcs(),
        &arcs,
    )?)
}

/// A connection to the adapter.
pub(super) fn connect() -> Result<Peer<TcpStream>, Box<dyn Error>> {
    Ok(frame::connect(&harness::var("INTEROP_MIT_PEER_ADDR")?)?)
}

/// An adapter krb5 acceptor credential for `peer@mit-peer.test.rskrb5`.
pub(super) fn acceptor_cred(adapter: &mut Peer<TcpStream>) -> Result<CredHandle, Box<dyn Error>> {
    let request = CredRequest::new(Usage::Accept)
        .named(PeerName::hostbased(&harness::var(
            "INTEROP_MIT_PEER_SERVICE",
        )?))
        .with_mechs(&[KRB5])
        .with_keytab(&harness::var("INTEROP_MIT_PEER_ACCEPTOR_KEYTAB_ID")?);
    Ok(adapter.acquire(&request)?.0)
}

/// An adapter krb5 initiator credential of `peeruser`.
pub(super) fn initiator_cred(adapter: &mut Peer<TcpStream>) -> Result<CredHandle, Box<dyn Error>> {
    let request = CredRequest::new(Usage::Initiate)
        .named(PeerName::principal(&peer_user()?))
        .with_mechs(&[KRB5])
        .with_keytab(&harness::var("INTEROP_MIT_PEER_USER_KEYTAB_ID")?);
    Ok(adapter.acquire(&request)?.0)
}

/// `testuser1@TEST.RSKRB5`, the Rust side's user.
pub(super) fn user() -> Result<String, Box<dyn Error>> {
    Ok(format!(
        "{}@{}",
        harness::var("INTEROP_MIT_USER")?,
        harness::var("INTEROP_MIT_REALM")?
    ))
}

/// `peeruser@TEST.RSKRB5`, the adapter's user.
pub(super) fn peer_user() -> Result<String, Box<dyn Error>> {
    Ok(format!(
        "{}@{}",
        harness::var("INTEROP_MIT_PEER_USER")?,
        harness::var("INTEROP_MIT_REALM")?
    ))
}

/// The MIT acceptor's host-based name.
pub(super) fn mit_target() -> Result<Name, Box<dyn Error>> {
    Ok(Name::import(
        harness::var("INTEROP_MIT_PEER_SERVICE")?.as_bytes(),
        NameType::HostbasedService,
    )?)
}

/// The Rust acceptor credential from the keytab MIT exported.
pub(super) fn rust_acceptor() -> Result<Credential, Box<dyn Error>> {
    let principal = harness::var("INTEROP_MIT_PEER_RUST_SERVICE")?;
    let (service, host) = principal
        .split_once('/')
        .ok_or("the Rust service is service/host")?;
    let name = Name::import(
        format!("{service}@{host}").as_bytes(),
        NameType::HostbasedService,
    )?;
    let store = CredStore::new().with(
        "keytab",
        &format!("FILE:{}", harness::var("INTEROP_MIT_PEER_RUST_KEYTAB")?),
    )?;
    Ok(Credential::acquire_cred_from(
        Some(&name),
        CredentialUsage::Accept,
        &store,
    )?)
}

/// The adapter's krb5 init request for the Rust acceptor with `flags`.
pub(super) fn mit_init(flags: u32) -> Result<InitRequest, Box<dyn Error>> {
    let target = format!(
        "{}@{}",
        harness::var("INTEROP_MIT_PEER_RUST_SERVICE")?,
        harness::var("INTEROP_MIT_REALM")?
    );
    Ok(InitRequest::new(PeerName::principal(&target))
        .with_mech(KRB5)
        .with_flags(flags))
}

/// A password credential of the test user holding a ticket for `target`.
pub(super) fn password_credential(
    target: &Name,
    config: &Config,
) -> Result<Credential, Box<dyn Error>> {
    let store = CredStore::new().with("password", &harness::var("INTEROP_MIT_USER_PASSWORD")?)?;
    let name = Name::import(user()?.as_bytes(), NameType::Principal)?;
    let mut credential =
        Credential::acquire_cred_from(Some(&name), CredentialUsage::Initiate, &store)?;
    runtime()?.block_on(async {
        timeout(
            Duration::from_secs(30),
            credential.acquire_service_ticket(target, config),
        )
        .await
    })??;
    Ok(credential)
}

/// The initiator options with `extra` flags added.
pub(super) fn flagged(extra: ContextFlags) -> InitiatorOptions {
    InitiatorOptions::new().with_flags(InitiatorOptions::new().flags() | extra)
}

/// A Rust initiator (the test user's password credential) accepted by MIT.
pub(super) fn rust_initiated() -> Result<Pair, Box<dyn Error>> {
    let credential = password_credential(&mit_target()?, &config("")?)?;
    let mut initiator = gss::Initiator::new(mit_target()?, InitiatorOptions::new());
    let InitStep::Continue(token) = initiator.init_sec_context(&credential, None)? else {
        return Err("mutual authentication waits for the AP-REP".into());
    };
    let mut adapter = connect()?;
    let cred = acceptor_cred(&mut adapter)?;
    let step = adapter.accept_step(&AcceptRequest::new(&token).with_cred(cred))?;
    assert_krb5(step.mech())?;
    assert_eq!(step.source(), user()?, "MIT sees the Rust initiator");
    let InitStep::Complete(None) = initiator.init_sec_context(&credential, Some(step.token()))?
    else {
        return Err("the MIT AP-REP completes the Rust initiator".into());
    };
    Ok(Pair {
        context: initiator.into_established()?,
        adapter,
        handle: step.context(),
    })
}

/// An MIT initiator (`peeruser`) accepted by the Rust acceptor.
pub(super) fn mit_initiated() -> Result<Pair, Box<dyn Error>> {
    let mut adapter = connect()?;
    let init = mit_init(STANDARD_FLAGS)?.with_cred(initiator_cred(&mut adapter)?);
    let first = adapter.init_step(&init)?;
    let store = rust_acceptor()?;
    let mut acceptor = gss::Acceptor::new(&store, AcceptorOptions::new())?;
    let accepted = acceptor.accept_sec_context(first.token())?;
    let reply = accepted.output_token().ok_or("an AP-REP")?.to_vec();
    let context = accepted.into_context();
    assert_eq!(context.inquire().source().display().0, peer_user()?);
    let last = adapter.init_step(&init.continuing(first.context(), &reply))?;
    assert!(!last.continue_needed(), "the Rust AP-REP completes MIT");
    assert_krb5(last.mech())?;
    Ok(Pair {
        context,
        adapter,
        handle: last.context(),
    })
}

/// Wrap, unwrap and MIC tokens both ways between the ends of `pair`.
pub(super) fn messages(pair: &mut Pair, tag: &str) -> Result<(), Box<dyn Error>> {
    let theirs = format!("sealed by mit {tag}");
    let sealed = pair
        .adapter
        .wrap(pair.handle, Protection::new(true), theirs.as_bytes())?;
    assert_eq!(
        pair.context.unwrap(sealed.token())?.message(),
        theirs.as_bytes()
    );
    let ours = format!("sealed by rust {tag}");
    let token = pair.context.wrap(ours.as_bytes(), true)?;
    assert_eq!(
        pair.adapter.unwrap(pair.handle, &token)?.message(),
        ours.as_bytes()
    );
    let mic = pair.context.get_mic(tag.as_bytes())?;
    let _qop: u32 = pair.adapter.verify_mic(pair.handle, tag.as_bytes(), &mic)?;
    let their_mic = pair.adapter.get_mic(pair.handle, tag.as_bytes())?;
    pair.context.verify_mic(tag.as_bytes(), &their_mic)?;
    Ok(())
}

/// Rust IOV buffers `HEADER, SIGN_ONLY, DATA, PADDING, TRAILER` around `data`.
pub(super) fn layout(sign_only: &[u8], data: &[u8]) -> Vec<IovBuffer> {
    vec![
        IovBuffer::empty(IovKind::Header),
        IovBuffer::new(IovKind::SignOnly, sign_only.to_vec()),
        IovBuffer::new(IovKind::Data, data.to_vec()),
        IovBuffer::empty(IovKind::Padding),
        IovBuffer::empty(IovKind::Trailer),
    ]
}

/// The value of the buffer of `kind` in `buffers` (empty when there is none).
pub(super) fn part(buffers: &[IovBuffer], kind: IovKind) -> Vec<u8> {
    buffers
        .iter()
        .find(|buffer| buffer.kind() == kind)
        .map_or_else(Vec::new, |buffer| buffer.value().to_vec())
}

/// `U`: MIT's `gss_unwrap_iov` of buffers a Rust `wrap_iov` filled.
pub(super) fn mit_unwrap_iov(
    pair: &mut Pair,
    buffers: &[IovBuffer],
) -> Result<Unsealed, PeerError> {
    let handle = pair.handle.to_bytes();
    let fields = [
        part(buffers, IovKind::Header),
        part(buffers, IovKind::SignOnly),
        part(buffers, IovKind::Data),
        part(buffers, IovKind::Padding),
        part(buffers, IovKind::Trailer),
    ];
    let mut request: Vec<&[u8]> = vec![&handle];
    request.extend(fields.iter().map(Vec::as_slice));
    let (status, rest) = pair
        .adapter
        .exchange_raw(&frame::encode_request(b'U', &request)?)?;
    Unsealed::read(frame::map_status(status, &rest)?.1)
}

/// `D`: MIT accepts the one-leg `token` with `cred` and keeps the delegated
/// credential under a handle.
pub(super) fn accept_keeping_delegation(
    adapter: &mut Peer<TcpStream>,
    cred: CredHandle,
    token: &[u8],
) -> Result<DelegAccept, PeerError> {
    let (status, rest) =
        adapter.exchange_raw(&frame::encode_request(b'D', &[&cred.to_bytes(), token])?)?;
    let (_continue, mut fields): (bool, Fields) = frame::map_status(status, &rest)?;
    let _context: u32 = fields.number()?;
    let reply = DelegAccept {
        token: fields.bytes()?,
        flags: fields.number()?,
        mech: fields.text()?,
        source: fields.text()?,
        delegated: match fields.number()? {
            0 => None,
            handle => Some(CredHandle::new(handle)),
        },
    };
    fields.finish()?;
    Ok(reply)
}
