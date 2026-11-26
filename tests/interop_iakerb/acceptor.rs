//! The Rust acceptor side of the IAKERB scenarios: its TCP relay and the MIT
//! initiator that talks to it.

use core::{error::Error, fmt::Display, time::Duration};
use std::{
    io::{Read as _, Write as _},
    net::{TcpStream, ToSocketAddrs as _},
};

use rskrb5_ng::{
    error::Iakerb,
    gss::{
        self, AcceptorOptions, CredStore, Credential, CredentialUsage, EstablishedContext, Name,
        NameType,
        iakerb::{AcceptStep, Context, KdcRelay, RelayFailure, RelayPolicy},
    },
};

use crate::{
    common::{IAKERB, ROUNDS, STANDARD_FLAGS, assert_mechanism, connect_iso, realm},
    harness,
    peer::{
        Peer,
        cred::{CredRequest, Name as PeerName, Usage},
        reply::Protection,
        types::InitRequest,
    },
};

/// The application's relay: a plain TCP client of the KDC (RFC 4120 section 7.2.2
/// record marking), the only path the isolated initiator has to it.
pub(super) struct TcpRelay {
    /// The KDC's `host:port`.
    pub kdc: String,
    /// How many requests were relayed.
    pub relayed: usize,
    /// The realms asked for.
    pub realms: Vec<String>,
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

/// Where the isolated MIT initiator's credential gets its tickets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Secret {
    /// The user's password.
    Password,
    /// The user's client keytab.
    Keytab,
}

/// The isolated MIT initiator's first request for the Rust acceptor: its
/// credential is the user's password or client keytab, its mechanism IAKERB.
fn iso_request(
    adapter: &mut Peer<TcpStream>,
    name: PeerName,
    secret: Secret,
) -> Result<InitRequest, Box<dyn Error>> {
    let base = CredRequest::new(Usage::Initiate)
        .named(name)
        .with_mechs(&[IAKERB]);
    let request = match secret {
        Secret::Password => {
            base.with_password(harness::var("INTEROP_MIT_PEER_USER_PASSWORD")?.as_bytes())
        }
        Secret::Keytab => base.with_keytab(&harness::var("INTEROP_MIT_PEER_USER_KEYTAB_ID")?),
    };
    let credential = adapter.acquire(&request)?;
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
pub(super) fn mit_to_rust(
    name: PeerName,
    policy: RelayPolicy,
) -> Result<(Result<EstablishedContext, Iakerb>, TcpRelay), Box<dyn Error>> {
    mit_to_rust_with(name, policy, Secret::Password)
}

/// [`mit_to_rust`] with the MIT credential's `secret`.
pub(super) fn mit_to_rust_with(
    name: PeerName,
    policy: RelayPolicy,
    secret: Secret,
) -> Result<(Result<EstablishedContext, Iakerb>, TcpRelay), Box<dyn Error>> {
    let mut adapter = connect_iso()?;
    let init = iso_request(&mut adapter, name, secret)?;
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
