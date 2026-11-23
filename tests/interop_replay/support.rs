//! Helpers of the replay scenarios: scratch directories, adapter connections, MIT tokens,
//! acceptor processes and container file copies.

use alloc::sync::Arc;
use core::error::Error;
use std::{
    env, fs,
    net::TcpStream,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio, id as process_id},
    time::{SystemTime, UNIX_EPOCH},
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use rskrb5_ng::{
    keytab::Keytab, replay::File2ReplayStore, service::Validator, spnego::accept_sec_context_header,
};

use crate::{
    harness::{self, Fixture},
    peer::{
        Peer,
        cred::{CredRequest, Name, Usage},
        frame::{self, encode_request},
        types::{AcceptRequest, InitRequest, PeerError},
    },
    worker::{KEYTAB, MARKER, STORE, TOKEN},
};

/// The adapter container with a route to the KDC (MIT's default `dfl` cache).
pub(super) const PEER: Fixture = Fixture::new("mit-peer", "INTEROP_MIT_PEER_ADDR");

/// The adapter container whose MIT acceptor keeps a `file2` cache.
pub(super) const REPLAY: Fixture = Fixture::new("replay", "INTEROP_REPLAY_ADDR");

/// The KDC fixture.
pub(super) const MIT_KDC: Fixture = Fixture::new("mit-kdc", "INTEROP_MIT_KDC");

/// The SPNEGO mechanism.
pub(super) const SPNEGO: &str = "1.3.6.1.5.5.2";

/// The krb5 mechanism.
pub(super) const KRB5: &str = "1.2.840.113554.1.2.2";

/// `GSS_C_MUTUAL_FLAG | GSS_C_REPLAY_FLAG | GSS_C_SEQUENCE_FLAG | GSS_C_CONF_FLAG | GSS_C_INTEG_FLAG`.
pub(super) const STANDARD_FLAGS: u32 = 2 | 4 | 8 | 16 | 32;

/// A scratch directory removed when dropped.
pub(super) struct Scratch {
    /// The directory.
    path: PathBuf,
}

impl Scratch {
    /// A fresh directory named for `label`.
    pub(super) fn new(label: &str) -> Result<Self, Box<dyn Error>> {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let path = env::temp_dir().join(format!(
            "rskrb5-replay-interop-{label}-{}-{nanos}",
            process_id()
        ));
        fs::create_dir_all(&path)?;
        Ok(Self { path })
    }

    /// A path inside the directory.
    pub(super) fn join(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        drop(fs::remove_dir_all(&self.path));
    }
}

/// Connects to the adapter at the env-file key `key`.
pub(super) fn connect(key: &str) -> Result<Peer<TcpStream>, Box<dyn Error>> {
    Ok(frame::connect(&harness::var(key)?)?)
}

/// The realm of the fixtures.
pub(super) fn realm() -> Result<String, Box<dyn Error>> {
    harness::var("INTEROP_MIT_REALM")
}

/// A Negotiate header carrying `token`.
pub(super) fn header_of(token: &[u8]) -> String {
    format!("Negotiate {}", STANDARD.encode(token))
}

/// A SPNEGO token MIT's initiator (the `peeruser` of the `mit-peer` adapter)
/// makes for the service principal `target`: a real MIT-issued AP-REQ.
pub(super) fn mit_token(target: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut adapter = connect("INTEROP_MIT_PEER_ADDR")?;
    let request = CredRequest::new(Usage::Initiate)
        .named(Name::principal(&format!(
            "{}@{}",
            harness::var("INTEROP_MIT_PEER_USER")?,
            realm()?
        )))
        .with_mechs(&[SPNEGO])
        .with_keytab(&harness::var("INTEROP_MIT_PEER_USER_KEYTAB_ID")?);
    let (cred, _name) = adapter.acquire(&request)?;
    let init = InitRequest::new(Name::principal(target))
        .with_cred(cred)
        .with_mech(SPNEGO)
        .with_flags(STANDARD_FLAGS);
    let first = adapter.init_step(&init)?;
    if !first.continue_needed() {
        return Err("mutual authentication waits for the AP-REP".into());
    }
    Ok(first.token().to_vec())
}

/// The principal of the MIT acceptor's service, `peer/mit-peer.test.rskrb5@REALM`.
pub(super) fn mit_service() -> Result<String, Box<dyn Error>> {
    Ok(format!(
        "{}@{}",
        harness::var("INTEROP_MIT_PEER_SERVICE_PRINCIPAL")?,
        realm()?
    ))
}

/// MIT's acceptor in the adapter at `key` takes `token`: `Ok` or MIT's refusal text.
pub(super) fn mit_accepts(key: &str, token: &[u8]) -> Result<Result<(), String>, Box<dyn Error>> {
    let mut adapter = connect(key)?;
    let request = CredRequest::new(Usage::Accept)
        .named(Name::hostbased(&harness::var("INTEROP_MIT_PEER_SERVICE")?))
        .with_mechs(&[SPNEGO])
        .with_keytab(&harness::var("INTEROP_MIT_PEER_ACCEPTOR_KEYTAB_ID")?);
    let (cred, _name) = adapter.acquire(&request)?;
    match adapter.accept_step(&AcceptRequest::new(token).with_cred(cred)) {
        Ok(step) if step.mech() == KRB5 => Ok(Ok(())),
        Ok(step) => Err(format!("MIT negotiated {} instead of krb5", step.mech()).into()),
        Err(PeerError::Gss {
            major: _,
            minor: _,
            text,
        }) => Ok(Err(text)),
        Err(other) => Err(other.into()),
    }
}

/// This crate's acceptor takes `token` in this process, over the cache file `store`.
pub(super) fn rust_accepts(
    keytab_path: &Path,
    store: &Path,
    token: &[u8],
) -> Result<Result<String, String>, Box<dyn Error>> {
    let keytab = Keytab::load(keytab_path)?;
    let mut validator = Validator::new(&keytab)
        .with_replay_store(Arc::new(File2ReplayStore::new(store.to_path_buf())))?;
    Ok(
        match accept_sec_context_header(&mut validator, &header_of(token)) {
            Ok(accepted) => Ok(accepted.ap_req().client().name()),
            Err(refusal) => Err(refusal.to_string()),
        },
    )
}

/// Run one acceptor process (this test binary, filtered to `worker::acceptor_worker`).
pub(super) fn spawn_worker(
    keytab: &Path,
    store: &Path,
    token: &Path,
) -> Result<Child, Box<dyn Error>> {
    Ok(Command::new(env::current_exe()?)
        .args([
            "worker::acceptor_worker",
            "--exact",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(KEYTAB, keytab)
        .env(STORE, store)
        .env(TOKEN, token)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?)
}

/// The result line of a finished worker.
pub(super) fn worker_outcome(child: Child) -> Result<String, Box<dyn Error>> {
    let output = child.wait_with_output()?;
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    if !output.status.success() {
        return Err(format!(
            "the acceptor process failed ({}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    stdout
        .lines()
        .find_map(|line| line.split_once(MARKER))
        .map(|(_, rest)| rest.trim().to_owned())
        .ok_or_else(|| format!("the acceptor process printed no result: {stdout}").into())
}

/// The fields of an adapter reply: `u32` length-prefixed byte strings.
pub(super) fn reply_fields(mut rest: &[u8]) -> Result<Vec<Vec<u8>>, Box<dyn Error>> {
    let mut fields = Vec::new();
    while !rest.is_empty() {
        let (prefix, after_prefix) = rest
            .split_at_checked(4)
            .ok_or("a field length is cut off")?;
        let length = usize::try_from(u32::from_be_bytes(prefix.try_into()?))?;
        let (value, after_value) = after_prefix
            .split_at_checked(length)
            .ok_or("a field is cut off")?;
        fields.push(value.to_vec());
        rest = after_value;
    }
    Ok(fields)
}

/// One adapter command `command` with `fields`: the reply fields of a status-0 reply.
pub(super) fn adapter_call(
    adapter: &mut Peer<TcpStream>,
    command: u8,
    fields: &[&[u8]],
) -> Result<Vec<Vec<u8>>, Box<dyn Error>> {
    let (status, rest) = adapter.exchange_raw(&encode_request(command, fields)?)?;
    if status != 0 {
        let text = reply_fields(&rest)
            .ok()
            .and_then(|parsed| parsed.last().cloned())
            .map_or_else(String::new, |bytes| {
                String::from_utf8_lossy(&bytes).into_owned()
            });
        return Err(format!(
            "adapter command {} failed with status {status}: {text}",
            char::from(command)
        )
        .into());
    }
    reply_fields(&rest)
}

/// Lowercase hex of `bytes`.
pub(super) fn hex_of(bytes: &[u8]) -> String {
    hex::encode(bytes)
}
