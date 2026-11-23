//! The replay scenarios: cross-process acceptors on one file store, `file2`
//! cache files exchanged with MIT in both directions, and MIT forwarding.

use alloc::sync::Arc;
use core::error::Error;
use std::{
    env, fs,
    io::{self, Write as _},
    net::TcpStream,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio, id as process_id},
    time::{SystemTime, UNIX_EPOCH},
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use rskrb5_ng::{
    keytab::{EncryptionKey, Keytab},
    messages::{AuthContext, CredentialTransport, MessagePolicy},
    replay::File2ReplayStore,
    service::Validator,
    spnego::accept_sec_context_header,
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
const PEER: Fixture = Fixture::new("mit-peer", "INTEROP_MIT_PEER_ADDR");

/// The adapter container whose MIT acceptor keeps a `file2` cache.
const REPLAY: Fixture = Fixture::new("replay", "INTEROP_REPLAY_ADDR");

/// The KDC fixture.
const MIT_KDC: Fixture = Fixture::new("mit-kdc", "INTEROP_MIT_KDC");

/// The SPNEGO mechanism.
const SPNEGO: &str = "1.3.6.1.5.5.2";

/// The krb5 mechanism.
const KRB5: &str = "1.2.840.113554.1.2.2";

/// `GSS_C_MUTUAL_FLAG | GSS_C_REPLAY_FLAG | GSS_C_SEQUENCE_FLAG | GSS_C_CONF_FLAG | GSS_C_INTEG_FLAG`.
const STANDARD_FLAGS: u32 = 2 | 4 | 8 | 16 | 32;

/// A scratch directory removed when dropped.
struct Scratch {
    /// The directory.
    path: PathBuf,
}

impl Scratch {
    /// A fresh directory named for `label`.
    fn new(label: &str) -> Result<Self, Box<dyn Error>> {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let path = env::temp_dir().join(format!(
            "rskrb5-replay-interop-{label}-{}-{nanos}",
            process_id()
        ));
        fs::create_dir_all(&path)?;
        Ok(Self { path })
    }

    /// A path inside the directory.
    fn join(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        drop(fs::remove_dir_all(&self.path));
    }
}

/// Connects to the adapter at the env-file key `key`.
fn connect(key: &str) -> Result<Peer<TcpStream>, Box<dyn Error>> {
    Ok(frame::connect(&harness::var(key)?)?)
}

/// The realm of the fixtures.
fn realm() -> Result<String, Box<dyn Error>> {
    harness::var("INTEROP_MIT_REALM")
}

/// A Negotiate header carrying `token`.
fn header_of(token: &[u8]) -> String {
    format!("Negotiate {}", STANDARD.encode(token))
}

/// A SPNEGO token MIT's initiator (the `peeruser` of the `mit-peer` adapter)
/// makes for the service principal `target`: a real MIT-issued AP-REQ.
fn mit_token(target: &str) -> Result<Vec<u8>, Box<dyn Error>> {
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
fn mit_service() -> Result<String, Box<dyn Error>> {
    Ok(format!(
        "{}@{}",
        harness::var("INTEROP_MIT_PEER_SERVICE_PRINCIPAL")?,
        realm()?
    ))
}

/// MIT's acceptor in the adapter at `key` takes `token`: `Ok` or MIT's refusal text.
fn mit_accepts(key: &str, token: &[u8]) -> Result<Result<(), String>, Box<dyn Error>> {
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
fn rust_accepts(
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
fn spawn_worker(keytab: &Path, store: &Path, token: &Path) -> Result<Child, Box<dyn Error>> {
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
fn worker_outcome(child: Child) -> Result<String, Box<dyn Error>> {
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

/// The container runtime of the run.
fn runtime() -> Result<String, Box<dyn Error>> {
    harness::var("INTEROP_RUNTIME")
}

/// Run `command` in the `replay` or `mit-peer` container; its stdout.
fn exec(
    container_key: &str,
    command: &[&str],
    stdin: Option<&Path>,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut command_line = Command::new(runtime()?);
    let mut options = vec!["exec"];
    if stdin.is_some() {
        options.push("-i");
    }
    let mut process = command_line
        .args(options)
        .arg(harness::var(container_key)?)
        .args(command)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    if let (Some(path), Some(mut pipe)) = (stdin, process.stdin.take()) {
        pipe.write_all(&fs::read(path)?)?;
    }
    let output = process.wait_with_output()?;
    if output.status.success() {
        Ok(output.stdout)
    } else {
        Err(format!(
            "`{}` failed in the container ({}): {}",
            command.join(" "),
            output.status,
            String::from_utf8_lossy(&output.stderr)
        )
        .into())
    }
}

/// Copy a replay-cache file into the `replay` container.
fn put_cache(source: &Path) -> Result<(), Box<dyn Error>> {
    let target = harness::var("INTEROP_REPLAY_RCACHE")?;
    drop(exec(
        "INTEROP_REPLAY_CONTAINER",
        &["sh", "-c", "umask 077 && cat > \"$1\"", "sh", &target],
        Some(source),
    )?);
    Ok(())
}

/// Copy a file out of a container into `destination`.
fn get_file(
    container_key: &str,
    path_command: &[&str],
    destination: &Path,
) -> Result<(), Box<dyn Error>> {
    fs::write(destination, exec(container_key, path_command, None)?)?;
    Ok(())
}

/// Two Rust acceptor processes sharing one `File2ReplayStore` directory: the first
/// accepts a real MIT-issued AP-REQ, the second refuses the same authenticator.
#[test]
fn two_rust_acceptor_processes_share_one_cache_file() -> Result<(), Box<dyn Error>> {
    if !harness::require(
        "two_rust_acceptor_processes_share_one_cache_file",
        &[MIT_KDC, PEER],
    )? {
        return Ok(());
    }
    let scratch = Scratch::new("processes")?;
    let keytab = PathBuf::from(harness::var("INTEROP_MIT_PEER_RUST_KEYTAB")?);
    let target = format!(
        "{}@{}",
        harness::var("INTEROP_MIT_PEER_RUST_SERVICE")?,
        realm()?
    );
    let store = scratch.join("service.rcache2");

    let token = mit_token(&target)?;
    let token_file = scratch.join("token.header");
    fs::write(&token_file, header_of(&token))?;
    let first = worker_outcome(spawn_worker(&keytab, &store, &token_file)?)?;
    let second = worker_outcome(spawn_worker(&keytab, &store, &token_file)?)?;
    let user = harness::var("INTEROP_MIT_PEER_USER")?;
    assert_eq!(
        first,
        format!("ACCEPTED {user}"),
        "the first process accepts"
    );
    assert!(
        second.starts_with("REFUSED") && second.to_lowercase().contains("replay"),
        "the second process refuses the same authenticator: {second}"
    );

    // Four processes racing on a fresh authenticator: exactly one accepts it.
    let raced = mit_token(&target)?;
    let raced_file = scratch.join("raced.header");
    fs::write(&raced_file, header_of(&raced))?;
    let mut racers = Vec::new();
    for _worker in 0_u8..4 {
        racers.push(spawn_worker(&keytab, &store, &raced_file)?);
    }
    let outcomes = racers
        .into_iter()
        .map(worker_outcome)
        .collect::<Result<Vec<_>, _>>()?;
    let accepted = outcomes
        .iter()
        .filter(|outcome| outcome.starts_with("ACCEPTED"))
        .count();
    assert_eq!(accepted, 1, "exactly one process accepts: {outcomes:?}");
    Ok(())
}

/// A cache file this crate wrote is read by MIT's own library: MIT's acceptor refuses
/// the authenticator the Rust store recorded and still accepts a fresh one.
#[test]
fn a_cache_file_written_by_the_rust_store_is_read_by_mit() -> Result<(), Box<dyn Error>> {
    if !harness::require(
        "a_cache_file_written_by_the_rust_store_is_read_by_mit",
        &[MIT_KDC, PEER, REPLAY],
    )? {
        return Ok(());
    }
    let scratch = Scratch::new("rust-writes")?;
    let keytab = PathBuf::from(harness::var("INTEROP_REPLAY_ACCEPTOR_KEYTAB")?);
    let store = scratch.join("rust.rcache2");
    let recorded = mit_token(&mit_service()?)?;
    let user = harness::var("INTEROP_MIT_PEER_USER")?;
    assert_eq!(
        rust_accepts(&keytab, &store, &recorded)?,
        Ok(user),
        "the Rust acceptor records the authenticator"
    );

    drop(exec(
        "INTEROP_REPLAY_CONTAINER",
        &["rm", "-f", &harness::var("INTEROP_REPLAY_RCACHE")?],
        None,
    )?);
    put_cache(&store)?;
    let refusal = mit_accepts("INTEROP_REPLAY_ADDR", &recorded)?
        .err()
        .ok_or("MIT accepted an authenticator the Rust store recorded")?;
    assert!(
        refusal.to_lowercase().contains("replay"),
        "MIT refuses it as a replay: {refusal}"
    );
    let fresh = mit_token(&mit_service()?)?;
    assert_eq!(
        mit_accepts("INTEROP_REPLAY_ADDR", &fresh)?,
        Ok(()),
        "MIT still accepts a fresh authenticator through the Rust-written file"
    );
    Ok(())
}

/// A cache file MIT wrote (`file2` by name, and MIT's default `dfl` file) is read by
/// this crate's store: the Rust acceptor refuses what MIT recorded and accepts a fresh one.
#[test]
fn a_cache_file_written_by_mit_is_read_by_the_rust_store() -> Result<(), Box<dyn Error>> {
    if !harness::require(
        "a_cache_file_written_by_mit_is_read_by_the_rust_store",
        &[MIT_KDC, PEER, REPLAY],
    )? {
        return Ok(());
    }
    let scratch = Scratch::new("mit-writes")?;
    let keytab = PathBuf::from(harness::var("INTEROP_REPLAY_ACCEPTOR_KEYTAB")?);
    let user = harness::var("INTEROP_MIT_PEER_USER")?;
    let rcache = harness::var("INTEROP_REPLAY_RCACHE")?;

    drop(exec(
        "INTEROP_REPLAY_CONTAINER",
        &["rm", "-f", &rcache],
        None,
    )?);
    let by_name = mit_token(&mit_service()?)?;
    assert_eq!(
        mit_accepts("INTEROP_REPLAY_ADDR", &by_name)?,
        Ok(()),
        "MIT records it"
    );
    let named = scratch.join("mit-file2.rcache2");
    get_file("INTEROP_REPLAY_CONTAINER", &["cat", &rcache], &named)?;
    let refusal = rust_accepts(&keytab, &named, &by_name)?
        .err()
        .ok_or("the Rust store accepted an authenticator MIT recorded in a file2 cache")?;
    assert!(refusal.to_lowercase().contains("replay"), "{refusal}");
    assert_eq!(
        rust_accepts(&keytab, &named, &mit_token(&mit_service()?)?)?,
        Ok(user),
        "the Rust store accepts a fresh authenticator through the MIT-written file"
    );

    let by_default = mit_token(&mit_service()?)?;
    assert_eq!(
        mit_accepts("INTEROP_MIT_PEER_ADDR", &by_default)?,
        Ok(()),
        "MIT records it in dfl"
    );
    let dfl = scratch.join("mit-dfl.rcache2");
    get_file(
        "INTEROP_MIT_PEER_CONTAINER",
        &[
            "sh",
            "-c",
            "cat \"${KRB5RCACHEDIR:-${TMPDIR:-/var/tmp}}/krb5_$(id -u).rcache2\"",
        ],
        &dfl,
    )?;
    let dfl_refusal = rust_accepts(&keytab, &dfl, &by_default)?
        .err()
        .ok_or("the Rust store accepted an authenticator MIT recorded in its dfl cache")?;
    assert!(
        dfl_refusal.to_lowercase().contains("replay"),
        "{dfl_refusal}"
    );
    Ok(())
}

/// The fields of an adapter reply: `u32` length-prefixed byte strings.
fn reply_fields(mut rest: &[u8]) -> Result<Vec<Vec<u8>>, Box<dyn Error>> {
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
fn adapter_call(
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

/// MIT's `krb5_fwd_tgt_creds` output (a forwardable TGT of `peeruser`) is read through
/// `CredentialTransport::Encrypted`; the credentials this crate forwards are read by
/// MIT's `krb5_rd_cred`.
#[test]
fn mit_forwarded_credentials_cross_the_credential_transport() -> Result<(), Box<dyn Error>> {
    if !harness::require(
        "mit_forwarded_credentials_cross_the_credential_transport",
        &[MIT_KDC, PEER],
    )? {
        return Ok(());
    }
    let realm = realm()?;
    let user = harness::var("INTEROP_MIT_PEER_USER")?;
    let host = "mit-peer.test.rskrb5";
    let mut adapter = connect("INTEROP_MIT_PEER_ADDR")?;
    let service = mit_service()?;
    let forwarded = adapter_call(
        &mut adapter,
        b'F',
        &[
            harness::var("INTEROP_MIT_PEER_USER_KEYTAB_ID")?.as_bytes(),
            format!("{user}@{realm}").as_bytes(),
            service.as_bytes(),
            host.as_bytes(),
        ],
    )?;
    let [etype_field, key, krb_cred, forwarded_server] = forwarded.as_slice() else {
        return Err("the forward reply has four fields".into());
    };
    let etype = i32::from_be_bytes(etype_field.as_slice().try_into()?);
    if env::var_os("RSKRB5_CAPTURE").is_some() {
        writeln!(
            io::stderr(),
            "interop: capture mit-krb-cred etype={etype} key={} cred={}",
            hex_of(key),
            hex_of(krb_cred)
        )?;
    }
    assert_eq!(
        String::from_utf8_lossy(forwarded_server),
        format!("krbtgt/{realm}@{realm}"),
        "MIT forwarded a TGT"
    );

    let session = EncryptionKey::new(etype, key.clone());
    let received = AuthContext::new(session, MessagePolicy::new())
        .rd_cred(krb_cred, CredentialTransport::Encrypted)?;
    let credentials = received.content();
    assert_eq!(credentials.len(), 1, "one forwarded credential");
    let credential = credentials.first().ok_or("one credential")?;
    assert_eq!(
        credential.client().principal_string(),
        format!("{user}@{realm}")
    );
    assert_eq!(
        credential.server().principal_string(),
        format!("krbtgt/{realm}@{realm}")
    );
    let flags = credential.ticket_flags();
    assert_eq!(
        flags.first().map(|byte| byte & 0x60),
        Some(0x60),
        "the ticket is forwardable and forwarded: {flags:?}"
    );
    assert!(
        !credential.ticket().is_empty(),
        "the forwarded ticket is present"
    );

    // This crate's KRB-CRED of the same credentials, read by MIT's krb5_rd_cred.
    let key_bytes = vec![0x5a; 32];
    let wire = AuthContext::new(
        EncryptionKey::new(18, key_bytes.clone()),
        MessagePolicy::new(),
    )
    .mk_cred(credentials, CredentialTransport::Encrypted)?;
    let read = adapter_call(
        &mut adapter,
        b'G',
        &[&18_u32.to_be_bytes(), &key_bytes, &wire],
    )?;
    let [count, client, server, _flags] = read.as_slice() else {
        return Err("MIT read exactly one credential".into());
    };
    assert_eq!(u32::from_be_bytes(count.as_slice().try_into()?), 1);
    assert_eq!(String::from_utf8_lossy(client), format!("{user}@{realm}"));
    assert_eq!(
        String::from_utf8_lossy(server),
        format!("krbtgt/{realm}@{realm}")
    );
    Ok(())
}

/// Lowercase hex of `bytes`.
fn hex_of(bytes: &[u8]) -> String {
    hex::encode(bytes)
}
