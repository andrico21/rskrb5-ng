//! The replay scenarios: cross-process acceptors on one file store, `file2`
//! cache files exchanged with MIT in both directions, and MIT forwarding.

use core::error::Error;
use std::{
    env, fs,
    io::{self, Write as _},
    path::PathBuf,
};

use rskrb5_ng::{
    keytab::EncryptionKey,
    messages::{AuthContext, CredentialTransport, MessagePolicy},
};

use super::{
    containers::{exec, get_file, put_cache},
    support::{
        MIT_KDC, PEER, REPLAY, Scratch, adapter_call, connect, header_of, hex_of, mit_accepts,
        mit_service, mit_token, realm, rust_accepts, spawn_worker, worker_outcome,
    },
};
use crate::harness;

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
