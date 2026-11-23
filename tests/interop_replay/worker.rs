//! One acceptor process: the scenarios spawn this test binary again, filtered to
//! this test, so two Rust acceptors in two processes share one cache file.
//!
//! The process reads a Negotiate header from a file, accepts it with a keytab
//! and a `File2ReplayStore`, and prints one line: `ACCEPTED <client>` or
//! `REFUSED <error text>`. Without the environment it is a no-op test.

use alloc::sync::Arc;
use core::error::Error;
use std::{
    env, fs,
    io::{Write as _, stdout},
};

use rskrb5_ng::{
    keytab::Keytab, replay::File2ReplayStore, service::Validator, spnego::accept_sec_context_header,
};

/// The keytab the acceptor holds.
pub(super) const KEYTAB: &str = "RSKRB5_REPLAY_WORKER_KEYTAB";
/// The replay-cache file shared by every acceptor process.
pub(super) const STORE: &str = "RSKRB5_REPLAY_WORKER_STORE";
/// The file holding the Negotiate header to accept.
pub(super) const TOKEN: &str = "RSKRB5_REPLAY_WORKER_TOKEN";
/// The marker every result line starts with.
pub(super) const MARKER: &str = "REPLAY-WORKER";

/// Accept the token of the environment once and print the outcome.
#[test]
fn acceptor_worker() -> Result<(), Box<dyn Error>> {
    let (Some(keytab), Some(store), Some(token)) =
        (env::var_os(KEYTAB), env::var_os(STORE), env::var_os(TOKEN))
    else {
        return Ok(());
    };
    let keytab = Keytab::load(keytab)?;
    let header = fs::read_to_string(token)?;
    let mut validator =
        Validator::new(&keytab).with_replay_store(Arc::new(File2ReplayStore::new(store.into())))?;
    let line = match accept_sec_context_header(&mut validator, header.trim()) {
        Ok(accepted) => format!("ACCEPTED {}", accepted.ap_req().client().name()),
        Err(refusal) => format!("REFUSED {refusal}"),
    };
    writeln!(stdout(), "{MARKER} {line}")?;
    Ok(())
}
