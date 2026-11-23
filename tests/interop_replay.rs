//! Live interoperability suite of the replay backends and the authenticated message API.
//!
//! The scenarios share one `file2` replay cache between this crate's
//! `replay::File2ReplayStore` and MIT krb5 1.22.2's own library (the adapter of
//! the `mit-peer` fixture and the `replay` container of
//! `scripts/interop/replay/`, whose MIT acceptor keeps its evidence in a `file2`
//! cache file), in both directions; two Rust acceptor processes share one cache
//! file and accept a real MIT-issued AP-REQ once; and MIT's own
//! `krb5_fwd_tgt_creds` output is read through `messages::CredentialTransport`
//! (and MIT reads ours). Every scenario that proves a mechanism asserts it.
//! Gated by `INTEROP=1`; `INTEROP_REQUIRED=1` turns an unreachable fixture into
//! a failure naming it.
#![cfg(feature = "spnego")]

extern crate alloc;

/// Child-process runner for the tests that change the environment.
#[path = "support/env.rs"]
mod child_env;

/// Port numbers from a reserved range that tests need refused.
#[path = "support/closed_port.rs"]
mod closed_port;

/// Shared harness of the interop suites.
#[path = "interop/harness.rs"]
mod harness;

/// Typed client of the adapter protocol.
#[path = "interop/peer.rs"]
mod peer;

/// The separate acceptor process of the multi-process scenarios.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    reason = "test code is not rendered API documentation"
)]
#[path = "interop_replay/worker.rs"]
mod worker;

/// The replay scenarios.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "interop_replay/scenarios.rs"]
mod scenarios;
