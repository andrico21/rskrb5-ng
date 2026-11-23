//! Live interoperability of the GSS-API Kerberos mechanism (`rskrb5_ng::gss`)
//! with MIT krb5 1.22.2 through the peer adapter (`scripts/interop/peer-mit/`).
//!
//! Rust initiators against the MIT acceptor and MIT initiators against the Rust
//! acceptor, with and without channel bindings, a mismatch refused, the
//! acceptor that requires bindings, the client keytab and password credential
//! stores, a delegated TGT that works against the KDC, SPNEGO over the GSS
//! contexts, and per-message tokens in both directions. Every scenario asserts
//! the negotiated mechanism. Gated by `INTEROP=1`; `INTEROP_REQUIRED=1` turns
//! an unreachable fixture into a failure naming it.
#![cfg(all(feature = "spnego", feature = "tokio"))]

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

/// The GSS scenarios.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "interop_gss/scenarios.rs"]
mod scenarios;
