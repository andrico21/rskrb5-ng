//! Live interoperability of the GSS-API II extensions with MIT krb5 1.22.2.
//!
//! The Rust `rskrb5_ng::gss` contexts meet MIT through the peer adapter
//! (`scripts/interop/peer-mit/`). IOV and AEAD tokens in both directions, `gss_pseudo_random` output compared
//! byte for byte with MIT's on both context roles, DCE-style three-leg
//! establishment with MIT as either end, context transfer (the Rust transfer
//! blob and MIT's export token) in the middle of a conversation with MIT, and
//! a TGT delegated from Rust to MIT and on from MIT back to Rust. Every
//! scenario asserts the negotiated mechanism. Gated by `INTEROP=1`;
//! `INTEROP_REQUIRED=1` turns an unreachable fixture into a failure naming it.
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

/// The GSS-API II scenarios.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "interop_gss_ext/scenarios.rs"]
mod scenarios;
