//! Live interoperability of IAKERB (`rskrb5_ng::gss::iakerb`) with MIT krb5
//! 1.22.2 through the peer adapter (`scripts/interop/peer-mit/`).
//!
//! A Rust initiator completes a context against MIT's IAKERB acceptor while its
//! direct path to the KDC is blocked, a Rust acceptor relays the AS and TGS
//! exchanges of an MIT initiator that sits in the container without a route to
//! the KDC, and the Rust acceptor refuses a relay request for a realm its policy
//! does not name. Every scenario asserts the negotiated mechanism. Gated by
//! `INTEROP=1`; `INTEROP_REQUIRED=1` turns an unreachable fixture into a failure
//! naming it.
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

/// The IAKERB scenarios.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "interop_iakerb/scenarios.rs"]
mod scenarios;
