//! Live interoperability suite of `NegoEx` (plan 2 todo 21, WP-13b).
//!
//! The crate's `NegoEx` under SPNEGO against MIT krb5 1.22.2's `NegoEx` and its
//! `negoextest` test mechanisms, both ways, through the external-peer adapter
//! of the fixture `mit-peer` (`scripts/interop/peer-mit/`): the crate's
//! initiator against MIT's acceptor and MIT's initiator against the crate's
//! acceptor. The crate's side runs a test-only Rust implementation of the
//! `negoextest` mechanism protocol; every scenario asserts the mechanism that
//! was negotiated. Gated by `INTEROP=1`; `INTEROP_REQUIRED=1` turns an
//! unreachable fixture into a failure naming it.
#![cfg(all(feature = "tokio", feature = "spnego"))]

extern crate alloc;

/// Child-process runner for the tests that change the environment.
#[path = "support/env.rs"]
mod child_env;

/// Port numbers from a reserved range that tests need refused.
#[path = "support/closed_port.rs"]
mod closed_port;

/// Turns `Option` and `Result` failures into test errors.
#[path = "support/context.rs"]
mod context;

/// The test-only Rust implementation of MIT's `negoextest` mechanism.
#[path = "support/negoextest.rs"]
mod negoextest;

/// Shared harness of the interop suites.
#[path = "interop/harness.rs"]
mod harness;

/// Typed client of the adapter protocol.
#[path = "interop/peer.rs"]
mod peer;

/// The scenarios.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::too_long_first_doc_paragraph,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "interop_negoex/scenarios.rs"]
mod scenarios;
