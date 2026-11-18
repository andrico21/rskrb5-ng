//! Live interoperability suite of the external-peer adapter.
//!
//! The fixture `mit-peer` (`scripts/interop/peer-mit/`) runs MIT krb5 1.22.2's
//! GSS-API behind a length-prefixed TCP protocol, in two containers: one with a
//! route to the KDC of the realm `TEST.RSKRB5` and one without. The scenarios
//! prove the adapter, and the crate's current SPNEGO machinery against it,
//! together; every scenario asserts the mechanism that was negotiated. The
//! scenarios that need GSS surface the crate does not have yet (todos 18 to 21)
//! are not here: the fixture is ready for them. Gated by `INTEROP=1`;
//! `INTEROP_REQUIRED=1` turns an unreachable fixture into a failure naming it.
#![cfg(feature = "tokio")]

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

/// The adapter scenarios.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::too_long_first_doc_paragraph,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "interop_peer/scenarios.rs"]
mod scenarios;
