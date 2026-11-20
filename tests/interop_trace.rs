//! Live trace diagnostics with the pinned MIT krb5 1.22.2 realm.
//!
//! Plan 2 todo 6 (WP-18): an AS success and a wrong-password failure (the KDC
//! refuses the encrypted timestamp with `KDC_ERR_PREAUTH_FAILED`) through the
//! stepwise engine and the Tokio client with a capture sink, and the same
//! through the file `KRB5_TRACE` names, each asserting that none of the run's
//! generated secrets (the env-file keys ending `_PASSWORD`, `_SECRET` or
//! `_TOKEN`) and neither the session key nor the ticket bytes appear in what
//! the sink received. Gated by `INTEROP=1`; `INTEROP_REQUIRED=1` turns an
//! unreachable fixture into a failure naming it.
#![cfg(feature = "tokio")]

/// Port numbers from a reserved range that tests need refused.
#[path = "support/closed_port.rs"]
mod closed_port;

/// Child-process runner for the tests that change the environment.
#[path = "support/env.rs"]
mod child_env;

/// Shared harness of the interop suites.
#[path = "interop/harness.rs"]
mod harness;

/// The trace scenarios.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "interop_trace/scenarios.rs"]
mod scenarios;
