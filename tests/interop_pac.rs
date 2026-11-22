//! Live PAC verification against the pinned MIT krb5 1.22.2 KDC.
//!
//! Plan 2 todo 22 (WP-14): the PAC MIT builds for a service without
//! `+no_auth_data_required` (client info and the server, KDC, ticket and full signatures, no
//! `KERB_VALIDATION_INFO`) is accepted by the acceptor (FU-SVC-P01), its four signatures verify
//! with the service key and the exported `krbtgt` key, and a PAC checked under the wrong KDC key is
//! refused. Gated by `INTEROP=1`; `INTEROP_REQUIRED=1` turns an unreachable fixture into a failure
//! naming it.
#![cfg(all(feature = "tokio", feature = "spnego"))]

/// Child-process runner for the tests that change the environment.
#[path = "support/env.rs"]
mod child_env;

/// Port numbers from a reserved range that tests need refused.
#[path = "support/closed_port.rs"]
mod closed_port;

/// Shared harness of the interop suites.
#[path = "interop/harness.rs"]
mod harness;

/// The MIT PAC scenarios.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::too_long_first_doc_paragraph,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "interop_pac/scenarios.rs"]
mod scenarios;
