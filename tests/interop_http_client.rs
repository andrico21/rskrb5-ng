//! Live HTTP client and session scenarios (plan 2 todo 26, WP-19, the
//! `http-client` leaf).
//!
//! The crate's `NegotiateHttpClient` against the MIT-backed Apache fixture
//! `httpd` (service `HTTP/httpd.test.rskrb5`, plain HTTP): the `401` Negotiate
//! round with mutual authentication verified on the final response, a
//! same-origin redirect, and the typed refusal of a service the realm does not
//! know; and the session manager behind a Rust acceptor holding Apache's own
//! keytab. `scripts/interop/run.sh test http-client` (or `all`) runs them after
//! `run.sh up`; everything is gated by `INTEROP=1`, and `INTEROP_REQUIRED=1`
//! turns an unreachable fixture into a failure naming it.
#![cfg(all(feature = "http-client", feature = "tokio"))]

#[cfg(feature = "tower")]
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

/// The scenarios.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::too_long_first_doc_paragraph,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "interop_http_client/scenarios.rs"]
mod scenarios;
