//! Live remote kadm5 administration against MIT krb5 1.22.2's kadmind.
//!
//! Plan 2 todo 24 (WP-15b): `kadm5::RemoteAdminClient` over `RPCSEC_GSS`
//! against the kadmind of the fixture `mit-kdc`: principal, policy and key
//! operations, each effect checked with MIT's own `kadmin.local` in the
//! container, and the ACL refusal of an unprivileged principal. Gated by
//! `INTEROP=1`; `INTEROP_REQUIRED=1` turns an unreachable fixture into a
//! failure naming it.
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

/// The kadm5 scenarios.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::too_long_first_doc_paragraph,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "interop_kadm5/scenarios.rs"]
mod scenarios;
