//! Live password expiry and kpasswd completion against MIT krb5 1.22.2.
//!
//! Plan 2 todo 23 (WP-15a): `Tokio::login_with_expiry` against the fixture `mit-kdc`
//! (`scripts/interop/mit/provision.d/73-kpasswd.sh`): a password that expired
//! (`KDC_ERR_KEY_EXP`) is changed through kpasswd and the login starts over with the
//! new one, a short password is a policy soft error that the responder answers again,
//! and the KDC's impending-expiry time reaches the responder. Gated by `INTEROP=1`;
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

/// The kpasswd scenarios.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::too_long_first_doc_paragraph,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "interop_kpasswd/scenarios.rs"]
mod scenarios;
