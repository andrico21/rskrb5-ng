//! Live stepwise AS and TGS exchanges with the pinned MIT krb5 1.22.2 realms.
//!
//! Plan 2 todo 4 (WP-04): the transport-neutral engine of `client::stepwise`
//! against the fixtures `mit-kdc` (TEST.RSKRB5) and `mit-other` (OTHER.RSKRB5,
//! reached through the direct trust): a password exchange that prompts and
//! answers the preauthentication challenge, a keytab exchange, profile flags
//! and renewal, a plain and a user-to-user TGS exchange, and a referral chain
//! with its bound. Gated by `INTEROP=1`; `INTEROP_REQUIRED=1` turns an
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

/// The exchange scenarios.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "interop_exchange/scenarios.rs"]
mod scenarios;
