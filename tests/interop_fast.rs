//! Live FAST armor and encrypted challenge with the pinned MIT krb5 1.22.2 realm.
//!
//! Plan 2 todo 7 (WP-05): the fixture `mit-kdc` (TEST.RSKRB5) with the FAST
//! principals of `scripts/interop/mit/provision.d/20-fast.sh`. An armor TGT
//! from testuser1's keytab armors fastuser's password login, which the KDC
//! answers with an armored encrypted-challenge offer; only a TGT obtained that
//! way carries the `fast-ec` indicator that `fastrequired/svc.test.rskrb5`
//! requires. Gated by `INTEROP=1`; `INTEROP_REQUIRED=1` turns an unreachable
//! fixture into a failure naming it.
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

/// The FAST scenarios.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "interop_fast/scenarios.rs"]
mod scenarios;
