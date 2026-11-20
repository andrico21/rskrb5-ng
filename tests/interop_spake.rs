//! Live SPAKE preauthentication against the pinned MIT krb5 1.22.2 realm.
//!
//! Plan 2 todo 9 (WP-07): the fixture `mit-kdc` offers SPAKE in all four MIT
//! groups (`scripts/interop/mit/krb5.conf.d/30-spake.conf`) and asserts the
//! auth indicator `spake` for SPAKE logins; the service
//! `spakerequired/svc.test.rskrb5` requires it (`require_auth = spake`,
//! `provision.d/30-spake.sh`). A TGT obtained through SPAKE therefore gets a
//! ticket for that service and a TGT obtained by encrypted timestamp does not,
//! which proves the mechanism the KDC accepted. Gated by `INTEROP=1` and the
//! `spake` leaf; `INTEROP_REQUIRED=1` turns an unreachable fixture into a
//! failure naming it.
#![cfg(all(feature = "spake", feature = "tokio"))]

/// Port numbers from a reserved range that tests need refused.
#[path = "support/closed_port.rs"]
mod closed_port;

/// Child-process runner for the tests that change the environment.
#[path = "support/env.rs"]
mod child_env;

/// Shared harness of the interop suites.
#[path = "interop/harness.rs"]
mod harness;

/// The SPAKE scenarios.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "interop_spake/scenarios.rs"]
mod scenarios;
