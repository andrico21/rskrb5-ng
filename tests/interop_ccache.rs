//! Live DIR collections and cache versions between this crate and MIT krb5 1.22.2.
//!
//! The fixture `ccache-mit` (`scripts/interop/suite-ccache/`) bind-mounts a
//! host directory into a container of the MIT image; the scenarios write DIR
//! collections and FILE caches of every format version on one side and read
//! them with the other side's own tools: the crate's stores on the host, MIT
//! `kinit`, `klist -A`, `kswitch` and `kvno` in the container. Each scenario
//! asserts the mechanism that was used: the collection's `primary` pointer
//! file, the version bytes of the cache file and the principal MIT reports.
//! Gated by `INTEROP=1`; `INTEROP_REQUIRED=1` turns an unreachable fixture
//! into a failure naming it.
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

/// The credential-store scenarios.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "interop_ccache/scenarios.rs"]
mod scenarios;
