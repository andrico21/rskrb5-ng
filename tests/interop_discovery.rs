//! Live discovery and canonicalization against the `CoreDNS` zone and the MIT KDC.
//!
//! Plan 2 todo 15 (WP-10a): DNS URI records before SRV records, the site records of
//! `lab1`, the primary KDC flag, the TXT realm record and the IPv6 record of the
//! `dns` fixture (`scripts/interop/net-zone`), and a password login through each
//! discovered endpoint of `mit-kdc`. Gated by `INTEROP=1`; `INTEROP_REQUIRED=1`
//! turns an unreachable fixture into a failure naming it.
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

/// The discovery scenarios.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "interop_discovery/scenarios.rs"]
mod scenarios;
