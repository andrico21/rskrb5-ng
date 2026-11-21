//! Live MS-KKDCP through the `kdcproxy` fixture to the pinned MIT krb5 1.22.2 realm.
//!
//! Plan 2 todo 16 (WP-10b): the fixture `kdcproxy` (latchset kdcproxy behind HTTPS,
//! `scripts/interop/net-kdcproxy`) forwards `TEST.RSKRB5` requests to the MIT KDC
//! and its kpasswd service. A profile that names only the proxy URL as the realm's
//! `kdc` and `kpasswd_server`, anchored on the fixture's per-run CA, logs in, gets a
//! service ticket and changes a password through the built-in rustls transport; the
//! same profile anchored on an unrelated CA is refused. Gated by `INTEROP=1` and the
//! `kkdcp-rustls` leaf; `INTEROP_REQUIRED=1` turns an unreachable fixture into a
//! failure naming it.
#![cfg(all(feature = "kkdcp-rustls", feature = "tokio"))]

/// Port numbers from a reserved range that tests need refused.
#[path = "support/closed_port.rs"]
mod closed_port;

/// Child-process runner for the tests that change the environment.
#[path = "support/env.rs"]
mod child_env;

/// Shared harness of the interop suites.
#[path = "interop/harness.rs"]
mod harness;

/// The KDC proxy scenarios.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "interop_kkdcp/scenarios.rs"]
mod scenarios;
