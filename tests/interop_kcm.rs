//! Live KCM caches between this crate and SSSD's `sssd_kcm` with MIT krb5 1.22.2.
//!
//! The fixture `kcm` (`scripts/interop/net-kcm/`) runs SSSD's KCM daemon on a
//! Unix socket in a host-visible directory; the fixture `kcm-mit`
//! (`scripts/interop/suite-kcm/`) runs MIT's tools against the same socket.
//! The scenarios write caches through the crate's `KCM` store (blocking and,
//! for the primary cache, Tokio) and read them back with MIT `klist`, `kvno`
//! and `kswitch`, and the reverse. Each scenario asserts the mechanism that was
//! used: MIT reads `KCM:` names through `kcm_socket` and the crate connects to
//! the daemon socket the fixture exports, so a file cache cannot stand in.
//! Gated by `INTEROP=1`; `INTEROP_REQUIRED=1` turns an unreachable fixture
//! into a failure naming it.
#![cfg(all(unix, feature = "tokio"))]

/// Child-process runner for the tests that change the environment.
#[path = "support/env.rs"]
mod child_env;

/// Port numbers from a reserved range that tests need refused.
#[path = "support/closed_port.rs"]
mod closed_port;

/// Shared harness of the interop suites.
#[path = "interop/harness.rs"]
mod harness;

/// The fixtures, the MIT tools and the crate's login.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    reason = "test code is not rendered API documentation"
)]
#[path = "interop_kcm/support.rs"]
mod support;

/// The KCM scenarios.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "interop_kcm/scenarios.rs"]
mod scenarios;
