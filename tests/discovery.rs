//! Server discovery and hostname canonicalization (WP-10a): DNS URI and SRV
//! records, sites, hostname canonicalization, host realms, the primary-KDC
//! retry and the total request budget, against a deterministic loopback DNS peer.
#![cfg(feature = "tokio")]

use core::error::Error;

/// A loopback UDP socket with a wildcard socket held on its number.
#[path = "discovery/loopback.rs"]
mod loopback;

/// Error type of the `Result`-returning tests.
type TestError = Box<dyn Error + Send + Sync>;

/// The deterministic DNS peer.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    reason = "test code is not rendered API documentation"
)]
#[path = "discovery/fixture.rs"]
mod fixture;

/// The plan-1 discovery residuals.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "discovery/residuals.rs"]
mod residuals;
