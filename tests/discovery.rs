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

/// URI records, sites, roles and registered locators.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "discovery/servers.rs"]
mod servers;

/// Server roles and registered locators.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "discovery/roles.rs"]
mod roles;

/// Host-to-realm mapping.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "discovery/realms.rs"]
mod realms;

/// Hostname canonicalization.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "discovery/hostnames.rs"]
mod hostnames;

/// The total request budget.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "discovery/budget.rs"]
mod budget;
