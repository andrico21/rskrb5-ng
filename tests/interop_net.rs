//! Live interoperability suite against the MIT network fixtures of lane 1D-b.
//!
//! Fixtures (`scripts/interop/net-*/`): `dns` (CoreDNS with the SRV, URI and
//! TXT records of both realms), `mit-other` (the second MIT realm
//! `OTHER.RSKRB5` trusting `TEST.RSKRB5` both ways, plus the capaths-only
//! realm `FAR.EXAMPLE`), `httpd` (Apache `mod_auth_gssapi`), `kdcproxy` and
//! `kcm`. `scripts/interop/run.sh test net` (or `all`) runs these scenarios
//! after `run.sh up`; they drive what the crate can drive today: SRV discovery
//! through the CoreDNS zone, the cross-realm referral to an `OTHER.RSKRB5`
//! service, and HTTP Negotiate against Apache. The KDC proxy, KCM, URI, site
//! and capaths fixtures are proven by their fixture self-checks with the MIT
//! tools until the work packages that use them add their scenarios. Everything
//! is gated by `INTEROP=1`; `INTEROP_REQUIRED=1` turns an unreachable fixture
//! into a failure naming it (`interop/harness.rs`).
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

/// The network fixture scenarios.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::too_long_first_doc_paragraph,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "interop_net/scenarios.rs"]
mod scenarios;
