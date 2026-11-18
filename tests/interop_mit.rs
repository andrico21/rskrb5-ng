//! Live interoperability suite against the pinned MIT krb5 1.22.2 fixture.
//!
//! The fixture `mit-kdc` serves the realm `TEST.RSKRB5` (`scripts/interop/mit/`).
//! `scripts/interop/run.sh test mit` (or `all`) runs it after `run.sh up`
//! exported the fixture's endpoints, generated passwords and exported keytabs.
//! The scenarios re-point the live AS, TGS, renewal, kpasswd, credential-cache
//! and HTTP Negotiate scenarios of `tests/client_integration.rs` at the pinned
//! fixture, and each asserts what was negotiated (enctype, pre-authentication,
//! ticket flag, GSS mechanism) so a fallback cannot pass. The referral
//! scenarios need the second realm `OTHER.RSKRB5` of lane 1D. Everything is
//! gated by `INTEROP=1`; `INTEROP_REQUIRED=1` turns an unreachable fixture into
//! a failure naming it (`interop/harness.rs`).
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

/// The MIT fixture scenarios.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::too_long_first_doc_paragraph,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "interop_mit/scenarios.rs"]
mod scenarios;
