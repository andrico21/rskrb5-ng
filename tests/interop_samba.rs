//! Live interoperability suite against the pinned Samba AD fixtures.
//!
//! Two Samba 4.22 domain controllers, `samba-user` (realm `USER.RSKRB5`) and
//! `samba-res` (realm `RES.RSKRB5`), joined by a bidirectional forest trust
//! (`scripts/interop/samba/`). `scripts/interop/run.sh test samba` (or `all`)
//! runs this suite after `run.sh up` exported the fixtures' endpoints,
//! generated passwords and exported keytabs. The scenarios re-point the
//! Active Directory scenarios of `tests/client_ad_integration.rs` at the
//! pinned domains, and add AS/TGS with pre-authentication, a referral across
//! the trust, kpasswd (FU-TST-06), constrained delegation and HTTP Negotiate
//! with a Samba-issued PAC; each asserts what was negotiated (enctype,
//! pre-authentication, ticket flag, GSS mechanism) so a fallback cannot pass.
//! Everything is gated by `INTEROP=1`; `INTEROP_REQUIRED=1` turns an
//! unreachable fixture into a failure naming it (`interop/harness.rs`).
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

/// The Samba fixture scenarios.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::too_long_first_doc_paragraph,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "interop_samba/scenarios.rs"]
mod scenarios;
