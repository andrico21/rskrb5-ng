//! Live OTP inside FAST with the pinned MIT krb5 1.22.2 realm.
//!
//! Plan 2 todo 10 (WP-08): the fixtures `mit-kdc` (TEST.RSKRB5) and `radius`
//! (`FreeRADIUS`, the OTP backend of the KDC's `otp` module) with the principals
//! of `scripts/interop/mit/provision.d/40-otp.sh`. An armor TGT from
//! testuser1's keytab armors otpuser's login, which the KDC answers with a
//! `PA-OTP-CHALLENGE`; the token is checked by RADIUS, and only that login
//! earns the `otp` indicator that `otprequired/svc.test.rskrb5` requires.
//! Gated by `INTEROP=1`; `INTEROP_REQUIRED=1` turns an unreachable fixture into
//! a failure naming it.
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

/// The OTP scenarios.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "interop_otp/scenarios.rs"]
mod scenarios;
