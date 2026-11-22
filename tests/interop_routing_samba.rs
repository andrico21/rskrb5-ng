//! Live routing and delegation against the pinned Samba AD forest trust.
//!
//! Plan 2 todo 17 (WP-11): the KDC referral a request for a RES.RSKRB5
//! service gets from USER.RSKRB5 is followed to RES for the service
//! (FU-IOP-P12); resource-based constrained delegation reaches the allowed
//! target and is refused for another (FU-IOP-P11). Gated by `INTEROP=1`;
//! `INTEROP_REQUIRED=1` turns an unreachable fixture into a failure naming it.
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

/// The Samba routing scenarios.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::too_long_first_doc_paragraph,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "interop_routing_samba/scenarios.rs"]
mod scenarios;
