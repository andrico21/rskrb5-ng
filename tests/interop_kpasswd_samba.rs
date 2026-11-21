//! Live password changes against the pinned Samba AD fixture.
//!
//! Plan 2 todo 23 (WP-15a, register row FU-IOP-P13): an ordinary user changes their
//! own password through Samba's kpasswd service without RFC 3244 target fields, and
//! the domain administrator's targeted reset of another account stays a separate
//! scenario (`scripts/interop/samba/`). Gated by `INTEROP=1`; `INTEROP_REQUIRED=1` turns
//! an unreachable fixture into a failure naming it.
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

/// The kpasswd scenarios.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::too_long_first_doc_paragraph,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "interop_kpasswd_samba/scenarios.rs"]
mod scenarios;
