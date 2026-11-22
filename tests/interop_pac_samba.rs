//! Live PAC verification against Samba AD 4.22.11 (two domains, forest trust).
//!
//! Plan 2 todo 22 (WP-14): Samba sends a zero-length client-claims buffer for an account without
//! claims and for every ticket issued across the trust, which the acceptor must accept
//! (FU-IOP-P14), and the PAC attributes and claims Samba does send read through the verified PAC.
//! Gated by `INTEROP=1`; `INTEROP_REQUIRED=1` turns an unreachable fixture into a failure naming
//! it.
#![cfg(all(feature = "tokio", feature = "spnego"))]

/// Child-process runner for the tests that change the environment.
#[path = "support/env.rs"]
mod child_env;

/// Port numbers from a reserved range that tests need refused.
#[path = "support/closed_port.rs"]
mod closed_port;

/// Shared harness of the interop suites.
#[path = "interop/harness.rs"]
mod harness;

/// The Samba PAC scenarios.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::too_long_first_doc_paragraph,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "interop_pac_samba/scenarios.rs"]
mod scenarios;
