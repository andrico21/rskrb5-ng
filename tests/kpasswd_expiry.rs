//! Password expiry and kpasswd completion (plan 2 todo 23, WP-15a).
//!
//! The `[libdefaults]` refusal kinds of the AS, TGS and kpasswd paths, the
//! self-service password change without RFC 3244 target fields, the expiry
//! notice, and the expired-password flow against deterministic loopback KDCs
//! and kpasswd servers.
#![cfg(all(feature = "tokio", feature = "messages"))]

/// The scenarios and their fixtures.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::too_long_first_doc_paragraph,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "kpasswd_expiry/scenarios.rs"]
mod scenarios;
