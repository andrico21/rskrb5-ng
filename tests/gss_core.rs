//! GSS-API Kerberos mechanism core (`rskrb5_ng::gss`): names, channel bindings,
//! credentials, context establishment, per-message tokens with their sequence
//! and replay windows, delegation and the configuration relations the
//! mechanism makes effective (plan 2 todo 18, WP-12a).
#![cfg(feature = "spnego")]

/// Turns `Option` and `Result` failures into test errors.
#[cfg(test)]
#[path = "support/context.rs"]
mod context;

/// Runs one test in a child process with a changed environment.
#[cfg(all(test, feature = "tokio"))]
#[path = "support/env.rs"]
mod env;

/// The GSS core scenarios.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "gss/tests.rs"]
mod tests;
