//! `NegoEx` (MS-NEGOEX) message framework and its SPNEGO integration
//! (`rskrb5_ng::gss::negoex`, plan 2 todo 21, WP-13b).
#![cfg(feature = "spnego")]

/// Turns `Option` and `Result` failures into test errors.
#[cfg(test)]
#[path = "support/context.rs"]
mod context;

/// The `NegoEx` scenarios.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "gss_negoex/tests.rs"]
mod tests;
