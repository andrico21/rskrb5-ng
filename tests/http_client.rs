//! The HTTP Negotiate client and the HTTP session manager (plan 2 todo 26,
//! WP-19): redirects, challenge bounds, mutual authentication, replayable
//! bodies and server sessions, over in-process origins (no sockets, no timing).
#![cfg(all(feature = "tokio", feature = "http"))]

extern crate alloc;

/// Turns `Option` and `Result` failures into test errors.
#[cfg(test)]
#[path = "support/context.rs"]
mod context;

/// The client and session scenarios.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "http_client/tests.rs"]
mod tests;
