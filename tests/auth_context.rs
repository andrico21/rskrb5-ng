//! The authenticated message API: KRB-PRIV, KRB-SAFE and KRB-CRED through an `AuthContext`.
#![cfg(feature = "messages")]

#[path = "support/context.rs"]
mod context;

/// Authenticated message tests.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod auth_context {
    mod addresses;
    mod forwarding;
    mod private;
    mod sequence;
    mod support;
    mod time;
}
