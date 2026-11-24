//! GSS-API Kerberos mechanism extensions (`rskrb5_ng::gss`): IOV and AEAD
//! tokens, the GSS pseudo-random function, context and credential transfer,
//! DCE-style establishment, the legacy RFC 1964/4757 token formats, name
//! attributes and impersonation (plan 2 todo 19, WP-12b).
#![cfg(feature = "spnego")]

/// Turns `Option` and `Result` failures into test errors.
#[cfg(test)]
#[path = "support/context.rs"]
mod context;

/// The GSS extension scenarios.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "gss_ext/tests.rs"]
mod tests;
