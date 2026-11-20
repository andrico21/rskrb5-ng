//! RFC 6113 FAST and the encrypted challenge (plan 2 todo 7, WP-05).
//!
//! MIT and independently generated vectors, a deterministic FAST KDC driven through
//! the stepwise AS engine with tamper switches, the policies, the
//! authenticated canonicalization and the outgoing padata admission.
#![cfg(feature = "messages")]

/// The fake KDC.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    reason = "test code is not rendered API documentation"
)]
#[path = "fast/kdc.rs"]
mod kdc;

/// Encoding and derivation vectors.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "fast/vectors.rs"]
mod vectors;

/// Exchanges through the engine.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "fast/exchange.rs"]
mod exchange;

/// The outgoing padata admission of armored requests.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "fast/admission.rs"]
mod admission;
