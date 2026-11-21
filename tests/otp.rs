//! OTP inside FAST (plan 2 todo 10, WP-08, RFC 6560).
//!
//! MIT's encodings, the challenge's flags and bounds, the request the client
//! builds, and the stepwise AS engine against a deterministic FAST KDC that
//! requires OTP.
#![cfg(feature = "messages")]

/// The RFC 6113 messages, written independently of the library.
#[cfg(test)]
#[path = "fast/asn1.rs"]
mod asn1;

/// The fake KDC.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    reason = "test code is not rendered API documentation"
)]
#[path = "otp/kdc.rs"]
mod kdc;

/// MIT's encodings.
#[cfg(test)]
#[path = "otp/vectors.rs"]
mod vectors;

/// The messages, flags, bounds and requests.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "otp/wire.rs"]
mod wire;

/// Exchanges through the engine.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "otp/exchange.rs"]
mod exchange;
