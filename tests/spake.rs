//! SPAKE preauthentication (RFC 9588, plan 2 todo 9, the `spake` leaf).
//!
//! The scenarios drive the public stepwise AS exchange against a fake KDC that
//! implements the KDC half of RFC 9588 independently (its own transcript and
//! key derivation over the public PRF primitives, and `curve25519-dalek` for
//! the group). They cover the full exchange, the optimistic challenge, the
//! rejections (group outside the policy, wrong factor, malformed messages and
//! elements, a tampered transcript), the absence of any fallback, and the
//! `disable_encrypted_timestamp` downgrade protection. Without the leaf, one
//! scenario shows the engine never answers PA-SPAKE and the profile tests check
//! the `FeatureUnavailable` diagnostic.
#![cfg(feature = "messages")]

/// The fake KDC.
#[cfg(test)]
#[path = "spake/kdc.rs"]
mod kdc;

/// The exchange scenarios.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "spake/scenarios.rs"]
mod scenarios;

/// Configuration and outgoing admission, with and without the leaf.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "spake/profile.rs"]
mod profile;
