//! PKINIT and anonymous PKINIT (RFC 4556, RFC 6112, RFC 8070, RFC 8636; plan 2
//! todo 8, the `pkinit` leaf).
//!
//! With the leaf, the scenarios drive the public stepwise AS exchange against a
//! fake KDC that implements the KDC half independently (its own ASN.1, CMS
//! assembly with `cms`, ECDH and signatures with `p256`, and its own RFC 8636
//! KDF), signing with the OpenSSL-generated fixtures of
//! `tests/pkinit/fixtures/generate.sh`. The profile tests run with and without
//! the leaf.
#![cfg(feature = "messages")]

/// The fake KDC.
#[cfg(test)]
#[cfg(feature = "pkinit")]
#[expect(
    clippy::missing_errors_doc,
    reason = "test code is not rendered API documentation"
)]
#[path = "pkinit/kdc.rs"]
mod kdc;

/// The exchange scenarios.
#[cfg(test)]
#[cfg(feature = "pkinit")]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "pkinit/scenarios.rs"]
mod scenarios;

/// Configuration, with and without the leaf.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "pkinit/profile.rs"]
mod profile;
