//! Remote kadm5 administration over RPCSEC_GSS (`rskrb5_ng::kadm5`,
//! `rskrb5_ng::rpcsec_gss`): the bounded XDR and record-marking codecs, the
//! RFC 2203 integrity and privacy services with their sequence checks, the
//! kadm5 API version negotiation and every remote operation of MIT krb5
//! 1.22.2's client library, against a test-only loopback server that runs the
//! crate's own GSS acceptor (plan 2 todo 24, WP-15b).
#![cfg(all(feature = "spnego", feature = "tokio"))]

/// Turns `Option` and `Result` failures into test errors.
#[cfg(test)]
#[path = "support/context.rs"]
mod context;

/// The kadm5 scenarios.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "kadm5/tests.rs"]
mod tests;
