//! IAKERB (`rskrb5_ng::gss::iakerb`): Kerberos through an application-mediated
//! KDC relay, as MIT krb5 1.22.2 implements `draft-ietf-krb-wg-iakerb-02`
//! (plan 2 todo 20, WP-13a).
#![cfg(feature = "spnego")]

/// Turns `Option` and `Result` failures into test errors.
#[cfg(test)]
#[path = "support/context.rs"]
mod context;

/// The IAKERB scenarios.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "gss_iakerb/tests.rs"]
mod tests;
