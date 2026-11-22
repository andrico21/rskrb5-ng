//! Local authorization and name translation (plan 2 todo 25, WP-17, the
//! `localauth` leaf).
//!
//! The mapping scenarios carry the expected values of MIT krb5 1.22.2's own
//! `src/tests/t_localauth.py`; the rule, `.k5login` and home-directory
//! scenarios are the negative paths of the delivery contract.
#![cfg(feature = "localauth")]

/// Principals, accounts and a fixture directory.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    reason = "test code is not rendered API documentation"
)]
#[path = "localauth/support.rs"]
mod support;

/// MIT's mapping fixtures through `krb5.conf` text.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "localauth/mapping.rs"]
mod mapping;

/// Malformed, hostile and over-bound rules.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "localauth/rules.rs"]
mod rules;

/// The `.k5login` module: ownership, modes, symlinks, bounds and the line match.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "localauth/k5login.rs"]
mod k5login;
