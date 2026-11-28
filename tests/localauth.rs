//! Local authorization and name translation (plan 2 todo 25, WP-17, the
//! `localauth` leaf).
//!
//! The mapping scenarios carry the expected values of MIT krb5 1.22.2's own
//! `src/tests/t_localauth.py`; the rule, `.k5login` and home-directory
//! scenarios are the negative paths of the delivery contract.

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

/// The `.k5login` file contents: bounds and the exact line match.
#[cfg(test)]
#[cfg(unix)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "localauth/k5login_content.rs"]
mod k5login_content;

/// The built-in modules as providers of the extension registry.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "localauth/builtin.rs"]
mod builtin;

/// `[plugins] localauth` controls over the public helpers.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "localauth/controls.rs"]
mod controls;

/// `HOME` never selects the `.k5login` file.
#[cfg(test)]
#[cfg(unix)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "localauth/home.rs"]
mod home;

/// The four relations, with and without the leaf.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "localauth/profile.rs"]
mod profile;
