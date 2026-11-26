//! AD-KDC-ISSUED and AD-AND-OR: the public helpers and the acceptor's handling of both.
#![cfg(feature = "messages")]

extern crate alloc;

/// AD-CAMMAC fixtures built without the crate's CAMMAC code.
#[path = "support/cammac.rs"]
mod cammac_fixture;

#[path = "support/context.rs"]
mod context;

/// Authorization data tests.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod auth_data {
    mod acceptor;
    mod cammac;
    mod helpers;
    mod support;
}
