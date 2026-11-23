//! Replay stores: the MIT `file2` format, fail-closed storage, cross-process locking and the validator.
#![cfg(feature = "messages")]

extern crate alloc;

#[path = "support/context.rs"]
mod context;
#[path = "support/env.rs"]
mod env;

/// Replay store tests.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod replay_store {
    mod concurrency;
    mod config;
    mod failures;
    mod layout;
    mod name;
    mod support;
    mod validator;
}
