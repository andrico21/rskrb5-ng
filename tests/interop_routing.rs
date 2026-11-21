//! Live routing against the pinned MIT krb5 1.22.2 realms.
//!
//! Plan 2 todo 17 (WP-11): the non-hierarchical `[capaths]` route TEST.RSKRB5
//! -> OTHER.RSKRB5 -> FAR.EXAMPLE (the TEST KDC has no `[capaths]`, so only a
//! client path reaches FAR) and the acceptor's check of the transited path
//! the FAR KDC recorded; `verify_init_creds` against the host keytab and a
//! wrong one; and a user-to-user ticket sealed in the target's TGT session
//! key. Gated by `INTEROP=1`; `INTEROP_REQUIRED=1` turns an unreachable
//! fixture into a failure naming it.
#![cfg(all(feature = "tokio", feature = "spnego"))]

extern crate alloc;

/// Child-process runner for the tests that change the environment.
#[path = "support/env.rs"]
mod child_env;

/// Port numbers from a reserved range that tests need refused.
#[path = "support/closed_port.rs"]
mod closed_port;

/// Shared harness of the interop suites.
#[path = "interop/harness.rs"]
mod harness;

/// The MIT routing scenarios.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::too_long_first_doc_paragraph,
    clippy::too_many_lines,
    reason = "test code is not rendered API documentation; a live scenario reads as one story"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "interop_routing/scenarios.rs"]
mod scenarios;
