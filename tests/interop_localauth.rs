//! Live local authorization against the pinned MIT krb5 1.22.2 realm.
//!
//! The fixture `mit-kdc` (`scripts/interop/mit/`, drop-ins numbered 85) holds
//! local accounts, their `.k5login` files and the `auth_to_local` relations of
//! the realm, and an installed probe of MIT's own `krb5_kuserok` and
//! `krb5_aname_to_localname`. The scenario logs `preauthuser` in against the
//! KDC, takes the verified client principal of the AS reply, and asks this
//! crate's `authorize_local` and `principal_to_local_name` the questions the
//! probe answers inside the container; it states every answer that differs
//! (this crate is stricter than MIT for a writable or symlinked `.k5login` and
//! for `auth_to_local_names` across realms). Gated by `INTEROP=1` and the
//! `localauth` leaf; `INTEROP_REQUIRED=1` turns an unreachable fixture into a
//! failure naming it.
#![cfg(all(unix, feature = "localauth", feature = "tokio"))]

/// Port numbers from a reserved range that tests need refused.
#[path = "support/closed_port.rs"]
mod closed_port;

/// Child-process runner for the tests that change the environment.
#[path = "support/env.rs"]
mod child_env;

/// Shared harness of the interop suites.
#[path = "interop/harness.rs"]
mod harness;

/// The accounts of the fixture rebuilt on the host.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    reason = "test code is not rendered API documentation"
)]
#[path = "interop_localauth/homes.rs"]
mod homes;

/// The local-authorization scenario.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "interop_localauth/scenarios.rs"]
mod scenarios;
