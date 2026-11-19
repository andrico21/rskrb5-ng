//! Live Camellia negotiation with the pinned MIT krb5 1.22.2 realm.
//!
//! The fixture `mit-kdc` (`scripts/interop/mit/`, drop-ins numbered 55) serves a
//! user and a service whose long-term keys are Camellia only. The scenario asks
//! for Camellia with `permitted_enctypes` naming it on both sides (the crate's
//! configuration and the fixture's `krb5.conf`), then asserts what was negotiated:
//! the AS reply is encrypted in the user's Camellia key, the service ticket and its
//! session key are Camellia, and the crate's acceptor opens the ticket with a
//! Camellia keytab. Gated by `INTEROP=1` and the `camellia` leaf feature;
//! `INTEROP_REQUIRED=1` turns an unreachable fixture into a failure naming it.
#![cfg(all(feature = "camellia", feature = "tokio", feature = "spnego"))]

/// Child-process runner for the tests that change the environment.
#[path = "support/env.rs"]
mod child_env;

/// Port numbers from a reserved range that tests need refused.
#[path = "support/closed_port.rs"]
mod closed_port;

/// Shared harness of the interop suites.
#[path = "interop/harness.rs"]
mod harness;

/// The Camellia scenario.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    reason = "test code is not rendered API documentation"
)]
#[path = "interop_camellia/scenarios.rs"]
mod scenarios;
