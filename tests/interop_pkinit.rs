//! Live PKINIT and anonymous PKINIT with the pinned MIT krb5 1.22.2 realm.
//!
//! Plan 2 todo 8 (WP-06): the fixture `mit-kdc` (TEST.RSKRB5) with the PKINIT
//! CA, principals and KDC certificate of `scripts/interop/mit/provision.d/45-pkinit.sh`
//! and the anonymous principal of `48-anonymous.sh`. A certificate login (DH and
//! ECDH) earns the `pkinit` indicator that `pkinitrequired/svc.test.rskrb5`
//! requires; anonymous PKINIT yields `WELLKNOWN/ANONYMOUS@WELLKNOWN:ANONYMOUS`;
//! and the anonymous-armor hook of FAST armors fastuser's encrypted-challenge
//! login, which earns `fast-ec`. Gated by `INTEROP=1`; `INTEROP_REQUIRED=1`
//! turns an unreachable fixture into a failure naming it.
#![cfg(all(feature = "tokio", feature = "pkinit"))]

/// Child-process runner for the tests that change the environment.
#[path = "support/env.rs"]
mod child_env;

/// Port numbers from a reserved range that tests need refused.
#[path = "support/closed_port.rs"]
mod closed_port;

/// Shared harness of the interop suites.
#[path = "interop/harness.rs"]
mod harness;

/// The PKINIT scenarios.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "interop_pkinit/scenarios.rs"]
mod scenarios;
