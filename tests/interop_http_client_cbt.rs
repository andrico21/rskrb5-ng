//! Live HTTP Negotiate with TLS channel bindings (plan 2 todo 28, wave 11 lane
//! F, FU-HTC-P07).
//!
//! An HTTPS service built in the test from the crate's own SPNEGO acceptor
//! (`spnego::Acceptor` over `gss::Acceptor`) holds the keytab of
//! `HTTP/http.test.rskrb5` that the pinned MIT krb5 1.22.2 realm exported and
//! REQUIRES the RFC 5929 `tls-server-end-point` bindings of its own certificate.
//! The crate's `NegotiateHttpClient` over the built-in rustls transport logs in
//! to the realm, gets the service ticket from the MIT KDC and binds its token to
//! the TLS connection that carries it: the service accepts the bound token and
//! refuses a token bound to another certificate and an unbound one. Gated by
//! `INTEROP=1` and the `kkdcp-rustls` leaf; `INTEROP_REQUIRED=1` turns an
//! unreachable fixture into a failure naming it.
#![cfg(all(feature = "kkdcp-rustls", feature = "http", feature = "tokio"))]

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

/// The channel-binding scenarios.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "interop_http_client_cbt/scenarios.rs"]
mod scenarios;
