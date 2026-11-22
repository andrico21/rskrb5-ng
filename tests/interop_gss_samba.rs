//! Live GSS-API channel bindings against Samba's LDAP server.
//!
//! The `samba-user` fixture (Samba 4.22, `scripts/interop/samba/`) runs with
//! `ldap server require strong auth = yes`, so a GSSAPI SASL bind over LDAPS
//! needs RFC 5929 `tls-server-end-point` channel bindings. The Rust GSS
//! initiator (`rskrb5_ng::gss`) binds with the bindings of the certificate its
//! TLS connection saw and is accepted as testuser1; the same bind without
//! bindings, or with the bindings of another certificate, is refused with
//! `SEC_E_BAD_BINDINGS` (0x80090346). The TLS client is the rustls of the
//! `kkdcp-rustls` leaf. Gated by `INTEROP=1`; `INTEROP_REQUIRED=1` turns an
//! unreachable fixture into a failure naming it.
#![cfg(all(feature = "kkdcp-rustls", feature = "spnego", feature = "tokio"))]

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

/// The LDAPS channel-binding scenarios.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "interop_gss_samba/scenarios.rs"]
mod scenarios;
