//! Pure-Rust Kerberos 5 client and service library with HTTP Negotiate.
//!
//! `rskrb5-ng` continues `rskrb5` independently. The API can still change
//! before 1.0; Kerberos wire formats, cryptographic behavior and the gokrb5
//! fixture parity are treated as compatibility-sensitive. The supported
//! surface is centered on Kerberos password or keytab login, FILE/WRFILE/DIR
//! credential-cache loading, password-change flows, service-side AP-REQ
//! validation, and HTTP Negotiate/SPNEGO header generation and retry wrappers.
//!
//! ```ignore
//! let config = rskrb5_ng::Config::load_default()?;
//! let mut client =
//!     rskrb5_ng::NegotiateClient::from_ccache_name(config, "FILE:/tmp/krb5cc")?;
//! let header = client
//!     .authorization_header_for_host("HTTP", "auth.cern.ch")
//!     .await?;
//! ```
//!
//! # Feature Flags
//!
//! - `messages`: Kerberos ASN.1 message wrappers and protocol modules.
//! - `spnego`: SPNEGO/GSSAPI token and HTTP Negotiate header support.
//! - `tokio`: async KDC/kpasswd transports and high-level client flows.
//! - `http`: generic `http` crate request/response helpers; with `tokio`,
//!   client retry wrappers.
//! - `tower`: service-side Tower Negotiate middleware.
//! - `serde`: JSON diagnostics and redacted metadata helpers.
//! - `evaluation`: candidate-crate compatibility report generation.
//!
//! # Current Limits
//!
//! Platform credential stores (`API`, `KCM`, `KEYRING`, `MSLSA`), FAST,
//! PKINIT, system GSSAPI/SSPI facades, and full maintained Active Directory
//! CI are outside the supported preview scope. Unsupported credential
//! cache stores are reported as
//! [`error::Ccache::UnsupportedCacheType`].

#![forbid(unsafe_code)]
#![expect(clippy::pub_use, reason = "public facade")]
#![cfg_attr(
    test,
    expect(
        dead_code_pub_in_binary,
        reason = "public API: unused inside the unit-test harness"
    )
)]

extern crate alloc;

#[cfg(doctest)]
#[doc = include_str!("../docs/migration-from-rskrb5-patched.md")]
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct MigrationGuideDoctests;

#[cfg(all(doctest, feature = "tokio", feature = "spnego"))]
#[doc = include_str!("../README.md")]
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct ReadmeDoctests;

use core::result;

#[cfg(feature = "evaluation")]
pub mod evaluation;

#[cfg(feature = "messages")]
pub mod ap_rep;
#[cfg(feature = "messages")]
pub mod ap_req;
pub mod ccache;
#[cfg(feature = "messages")]
pub mod client;
#[path = "config.rs"]
pub mod configuration;
#[path = "crypto.rs"]
pub mod cryptography;
#[cfg(feature = "messages")]
/// DER helpers: trimming zero padding after a top-level DER value.
mod der;
#[cfg(feature = "tokio")]
pub mod discovery;
pub mod error;
pub mod extensions;
/// Credential-cache and keytab file-name parsing with path-token expansion.
mod file_name;
#[cfg(feature = "http")]
pub mod http;
#[cfg(feature = "messages")]
pub mod kadmin;
#[cfg(feature = "messages")]
pub mod kdc_rep;
#[cfg(feature = "messages")]
pub mod kdc_req;
pub mod keytab;
#[cfg(feature = "messages")]
pub mod krb_cred;
#[cfg(feature = "messages")]
pub mod krb_error;
#[cfg(feature = "messages")]
pub mod krb_priv;
#[cfg(feature = "messages")]
pub mod krb_safe;
#[cfg(feature = "messages")]
pub mod messages;
pub mod pac;
#[cfg(feature = "messages")]
pub mod preauth;
pub mod routing;
mod secure_env;
#[cfg(feature = "messages")]
pub mod service;
#[cfg(feature = "spnego")]
pub mod spnego;
#[cfg(feature = "messages")]
pub mod ticket;
pub mod trace;
#[cfg(feature = "messages")]
pub mod transport;

#[cfg(feature = "tokio")]
pub use client::Tokio as TokioClient;
#[cfg(all(feature = "tokio", feature = "spnego"))]
pub use client::negotiate::{BlockingClient as BlockingNegotiateClient, Client as NegotiateClient};
#[cfg(feature = "messages")]
pub use client::principal::Principal;
pub use config::Config;
pub use configuration as config;
pub use cryptography as crypto;
#[cfg(feature = "messages")]
pub use service::Validator as ServiceValidator;

/// Current crate-level result type.
pub type Result<T> = result::Result<T, Error>;

use crate::error::Any as Error;
