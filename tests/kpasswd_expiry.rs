//! Password expiry and kpasswd completion (plan 2 todo 23, WP-15a).
//!
//! The `[libdefaults]` refusal kinds of the AS, TGS and kpasswd paths, the
//! self-service password change without RFC 3244 target fields, the expiry
//! notice, and the expired-password flow against deterministic loopback KDCs
//! and kpasswd servers.
#![cfg(all(feature = "tokio", feature = "messages"))]

use core::error::Error;

use rskrb5_ng::client::transport::{KdcProtocol, Tokio};
use tokio::runtime::{Builder, Runtime};

/// The error a fallible test returns; returning it fails the test.
type TestError = Box<dyn Error + Send + Sync>;

/// The same `[libdefaults]` refusal on the AS, TGS and kpasswd paths.
#[path = "kpasswd_expiry/policy_kinds.rs"]
mod policy_kinds;
/// Loopback fixtures.
#[path = "kpasswd_expiry/support.rs"]
mod support;

/// A current-thread runtime with I/O and timers.
fn runtime() -> Result<Runtime, TestError> {
    Ok(Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()?)
}
