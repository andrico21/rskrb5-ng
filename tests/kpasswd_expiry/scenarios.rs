//! Shared setup of the password expiry scenarios.

use core::error::Error;

use rskrb5_ng::client::transport::{KdcProtocol, Tokio};
use tokio::runtime::{Builder, Runtime};

/// The error a fallible test returns; returning it fails the test.
type TestError = Box<dyn Error + Send + Sync>;

/// The expired-password flow.
#[path = "flow.rs"]
mod flow;
/// The expiry the KDC reports in last-req and key-expiration.
#[path = "notice.rs"]
mod notice;
/// The same `[libdefaults]` refusal on the AS, TGS and kpasswd paths.
#[path = "policy_kinds.rs"]
mod policy_kinds;
/// A fake realm.
#[path = "realm.rs"]
mod realm;
/// Password-policy mapping of a kpasswd result.
#[path = "result_policy.rs"]
mod result_policy;
/// A self-service change carries no RFC 3244 target fields.
#[path = "self_change.rs"]
mod self_change;
/// A fake kpasswd server.
#[path = "server.rs"]
mod server;
/// Loopback fixtures.
#[path = "support.rs"]
mod support;

/// A current-thread runtime with I/O and timers.
fn runtime() -> Result<Runtime, TestError> {
    Ok(Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()?)
}
