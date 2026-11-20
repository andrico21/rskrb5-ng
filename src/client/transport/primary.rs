//! The primary-KDC retry of an initial login (MIT `k5_get_init_creds`,
//! `src/lib/krb5/krb/get_in_tkt.c:2012-2046`).
//!
//! A login that a replica answered with an error is repeated once, from the
//! start, against the primary KDCs only, because the replica may not have the
//! database change (a password that was just changed) yet. The primary's result
//! is the result, except that a primary that cannot be contacted leaves the
//! replica's error.

use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, PoisonError};

use super::{AsRepSession, Config, Error, KdcProtocol, NoResponder, Tokio, drive_tokio};
use crate::{client::stepwise::InitCreds, discovery::locate::EndpointRole};

/// The `(host, port)` of every KDC that answered a request, for each login in progress.
///
/// `Tokio` is `Copy` and the exchange driver is not this module's, so the transport carries
/// the key of its login and reports answers here.
static ANSWERED: Mutex<BTreeMap<u64, Vec<(String, u16)>>> = Mutex::new(BTreeMap::new());
/// The next key.
static NEXT_WATCH: AtomicU64 = AtomicU64::new(1);

/// A login's entry of [`ANSWERED`], removed when the login ends or is cancelled.
struct Watch(u64);

impl Watch {
    /// Start a watch.
    fn start() -> Self {
        let key = NEXT_WATCH.fetch_add(1, Ordering::Relaxed);
        drop(
            ANSWERED
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .insert(key, Vec::new()),
        );
        Self(key)
    }

    /// The servers that answered so far.
    fn heard(&self) -> Vec<(String, u16)> {
        ANSWERED
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&self.0)
            .cloned()
            .unwrap_or_default()
    }
}

impl Drop for Watch {
    fn drop(&mut self) {
        drop(
            ANSWERED
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .remove(&self.0),
        );
    }
}

/// Remember that `host:port` answered a request of the login `key`, if it is being watched.
pub(super) fn record_answer(key: Option<u64>, host: &str, port: u16) {
    let Some(watched) = key else {
        return;
    };
    if let Some(list) = ANSWERED
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .get_mut(&watched)
    {
        list.push((host.to_owned(), port));
    }
}

/// Whether the error of a login can be a replica's stale view: an error reply of the KDC or
/// a reply that does not decrypt (a changed password).
const fn replica_failure(error: &Error) -> bool {
    matches!(error, Error::Kdc(_) | Error::Crypto(_))
}

/// Whether `error` says that no server could be contacted or located.
const fn no_contact(error: &Error) -> bool {
    matches!(
        error,
        Error::KdcEndpointFailures {
            realm: _,
            protocol: _,
            failures: _
        } | Error::NoKdcEndpoints {
            realm: _,
            protocol: _
        } | Error::DnsSrvLookup {
            realm: _,
            protocol: _,
            message: _
        } | Error::DnsServiceUnavailable {
            service: _,
            realm: _
        } | Error::TransportTimeout(_)
            | Error::Io(_)
            | Error::Config(_)
            | Error::DnsResolverConfig(_)
    )
}

/// Run the login `build` makes, and repeat it on the primary KDCs when a replica failed it.
///
/// # Errors
/// Returns the login's error, or that of the primary retry unless the primary could not be
/// contacted.
///
/// # Cancel safety
/// cancel-safe in the sense of [`drive_tokio`]: no client or cache state changes.
pub(super) async fn login<'exchange, F>(
    transport: &Tokio,
    (config, protocol, realm): (&Config, KdcProtocol, &str),
    build: F,
) -> Result<AsRepSession, Error>
where
    F: Fn() -> InitCreds<'exchange> + Send + Sync,
{
    let watch = Watch::start();
    let watched = transport.with_watch(watch.0);
    let mut exchange = build();
    let first = drive_tokio(
        &watched,
        (config, protocol),
        &mut exchange,
        &mut NoResponder,
    )
    .await;
    let Err(error) = first else {
        return first;
    };
    if transport.primary_only || !replica_failure(&error) {
        return Err(error);
    }
    let heard = watch.heard();
    let Ok(primaries) = transport
        .locator(config)
        .locate(None, realm, EndpointRole::PrimaryKdc, protocol)
        .await
    else {
        return Err(error);
    };
    let from_replica = heard.iter().any(|(host, port)| {
        !primaries
            .iter()
            .any(|primary| primary.host == *host && primary.port == *port)
    });
    if primaries.is_empty() || !from_replica {
        return Err(error);
    }
    let primary = transport.with_primary_kdcs();
    let mut repeated = build();
    match drive_tokio(
        &primary,
        (config, protocol),
        &mut repeated,
        &mut NoResponder,
    )
    .await
    {
        Err(retry) if no_contact(&retry) => Err(error),
        other => other,
    }
}
