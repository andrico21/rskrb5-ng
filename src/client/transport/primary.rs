//! The primary-KDC retry of an initial login (MIT `k5_get_init_creds`,
//! `src/lib/krb5/krb/get_in_tkt.c:2012-2046`).
//!
//! A login that a replica answered with an error is repeated once, from the
//! start, against the primary KDCs only, because the replica may not have the
//! database change (a password that was just changed) yet. The primary's result
//! is the result, except that a primary that cannot be contacted leaves the
//! replica's error.

use alloc::sync::Arc;
use std::sync::Mutex;

use super::{AsRepSession, Config, Error, KdcProtocol, NoResponder, Tokio, drive_tokio};
use crate::{client::stepwise::InitCreds, discovery::locate::EndpointRole};

tokio::task_local! {
    /// The `(host, port)` of every KDC that answered a request of the login in progress.
    pub(super) static ANSWERED: Arc<Mutex<Vec<(String, u16)>>>;
}

/// Remember that `host:port` answered, if a login is watching.
pub(super) fn record_answer(host: &str, port: u16) {
    // Outside a login there is nothing watching, which is not an error.
    match ANSWERED.try_with(|answered| {
        if let Ok(mut list) = answered.lock() {
            list.push((host.to_owned(), port));
        }
    }) {
        Ok(()) | Err(_) => {}
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
    let answered = Arc::new(Mutex::new(Vec::new()));
    let first = ANSWERED
        .scope(Arc::clone(&answered), async {
            let mut exchange = build();
            drive_tokio(
                transport,
                (config, protocol),
                &mut exchange,
                &mut NoResponder,
            )
            .await
        })
        .await;
    let Err(error) = first else {
        return first;
    };
    if transport.primary_only || !replica_failure(&error) {
        return Err(error);
    }
    let Ok(heard) = answered.lock().map(|list| list.clone()) else {
        return Err(error);
    };
    let Ok(primaries) = transport
        .locator(config)
        .locate(realm, EndpointRole::PrimaryKdc, protocol)
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
    let mut exchange = build();
    match drive_tokio(
        &primary,
        (config, protocol),
        &mut exchange,
        &mut NoResponder,
    )
    .await
    {
        Err(retry) if no_contact(&retry) => Err(error),
        other => other,
    }
}
