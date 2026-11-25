//! Registered server locators on the exchange routes (MIT-plugin-6).
//!
//! KDC requests and the primary-KDC retry ask the transport's registry before
//! the profile, and a failing locator stops the request.

extern crate alloc;

use alloc::sync::Arc;
use core::{sync::atomic::Ordering, time::Duration};
use std::time::SystemTime;

use rskrb5_ng::{
    client::{
        options::AsReq,
        principal::Principal,
        transport::{KdcProtocol, Tokio},
    },
    config::Config,
    error::Client as ClientError,
    extensions::{
        Extension, LocateRequest, LocateService, ProviderError, Registry, ServerAddress,
        ServerLocator,
    },
};
use tokio::time::timeout;

use crate::{
    TestError,
    primary::{Stub, kdc},
};

/// A realm no profile below lists.
const REALM: &str = "LOCATED.TEST";

/// A locator that names `kdc` for any KDC and `primary` for the primary KDC,
/// or fails every request.
struct Located {
    /// The KDC address, or the failure.
    kdc: Result<String, &'static str>,
    /// The primary KDC address, if any.
    primary: Option<String>,
}

impl ServerLocator for Located {
    fn id(&self) -> &'static str {
        "located"
    }

    fn locate(
        &self,
        request: &LocateRequest<'_>,
    ) -> Result<Option<Vec<ServerAddress>>, ProviderError> {
        let address = match (request.service, &self.kdc) {
            (_, Err(reason)) => return Err((*reason).into()),
            (LocateService::Kdc, Ok(address)) => Some(address),
            (LocateService::PrimaryKdc, Ok(_)) => self.primary.as_ref(),
            (_, Ok(_)) => None,
        };
        address
            .map(|text| {
                let (host, port) = text.rsplit_once(':').ok_or("host:port")?;
                Ok(vec![ServerAddress::new(host, port.parse()?)])
            })
            .transpose()
    }
}

/// A transport whose registry holds `locator`.
fn transport(locator: Located) -> Result<Tokio, TestError> {
    let mut registry = Registry::new();
    registry.register(Extension::ServerLocator(Arc::new(locator)))?;
    Ok(Tokio::new().with_registry(Arc::new(registry)))
}

/// A profile without DNS that lists `kdc` for `realm` when given.
fn profile(listed: Option<(&str, &Stub)>) -> Result<Config, TestError> {
    let realms = listed.map_or_else(String::new, |(realm, stub)| {
        format!("[realms]\n{realm} = {{\nkdc = {}\n}}\n", stub.address)
    });
    Ok(Config::parse(&format!(
        "[libdefaults]\ndns_lookup_kdc = false\n{realms}"
    ))?)
}

/// A KDC request for a realm only the registered locator knows reaches the
/// located KDC, and its answer is the reply.
#[tokio::test]
async fn send_to_realm_uses_registered_locator() -> Result<(), TestError> {
    // Given a stub KDC that only a registered locator names.
    let located = kdc(6).await?;
    let config = profile(None)?;
    let with_registry = transport(Located {
        kdc: Ok(located.address.clone()),
        primary: None,
    })?;
    // When a request is sent to the realm with and without the registry.
    let reply = with_registry
        .send_to_realm(&config, KdcProtocol::Tcp, REALM, &[0x6a, 0])
        .await?;
    let unknown = Tokio::new()
        .send_to_realm(&config, KdcProtocol::Tcp, REALM, &[0x6a, 0])
        .await;
    // Then the located KDC answered, and without the registry the realm is unknown.
    assert_eq!(reply.first(), Some(&0x7e), "a KRB-ERROR came back");
    assert_eq!(located.contacts.load(Ordering::SeqCst), 1);
    assert!(
        matches!(unknown, Err(ClientError::Config(_))),
        "{unknown:?}"
    );
    Ok(())
}

/// A failing registered locator stops the request: the profile's KDC is not asked.
#[tokio::test]
async fn failing_locator_stops_send_to_realm() -> Result<(), TestError> {
    // Given a profile KDC and a registered locator that fails.
    let listed = kdc(6).await?;
    let config = profile(Some((REALM, &listed)))?;
    let failing = transport(Located {
        kdc: Err("the locator is down"),
        primary: None,
    })?;
    // When a request is sent.
    let result = failing
        .send_to_realm(&config, KdcProtocol::Tcp, REALM, &[0x6a, 0])
        .await;
    // Then the locator's failure is the error and the profile KDC was never contacted.
    assert!(matches!(result, Err(ClientError::Locate(_))), "{result:?}");
    assert_eq!(listed.contacts.load(Ordering::SeqCst), 0);
    Ok(())
}

/// The primary-KDC retry after a replica's failure asks the same registry for
/// the primary KDC (MIT `get_in_tkt.c:2031-2045` with `locate_kdc.c` modules).
#[tokio::test]
async fn primary_retry_preserves_registry() -> Result<(), TestError> {
    // Given a located replica that refuses the preauthentication and a located primary.
    let replica = kdc(24).await?;
    let primary = kdc(6).await?;
    let config = profile(None)?;
    let located = transport(Located {
        kdc: Ok(replica.address.clone()),
        primary: Some(primary.address.clone()),
    })?;
    // When a password login runs.
    let result = timeout(
        Duration::from_secs(10),
        located.login_tgt_with_password_config(
            &config,
            KdcProtocol::Tcp,
            Principal::user(REALM, "testuser1"),
            b"wrong",
            AsReq::new(SystemTime::now(), 7),
        ),
    )
    .await?;
    // Then the primary the registry names was asked after the replica and answered.
    let code = match result {
        Err(ClientError::Kdc(error)) => error.error_code(),
        other => return Err(format!("expected a KDC error, got {other:?}").into()),
    };
    assert_eq!(code, 6_i32);
    assert_eq!(replica.contacts.load(Ordering::SeqCst), 1);
    assert_eq!(primary.contacts.load(Ordering::SeqCst), 1);
    Ok(())
}
