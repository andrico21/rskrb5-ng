//! Server roles and registered locators (MIT-dns-1, -7, MIT-plugin-6): the typed
//! `discovery::locate` API.

extern crate alloc;

use alloc::sync::Arc;

use hickory_resolver::proto::rr::RecordType;
use rskrb5_ng::{
    client::transport::{KdcEndpoint, KdcEndpointSource, KdcProtocol, Tokio},
    config::Config,
    discovery::locate::EndpointRole,
    error::Client as ClientError,
    extensions::{
        Extension, LocateRequest, LocateService, ProviderError, Registry, ServerAddress,
        ServerLocator,
    },
};

use crate::{
    TestError,
    fixture::{Dns, Reply, srv, uri},
};

/// The realm every test discovers.
const REALM: &str = "TEST.GOKRB5";
/// URI discovery name of the KDC service.
const KDC_URI: &str = "_kerberos.test.gokrb5.";

/// A profile with DNS discovery and URI records.
fn config(uri_lookup: bool) -> Result<Config, TestError> {
    Ok(Config::parse(&format!(
        "[libdefaults]\ndns_lookup_kdc = true\ndns_uri_lookup = {uri_lookup}\n"
    ))?)
}

/// A transport that asks `dns`.
fn via(dns: &Dns) -> Result<Tokio, TestError> {
    Ok(Tokio::new().with_dns_server(&dns.address().to_string())?)
}

/// The `host:port` of each endpoint.
fn authorities(endpoints: &[KdcEndpoint]) -> Vec<String> {
    endpoints.iter().map(KdcEndpoint::authority).collect()
}

/// MIT-dns-7 (record side): a primary KDC is a URI record with the `m` flag.
#[tokio::test]
async fn the_primary_role_needs_the_m_flag() -> Result<(), TestError> {
    // Given a flagged and an unflagged record.
    let dns = Dns::start([(
        KDC_URI,
        RecordType::Unknown(256),
        Reply::Records(vec![
            uri(0, "krb5srv::tcp:127.0.0.1:1088"),
            uri(1, "krb5srv:m:tcp:127.0.0.1:1089"),
        ]),
    )])
    .await?;
    let transport = via(&dns)?;
    let profile = config(true)?;
    // When each role is located.
    let any = transport
        .locator(&profile)
        .locate(REALM, EndpointRole::Kdc, KdcProtocol::Tcp)
        .await?;
    let primary = transport
        .locator(&profile)
        .locate(REALM, EndpointRole::PrimaryKdc, KdcProtocol::Tcp)
        .await?;
    // Then the primary role sees only the flagged record.
    assert_eq!(authorities(&any), ["127.0.0.1:1088", "127.0.0.1:1089"]);
    assert_eq!(authorities(&primary), ["127.0.0.1:1089"]);
    Ok(())
}

/// MIT-dns-1: the administration server has its own role, port and labels.
#[tokio::test]
async fn the_admin_role_uses_its_own_profile_key_and_dns_labels() -> Result<(), TestError> {
    // Given a configured realm and a DNS-only realm.
    let dns = Dns::start([
        (
            "_kerberos-adm._tcp.test.gokrb5.",
            RecordType::SRV,
            Reply::Records(vec![srv(0, 7749, "127.0.0.1.")?]),
        ),
        (
            "_kerberos._tcp.test.gokrb5.",
            RecordType::SRV,
            Reply::Records(vec![srv(0, 88, "127.0.0.2.")?]),
        ),
    ])
    .await?;
    let transport = via(&dns)?;
    let configured = Config::parse(
        "[libdefaults]\ndns_lookup_kdc = true\n[realms]\nTEST.GOKRB5 = {\nadmin_server = adm.example\n}\n",
    )?;
    // When the administration server is located for each.
    let listed = transport
        .locator(&configured)
        .locate(REALM, EndpointRole::Kadmin, KdcProtocol::Tcp)
        .await?;
    let published = transport
        .locator(&config(false)?)
        .locate(REALM, EndpointRole::Kadmin, KdcProtocol::Tcp)
        .await?;
    // Then the profile's host takes port 749 and DNS answers `_kerberos-adm`.
    assert_eq!(authorities(&listed), ["adm.example:749"]);
    assert_eq!(authorities(&published), ["127.0.0.1:7749"]);
    Ok(())
}

/// A registered locator, a failing one, and the profile all come before DNS (MIT-plugin-6).
struct Fixed(Result<Vec<ServerAddress>, &'static str>);

impl ServerLocator for Fixed {
    fn id(&self) -> &'static str {
        "fixed"
    }

    fn locate(
        &self,
        request: &LocateRequest<'_>,
    ) -> Result<Option<Vec<ServerAddress>>, ProviderError> {
        match (&self.0, request.service) {
            (Ok(addresses), LocateService::Kdc) => Ok(Some(addresses.clone())),
            (Err(reason), LocateService::Kdc) => Err((*reason).into()),
            (Ok(_) | Err(_), _) => Ok(None),
        }
    }
}

/// A registry holding `locator`.
fn registry_of(locator: Fixed) -> Result<Registry, TestError> {
    let mut registry = Registry::new();
    registry.register(Extension::ServerLocator(Arc::new(locator)))?;
    Ok(registry)
}

/// MIT-plugin-6: a registered locator is asked before the profile and DNS.
#[tokio::test]
async fn a_registered_locator_answers_before_the_profile_and_dns() -> Result<(), TestError> {
    // Given a locator and a profile that lists a different KDC.
    let dns = Dns::start([]).await?;
    let registry = registry_of(Fixed(Ok(vec![ServerAddress::new(
        "provided.example",
        8888,
    )])))?;
    let profile = Config::parse(
        "[libdefaults]\ndns_lookup_kdc = true\n[realms]\nTEST.GOKRB5 = {\nkdc = listed.example\n}\n",
    )?;
    // When the KDCs are located with and without the registry.
    let transport = via(&dns)?;
    let provided = transport
        .locator(&profile)
        .with_registry(&registry)
        .locate(REALM, EndpointRole::Kdc, KdcProtocol::Tcp)
        .await?;
    let listed = transport
        .locator(&profile)
        .locate(REALM, EndpointRole::Kdc, KdcProtocol::Tcp)
        .await?;
    // Then the locator wins, the profile is used without it, and DNS is never asked.
    assert_eq!(authorities(&provided), ["provided.example:8888"]);
    assert_eq!(
        provided.first().map(|endpoint| endpoint.source),
        Some(KdcEndpointSource::Provider)
    );
    assert_eq!(authorities(&listed), ["listed.example:88"]);
    assert_eq!(dns.questions()?, Vec::<String>::new());
    Ok(())
}

/// A locator that fails stops the lookup with a typed error.
#[tokio::test]
async fn a_failing_locator_stops_the_lookup() -> Result<(), TestError> {
    // Given a locator that fails.
    let dns = Dns::start([]).await?;
    let registry = registry_of(Fixed(Err("no route to the locator")))?;
    // When the KDCs are located.
    let result = via(&dns)?
        .locator(&config(false)?)
        .with_registry(&registry)
        .locate(REALM, EndpointRole::Kdc, KdcProtocol::Tcp)
        .await;
    // Then the failure is the error, and DNS is not asked.
    assert!(matches!(result, Err(ClientError::Locate(_))), "{result:?}");
    assert_eq!(dns.questions()?, Vec::<String>::new());
    Ok(())
}
