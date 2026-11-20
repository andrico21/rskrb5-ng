//! Server location: registered locators, the profile, DNS URI records, DNS SRV records.
//!
//! The order is MIT's `locate_server` (`src/lib/krb5/os/locate_kdc.c:819-836`):
//! locator modules, then the profile, then (when the list is still empty and
//! `dns_lookup_kdc` is on) DNS URI records when `dns_uri_lookup` is on, then DNS SRV
//! records. The built-in steps never authenticate a server: the reply keys do.

use hickory_resolver::TokioResolver;

use crate::{
    client::transport::{KdcEndpoint, KdcEndpointSource, KdcProtocol, Tokio, srv_targets},
    config::{Config, restrictions},
    discovery::{records, uri},
    error::{Client as Error, Config as ConfigError},
    extensions::{LocateRequest, LocateService, LocateTransport, Registry},
};

/// The kind of server to locate (MIT `locate_service_type`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum EndpointRole {
    /// Any KDC: `kdc`, `_kerberos`, port 88.
    Kdc,
    /// A primary KDC: `primary_kdc` (then `master_kdc`), URI records flagged `m`,
    /// `_kerberos-master`, port 88.
    PrimaryKdc,
    /// The administration server: `admin_server`, `_kerberos-adm`, port 749.
    Kadmin,
    /// The password-change server: `kpasswd_server`, `_kpasswd`, port 464.
    Kpasswd,
}

impl EndpointRole {
    /// The service label of this role's DNS URI records and, except for the
    /// primary KDC, of its SRV records.
    #[must_use]
    #[inline]
    pub const fn service(self) -> &'static str {
        match self {
            Self::Kdc | Self::PrimaryKdc => "_kerberos",
            Self::Kadmin => "_kerberos-adm",
            Self::Kpasswd => "_kpasswd",
        }
    }

    /// The service label of this role's SRV records (MIT `dns_locate_server_srv`,
    /// `locate_kdc.c:756-790`).
    #[must_use]
    #[inline]
    pub const fn srv_service(self) -> &'static str {
        match self {
            Self::PrimaryKdc => "_kerberos-master",
            Self::Kdc | Self::Kadmin | Self::Kpasswd => self.service(),
        }
    }

    /// The port of a server named without one.
    #[must_use]
    #[inline]
    pub const fn default_port(self) -> u16 {
        match self {
            Self::Kdc | Self::PrimaryKdc => 88,
            Self::Kadmin => 749,
            Self::Kpasswd => 464,
        }
    }

    /// The matching extension-interface service.
    const fn locate_service(self) -> LocateService {
        match self {
            Self::Kdc => LocateService::Kdc,
            Self::PrimaryKdc => LocateService::PrimaryKdc,
            Self::Kadmin => LocateService::Kadmin,
            Self::Kpasswd => LocateService::Kpasswd,
        }
    }
}

/// The site of `realm`, the `sitename` relation of its `[realms]` entry.
#[must_use]
#[inline]
pub fn sitename<'config>(config: &'config Config, realm: &str) -> Option<&'config str> {
    use crate::config::section_values::Value;
    match config.realm(realm)?.relations.get("sitename")? {
        Value::Text(name) | Value::Choice(name) => {
            Some(name.as_str()).filter(|text| !text.is_empty())
        }
        Value::List(names) => names
            .last()
            .map(String::as_str)
            .filter(|text| !text.is_empty()),
        Value::Boolean(_) | Value::Locations(_) => None,
    }
}

/// Locates the servers of a realm.
///
/// Built with [`Tokio::locator`]; it uses that transport's DNS server selection.
#[derive(Clone, Copy, Debug)]
pub struct ServerLocator<'config> {
    /// The transport whose DNS server is used.
    transport: Tokio,
    /// The profile.
    config: &'config Config,
}

impl<'config> ServerLocator<'config> {
    /// A locator over `config` that asks DNS through `transport`.
    pub(crate) const fn new(transport: Tokio, config: &'config Config) -> Self {
        Self { transport, config }
    }

    /// The servers of `role` for `realm`, in the order to try them.
    ///
    /// The locators registered in `registry` are asked first, as MIT asks its locator
    /// modules before the profile; `None` skips that step. An empty list means that no step knows a server. For
    /// [`EndpointRole::Kpasswd`] the profile and DNS steps are those of
    /// [`Tokio::discover_kpasswd_servers`].
    ///
    /// # Security
    ///
    /// DNS only says where to send the request; it authenticates nothing.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] for a refused configuration or an unknown
    /// realm that no step knows, [`Error::Locate`] for a registered locator
    /// that fails or answers malformed data, [`Error::InvalidKdcEndpoint`] for a
    /// malformed profile entry, and the DNS errors of [`Tokio::discover_kdcs`].
    ///
    /// # Cancel safety
    ///
    /// cancel-safe: it only reads `config`, the registry and DNS.
    #[inline]
    pub async fn locate(
        &self,
        registry: Option<&Registry>,
        realm: &str,
        role: EndpointRole,
        protocol: KdcProtocol,
    ) -> Result<Vec<KdcEndpoint>, Error> {
        restrictions::config(self.config)?;
        if realm.is_empty() {
            return Err(ConfigError::NoRealm(String::new()).into());
        }
        if let Some(found) = Self::provided(registry, realm, role, protocol)? {
            return Ok(found);
        }
        if role == EndpointRole::Kpasswd {
            return self
                .transport
                .discover_kpasswd_servers(self.config, realm, protocol)
                .await;
        }
        if let Some(found) = self.configured(realm, role, protocol)? {
            return Ok(found);
        }
        if self.config.libdefaults.dns_lookup_kdc.is_enabled() {
            return Box::pin(self.dns(realm, role, protocol)).await;
        }
        Ok(Vec::new())
    }

    /// The first registered locator's servers.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Locate`] for a locator that fails or answers malformed data.
    fn provided(
        registry: Option<&Registry>,
        realm: &str,
        role: EndpointRole,
        protocol: KdcProtocol,
    ) -> Result<Option<Vec<KdcEndpoint>>, Error> {
        let Some(providers) = registry else {
            return Ok(None);
        };
        let transports: &[(LocateTransport, KdcProtocol)] = match protocol {
            KdcProtocol::Udp => &[(LocateTransport::Udp, KdcProtocol::Udp)],
            KdcProtocol::Tcp => &[(LocateTransport::Tcp, KdcProtocol::Tcp)],
            KdcProtocol::Auto => &[
                (LocateTransport::Udp, KdcProtocol::Udp),
                (LocateTransport::Tcp, KdcProtocol::Tcp),
            ],
        };
        let mut found = Vec::new();
        for (transport, wire) in transports {
            let request = LocateRequest::new(realm, role.locate_service(), *transport);
            if let Some(addresses) = providers
                .locate(&request)
                .map_err(|source| Error::Locate(Box::new(source)))?
            {
                found.extend(addresses.into_iter().map(|address| KdcEndpoint {
                    protocol: *wire,
                    host: address.host,
                    port: address.port,
                    source: KdcEndpointSource::Provider,
                }));
            }
        }
        Ok((!found.is_empty()).then_some(found))
    }

    /// The profile's servers of `role`, `None` when the realm lists none.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKdcEndpoint`] for a malformed entry.
    fn configured(
        &self,
        realm: &str,
        role: EndpointRole,
        protocol: KdcProtocol,
    ) -> Result<Option<Vec<KdcEndpoint>>, Error> {
        let Some(entry) = self.config.realm(realm) else {
            return Ok(None);
        };
        let values = match role {
            EndpointRole::Kdc => &entry.kdc,
            EndpointRole::PrimaryKdc => &entry.primary_kdc,
            EndpointRole::Kadmin => &entry.admin_server,
            EndpointRole::Kpasswd => return Ok(None),
        };
        if values.is_empty() {
            return Ok(None);
        }
        values
            .iter()
            .map(|value| {
                KdcEndpoint::configured_with_default_port(protocol, value, role.default_port())
            })
            .collect::<Result<Vec<_>, _>>()
            .map(Some)
    }

    /// DNS URI records, then DNS SRV records.
    ///
    /// # Errors
    ///
    /// The DNS errors of [`Tokio::discover_kdcs`].
    ///
    /// # Cancel safety
    ///
    /// cancel-safe: DNS lookups change no state.
    async fn dns(
        &self,
        realm: &str,
        role: EndpointRole,
        protocol: KdcProtocol,
    ) -> Result<Vec<KdcEndpoint>, Error> {
        let found = uri_servers(&self.transport, self.config, realm, role, protocol).await?;
        if !found.is_empty() {
            return Ok(found);
        }
        let srv_protocol = if role == EndpointRole::Kadmin {
            KdcProtocol::Tcp
        } else {
            protocol
        };
        self.transport
            .discover_srv_endpoints(
                role.srv_service(),
                realm,
                srv_protocol,
                sitename(self.config, realm),
            )
            .await
    }
}

/// The servers of `role` that DNS URI records name, `[]` when `dns_uri_lookup` is off.
///
/// # Errors
///
/// Returns the DNS errors of the generic URI name and the errors of resolving
/// its targets.
///
/// # Cancel safety
///
/// cancel-safe: DNS lookups change no state.
pub(crate) async fn uri_servers(
    transport: &Tokio,
    config: &Config,
    realm: &str,
    role: EndpointRole,
    protocol: KdcProtocol,
) -> Result<Vec<KdcEndpoint>, Error> {
    if !config.libdefaults.dns_uri_lookup.is_enabled() {
        return Ok(Vec::new());
    }
    let resolver = records::dns_resolver(transport.dns_server())?;
    let found = records::uri_records(
        &resolver,
        (role.service(), sitename(config, realm), realm),
        protocol,
    )
    .await?;
    let targets = uri_targets(&found, role, protocol);
    resolve_uri_targets(
        &resolver,
        (realm, protocol),
        targets,
        transport.dns_server().is_some(),
    )
    .await
}

/// The endpoints a set of URI record targets names for `role`.
///
/// A record is skipped when its target does not parse (MIT `parse_uri_fields`),
/// when its transport is not the requested one (`Auto` accepts both datagrams and
/// streams), when it names MS-KKDCP (HTTPS is not a transport of this crate yet,
/// WP-10b) and, for [`EndpointRole::PrimaryKdc`], when it lacks the `m` flag.
/// Targets that are not literals are kept as names, or resolved by `resolve`.
fn uri_targets(
    records: &[(u16, Vec<u8>)],
    role: EndpointRole,
    protocol: KdcProtocol,
) -> Vec<(KdcProtocol, String, u16)> {
    records
        .iter()
        .filter_map(|(_, bytes)| uri::parse(bytes))
        .filter(|target| role != EndpointRole::PrimaryKdc || target.primary)
        .filter_map(|target| {
            let wire = match target.transport {
                uri::Transport::Udp => KdcProtocol::Udp,
                uri::Transport::Tcp => KdcProtocol::Tcp,
                uri::Transport::Kkdcp => return None,
            };
            if protocol != KdcProtocol::Auto && protocol != wire {
                return None;
            }
            let (host, port) = uri::host_port(&target.spec, role.default_port())?;
            Some((wire, host, port))
        })
        .collect()
}

/// Resolve the targets of URI records as SRV targets are resolved.
///
/// # Errors
///
/// Returns the error of [`srv_targets::resolve`].
///
/// # Cancel safety
///
/// cancel-safe: DNS lookups change no state.
async fn resolve_uri_targets(
    resolver: &TokioResolver,
    (realm, protocol): (&str, KdcProtocol),
    targets: Vec<(KdcProtocol, String, u16)>,
    resolve_names: bool,
) -> Result<Vec<KdcEndpoint>, Error> {
    let mut endpoints = Vec::new();
    let mut failures = Vec::new();
    for (wire, host, port) in targets {
        let set = srv_targets::resolve(
            resolver,
            realm,
            wire,
            vec![(0, 0, host, port)],
            resolve_names,
        )
        .await?;
        failures.extend(set.failures);
        endpoints.extend(set.endpoints.into_iter().map(|endpoint| KdcEndpoint {
            source: KdcEndpointSource::DnsUri,
            ..endpoint
        }));
    }
    srv_targets::Resolved {
        endpoints,
        failures,
    }
    .endpoints_or_failures(realm, protocol)
}
