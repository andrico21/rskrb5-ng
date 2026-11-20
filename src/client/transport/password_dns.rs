//! DNS password-service fallback.

use super::{Config, Error, KdcEndpoint, KdcProtocol, Tokio, dns_resolver, srv_targets};
use crate::discovery::locate::{EndpointRole, sitename, uri_servers};

/// Discover password servers for one protocol, falling back to administrative service hosts.
///
/// The administrative hosts are asked for only when the `_kpasswd` set of
/// `protocol` is absent. A set whose SRV answer held a record counts as
/// published, and when, with an explicit DNS server, none of its targets
/// resolves the call fails without the fallback, as [`discover_auto`] does for
/// its sets; the system resolver keeps the target names as endpoints. A root
/// target drops only itself from a set that also holds real records; it alone
/// is "service unavailable". Only NXDOMAIN and an empty NOERROR answer mean
/// absent: any other failure of the `_kpasswd` lookup is the error of the call.
///
/// # Errors
/// Returns [`Error::DnsResolverConfig`] when the resolver cannot be built,
/// [`Error::DnsServiceUnavailable`] for a lone root target,
/// [`Error::DnsSrvLookup`] when the `_kpasswd` lookup fails other than by absence
/// and [`Error::KdcEndpointFailures`] when, with an explicit DNS server, the
/// published set's targets all failed to resolve. When the set is absent: DNS
/// errors of the administrative lookup (whose `protocol` is the `_tcp` label it
/// queried; an absent administrative set is such an error too), or
/// [`Error::NoKdcEndpoints`] when no host is found.
///
/// # Cancel safety
/// cancel-safe: abandoning DNS lookups changes no credential state.
pub(super) async fn discover(
    transport: &Tokio,
    config: &Config,
    realm: &str,
    protocol: KdcProtocol,
) -> Result<Vec<KdcEndpoint>, Error> {
    let found = uri_servers(transport, config, realm, EndpointRole::Kpasswd, protocol).await?;
    if !found.is_empty() {
        return Ok(found);
    }
    let resolver = dns_resolver(transport.dns_server)?;
    let site = sitename(config, realm);
    if let Some(answer) = transport
        .srv_answer(&resolver, ("_kpasswd", site), realm, protocol)
        .await?
    {
        if answer.root && answer.records.is_empty() {
            return Err(Error::DnsServiceUnavailable {
                service: "_kpasswd".to_owned(),
                realm: realm.to_owned(),
            });
        }
        let endpoints = srv_targets::resolve(
            &resolver,
            realm,
            protocol,
            answer.records,
            transport.dns_server.is_some(),
        )
        .await?
        .endpoints_or_failures(realm, protocol)?;
        if !endpoints.is_empty() {
            return Ok(endpoints);
        }
    }
    let mut endpoints = admin_hosts(transport, config, realm)
        .await
        .map_err(|error| requested(error, protocol))?;
    for endpoint in &mut endpoints {
        endpoint.port = 464;
        endpoint.protocol = protocol;
    }
    if endpoints.is_empty() {
        Err(Error::NoKdcEndpoints {
            realm: realm.to_owned(),
            protocol,
        })
    } else {
        Ok(endpoints)
    }
}

/// Discover the password servers of [`KdcProtocol::Auto`] once, as MIT's `changepw.c` does.
///
/// `_kpasswd._udp` and `_kpasswd._tcp` are both queried and form one list whose
/// entries are tagged with their protocol. A root target contributes no entry
/// and the other records of its set are kept. A set whose SRV answer held any
/// record, decided before the targets are resolved, counts as published, and
/// `_kerberos-adm._tcp` is queried only when neither set was. Its hosts are
/// offered on port 464 over both protocols. Only NXDOMAIN and an empty NOERROR
/// answer mean an absent set; any other failure of a `_kpasswd` lookup is the
/// error of the call.
///
/// # Errors
/// Returns [`Error::DnsResolverConfig`] when the resolver cannot be built,
/// [`Error::DnsSrvLookup`] when a `_kpasswd` lookup fails other than by absence,
/// [`Error::KdcEndpointFailures`] with one entry per published set none
/// of whose targets resolved (the UDP set first; with an explicit DNS server
/// only, the system resolver keeps target names) when no endpoint is left and
/// there is such a set,
/// [`Error::DnsServiceUnavailable`] when only root targets were published, DNS
/// errors of the administrative lookup, or `NoKdcEndpoints` when no host is
/// found at all.
///
/// # Cancel safety
/// cancel-safe: abandoning DNS lookups changes no credential state.
pub(super) async fn discover_auto(
    transport: &Tokio,
    config: &Config,
    realm: &str,
) -> Result<Vec<KdcEndpoint>, Error> {
    let found = uri_servers(
        transport,
        config,
        realm,
        EndpointRole::Kpasswd,
        KdcProtocol::Auto,
    )
    .await?;
    if !found.is_empty() {
        return Ok(found);
    }
    let resolver = dns_resolver(transport.dns_server)?;
    let site = sitename(config, realm);
    let mut endpoints = Vec::new();
    let mut published = false;
    let mut unresolved = Vec::new();
    for protocol in [KdcProtocol::Udp, KdcProtocol::Tcp] {
        let Some(answer) = transport
            .srv_answer(&resolver, ("_kpasswd", site), realm, protocol)
            .await?
        else {
            continue;
        };
        published |= answer.published;
        let set = srv_targets::resolve(
            &resolver,
            realm,
            protocol,
            answer.records,
            transport.dns_server.is_some(),
        )
        .await?;
        if set.endpoints.is_empty() && !set.failures.is_empty() {
            unresolved.push(set.failures.join("; "));
        }
        endpoints.extend(set.endpoints);
    }
    if !endpoints.is_empty() {
        return Ok(endpoints);
    }
    if !unresolved.is_empty() {
        return Err(Error::KdcEndpointFailures {
            realm: realm.to_owned(),
            protocol: KdcProtocol::Auto,
            failures: unresolved,
        });
    }
    if published {
        return Err(Error::DnsServiceUnavailable {
            service: "_kpasswd".to_owned(),
            realm: realm.to_owned(),
        });
    }
    let admin = admin_entries(
        admin_hosts(transport, config, realm)
            .await
            .map_err(|error| requested(error, KdcProtocol::Auto))?,
    );
    if admin.is_empty() {
        Err(Error::NoKdcEndpoints {
            realm: realm.to_owned(),
            protocol: KdcProtocol::Auto,
        })
    } else {
        Ok(admin)
    }
}

/// The administrative hosts of `realm`: DNS URI records of `_kerberos-adm`, then its
/// `_kerberos-adm._tcp` SRV records (MIT `locate_server` for `locate_service_kadmin`).
///
/// # Errors
/// The errors of the URI step and of [`Tokio::discover_srv_endpoints`].
///
/// # Cancel safety
/// cancel-safe: abandoning DNS lookups changes no credential state.
async fn admin_hosts(
    transport: &Tokio,
    config: &Config,
    realm: &str,
) -> Result<Vec<KdcEndpoint>, Error> {
    let found = uri_servers(
        transport,
        config,
        realm,
        EndpointRole::Kadmin,
        KdcProtocol::Tcp,
    )
    .await?;
    if !found.is_empty() {
        return Ok(found);
    }
    transport
        .discover_srv_endpoints(
            "_kerberos-adm",
            realm,
            KdcProtocol::Tcp,
            sitename(config, realm),
        )
        .await
}

/// The error of the `_kerberos-adm._tcp` lookup, as the call reports it.
///
/// A failure of the lookup itself ([`Error::DnsSrvLookup`]) keeps the `_tcp` label
/// it queried as its protocol, which is how that error defines the field. The
/// failure of a set whose targets did not resolve is an endpoint failure and
/// reports the protocol the caller asked for.
fn requested(error: Error, protocol: KdcProtocol) -> Error {
    if let Error::KdcEndpointFailures {
        realm,
        protocol: _,
        failures,
    } = error
    {
        Error::KdcEndpointFailures {
            realm,
            protocol,
            failures,
        }
    } else {
        error
    }
}

/// Offer each administrative host on the kpasswd port over TCP and over UDP.
fn admin_entries(hosts: Vec<KdcEndpoint>) -> Vec<KdcEndpoint> {
    hosts
        .into_iter()
        .flat_map(|host| {
            [KdcProtocol::Tcp, KdcProtocol::Udp].map(|protocol| KdcEndpoint {
                protocol,
                port: 464,
                ..host.clone()
            })
        })
        .collect()
}

/// Administrative-host expansion.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use super::{KdcEndpoint, KdcProtocol, admin_entries};
    use crate::client::transport::KdcEndpointSource;

    /// An administrative host becomes one TCP and one UDP entry at port 464.
    #[test]
    fn admin_hosts_are_offered_on_both_transports_at_the_kpasswd_port() -> Result<(), &'static str>
    {
        // Given an administrative host found on its own port.
        let host = KdcEndpoint {
            protocol: KdcProtocol::Tcp,
            host: "admin.test.gokrb5".to_owned(),
            port: 749,
            source: KdcEndpointSource::DnsSrv,
        };
        // When it is expanded for the password passes.
        let entries = admin_entries(vec![host.clone()]);
        // Then both transports use the kpasswd port and the rest of the entry is kept.
        let [tcp, udp] = entries.as_slice() else {
            return Err("one entry per transport");
        };
        assert_eq!(
            tcp,
            &KdcEndpoint {
                protocol: KdcProtocol::Tcp,
                port: 464,
                ..host.clone()
            }
        );
        assert_eq!(
            udp,
            &KdcEndpoint {
                protocol: KdcProtocol::Udp,
                port: 464,
                ..host
            }
        );
        Ok(())
    }
}
