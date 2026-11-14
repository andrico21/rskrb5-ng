//! DNS password-service fallback.

use super::{Error, KdcEndpoint, KdcProtocol, Tokio};

/// Discover password servers for one protocol, falling back to administrative service hosts.
///
/// # Errors
/// Returns DNS lookup, unavailable-service or empty-endpoint errors.
///
/// # Cancel safety
/// cancel-safe: abandoning DNS lookups changes no credential state.
pub(super) async fn discover(
    transport: &Tokio,
    realm: &str,
    protocol: KdcProtocol,
) -> Result<Vec<KdcEndpoint>, Error> {
    match transport
        .discover_srv_endpoints("_kpasswd", realm, protocol)
        .await
    {
        Ok(endpoints) if !endpoints.is_empty() => return Ok(endpoints),
        Err(
            error @ Error::DnsServiceUnavailable {
                service: _,
                realm: _,
            },
        ) => return Err(error),
        Ok(_) | Err(_) => {}
    }
    let mut endpoints = transport
        .discover_srv_endpoints("_kerberos-adm", realm, KdcProtocol::Tcp)
        .await?;
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
/// `_kpasswd._udp` and `_kpasswd._tcp` form one list whose entries are tagged
/// with their protocol. A root target in either record set stops discovery
/// without fallback. Only an empty list falls back to `_kerberos-adm._tcp`,
/// whose hosts are offered on port 464 over both protocols.
///
/// # Errors
/// Returns the root-target error, DNS errors of the administrative lookup, or
/// `NoKdcEndpoints` when no host is found at all.
///
/// # Cancel safety
/// cancel-safe: abandoning DNS lookups changes no credential state.
pub(super) async fn discover_auto(
    transport: &Tokio,
    realm: &str,
) -> Result<Vec<KdcEndpoint>, Error> {
    let mut endpoints = Vec::new();
    for protocol in [KdcProtocol::Udp, KdcProtocol::Tcp] {
        match transport
            .discover_srv_endpoints("_kpasswd", realm, protocol)
            .await
        {
            Ok(found) => endpoints.extend(found),
            Err(
                error @ Error::DnsServiceUnavailable {
                    service: _,
                    realm: _,
                },
            ) => return Err(error),
            Err(_) => {}
        }
    }
    if endpoints.is_empty() {
        endpoints = admin_entries(
            transport
                .discover_srv_endpoints("_kerberos-adm", realm, KdcProtocol::Tcp)
                .await?,
        );
    }
    if endpoints.is_empty() {
        Err(Error::NoKdcEndpoints {
            realm: realm.to_owned(),
            protocol: KdcProtocol::Auto,
        })
    } else {
        Ok(endpoints)
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
