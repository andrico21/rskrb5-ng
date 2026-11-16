//! DNS password-service fallback.

use super::{Error, KdcEndpoint, KdcProtocol, Tokio, dns_resolver, srv_targets};

/// Discover password servers for one protocol, falling back to administrative service hosts.
///
/// The administrative hosts are asked for only when the `_kpasswd` set of
/// `protocol` is absent. A set whose SRV answer held a record counts as
/// published, and when none of its targets resolves the call fails without the
/// fallback, as [`discover_auto`] does for its sets.
///
/// # Errors
/// Returns [`Error::DnsServiceUnavailable`] for a root target and
/// [`Error::KdcEndpointFailures`] when the published set's targets all failed to
/// resolve. When the set is absent: DNS errors of the administrative lookup, or
/// [`Error::NoKdcEndpoints`] when no host is found.
///
/// # Cancel safety
/// cancel-safe: abandoning DNS lookups changes no credential state.
pub(super) async fn discover(
    transport: &Tokio,
    realm: &str,
    protocol: KdcProtocol,
) -> Result<Vec<KdcEndpoint>, Error> {
    let resolver = dns_resolver(transport.dns_server)?;
    if let Ok(answer) = transport
        .srv_answer(&resolver, "_kpasswd", realm, protocol)
        .await
    {
        if answer.root {
            return Err(Error::DnsServiceUnavailable {
                service: "_kpasswd".to_owned(),
                realm: realm.to_owned(),
            });
        }
        match srv_targets::resolve(
            &resolver,
            realm,
            protocol,
            answer.records,
            transport.dns_server.is_some(),
        )
        .await
        {
            Ok(endpoints) if !endpoints.is_empty() => return Ok(endpoints),
            Ok(_) => {}
            Err(error) => {
                return Err(Error::KdcEndpointFailures {
                    realm: realm.to_owned(),
                    protocol,
                    failures: vec![error.to_string()],
                });
            }
        }
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
/// `_kpasswd._udp` and `_kpasswd._tcp` are both queried and form one list whose
/// entries are tagged with their protocol. A root target contributes no entry
/// and the other records of its set are kept. A set whose SRV answer held any
/// record, decided before the targets are resolved, counts as published, and
/// `_kerberos-adm._tcp` is queried only when neither set was. Its hosts are
/// offered on port 464 over both protocols.
///
/// # Errors
/// Returns [`Error::KdcEndpointFailures`] with the failed target lookups of
/// every published set (the UDP set first) when no endpoint is left,
/// [`Error::DnsServiceUnavailable`] when only root targets were published, DNS
/// errors of the administrative lookup, or `NoKdcEndpoints` when no host is
/// found at all.
///
/// # Cancel safety
/// cancel-safe: abandoning DNS lookups changes no credential state.
pub(super) async fn discover_auto(
    transport: &Tokio,
    realm: &str,
) -> Result<Vec<KdcEndpoint>, Error> {
    let resolver = dns_resolver(transport.dns_server)?;
    let mut endpoints = Vec::new();
    let mut published = false;
    let mut unresolved = Vec::new();
    for protocol in [KdcProtocol::Udp, KdcProtocol::Tcp] {
        let Ok(answer) = transport
            .srv_answer(&resolver, "_kpasswd", realm, protocol)
            .await
        else {
            continue;
        };
        published |= answer.published;
        match srv_targets::resolve(
            &resolver,
            realm,
            protocol,
            answer.records,
            transport.dns_server.is_some(),
        )
        .await
        {
            Ok(found) => endpoints.extend(found),
            Err(error) => {
                unresolved.push(error.to_string());
            }
        }
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
        transport
            .discover_srv_endpoints("_kerberos-adm", realm, KdcProtocol::Tcp)
            .await?,
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
