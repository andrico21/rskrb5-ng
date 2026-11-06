//! Ordered SRV target address resolution.

use super::{
    Error, KdcEndpoint, KdcEndpointSource, KdcProtocol, TokioResolver, resolve_dns_endpoint_host,
};

/// Resolve selected SRV targets while preserving their service order.
///
/// # Errors
/// Returns target address lookup errors.
///
/// # Cancel safety
/// cancel-safe: DNS lookups change no credential state.
pub(super) async fn resolve(
    resolver: &TokioResolver,
    realm: &str,
    protocol: KdcProtocol,
    records: Vec<(u16, u16, String, u16)>,
    resolve_targets: bool,
) -> Result<Vec<KdcEndpoint>, Error> {
    let mut endpoints = Vec::with_capacity(records.len());
    let mut failures = Vec::new();
    for (_, _, target, port) in records {
        let hosts = if resolve_targets {
            match resolve_dns_endpoint_host(resolver, realm, protocol, &target).await {
                Ok(hosts) => hosts,
                Err(error) => {
                    failures.push(error.to_string());
                    continue;
                }
            }
        } else {
            vec![target]
        };
        endpoints.extend(hosts.into_iter().map(|host| KdcEndpoint {
            protocol,
            host,
            port,
            source: KdcEndpointSource::DnsSrv,
        }));
    }
    if endpoints.is_empty() && !failures.is_empty() {
        return Err(Error::DnsSrvLookup {
            realm: realm.to_owned(),
            protocol,
            message: failures.join("; "),
        });
    }
    Ok(endpoints)
}

/// Empty successful SRV lookup handling.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use super::{Error, KdcProtocol, resolve};
    use crate::client::transport::dns_resolver;

    /// No SRV answers means no endpoints, not a target resolution failure.
    #[tokio::test]
    async fn empty_srv_answers_preserve_empty_success() -> Result<(), Error> {
        let resolver = dns_resolver(None)?;
        let endpoints = resolve(&resolver, "TEST.GOKRB5", KdcProtocol::Tcp, vec![], false).await?;
        assert!(
            endpoints.is_empty(),
            "empty answers must yield no endpoints"
        );
        Ok(())
    }
}
