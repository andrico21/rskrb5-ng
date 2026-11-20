//! Ordered SRV target address resolution.

use super::{
    Error, KdcEndpoint, KdcEndpointSource, KdcProtocol, TokioResolver, resolve_dns_endpoint_host,
};

/// One SRV answer before its targets are resolved.
pub(super) struct SrvAnswer {
    /// The answer held at least one record, a root one included.
    pub published: bool,
    /// A record named the root target, which stands for no service.
    pub root: bool,
    /// `(priority, weight, target, port)` of the non-root records in service order.
    pub records: Vec<(u16, u16, String, u16)>,
}

/// The endpoints of an SRV set and the targets that gave none.
pub(super) struct Resolved {
    /// Endpoints in service order.
    pub endpoints: Vec<KdcEndpoint>,
    /// One `target <name>: <reason>` entry for each target skipped because it
    /// has no address data.
    pub failures: Vec<String>,
}

impl Resolved {
    /// The endpoints, or the failure of a set none of whose targets resolved.
    ///
    /// A set without records is not a failure: it gives no endpoints and no
    /// error.
    ///
    /// # Errors
    /// Returns [`Error::KdcEndpointFailures`], one entry for the set, when no
    /// endpoint resulted and at least one target was skipped.
    pub(super) fn endpoints_or_failures(
        self,
        realm: &str,
        protocol: KdcProtocol,
    ) -> Result<Vec<KdcEndpoint>, Error> {
        if self.endpoints.is_empty() && !self.failures.is_empty() {
            return Err(Error::KdcEndpointFailures {
                realm: realm.to_owned(),
                protocol,
                failures: vec![self.failures.join("; ")],
            });
        }
        Ok(self.endpoints)
    }
}

/// Resolve selected SRV targets while preserving their service order.
///
/// Only with `resolve_targets` (an explicit DNS server); otherwise each target
/// name is kept as the endpoint host and is looked up when it is contacted. A
/// target without address data is skipped and reported in
/// [`Resolved::failures`].
///
/// # Errors
/// Returns the lookup error of a target whose lookup failed for another reason
/// than having no address data.
///
/// # Cancel safety
/// cancel-safe: DNS lookups change no credential state.
pub(super) async fn resolve(
    resolver: &TokioResolver,
    realm: &str,
    protocol: KdcProtocol,
    records: Vec<(u16, u16, String, u16)>,
    resolve_targets: bool,
) -> Result<Resolved, Error> {
    let mut endpoints = Vec::with_capacity(records.len());
    let mut failures = Vec::new();
    for (_, _, target, port) in records {
        let hosts = if resolve_targets {
            let hosts = resolve_dns_endpoint_host(resolver, realm, protocol, &target).await?;
            if hosts.is_empty() {
                failures.push(format!("target {target}: no address records found"));
                continue;
            }
            hosts
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
    Ok(Resolved {
        endpoints,
        failures,
    })
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
        let endpoints = resolve(&resolver, "TEST.GOKRB5", KdcProtocol::Tcp, vec![], false)
            .await?
            .endpoints_or_failures("TEST.GOKRB5", KdcProtocol::Tcp)?;
        assert!(
            endpoints.is_empty(),
            "empty answers must yield no endpoints"
        );
        Ok(())
    }
}
