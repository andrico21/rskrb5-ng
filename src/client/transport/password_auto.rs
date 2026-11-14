//! MIT-shaped password transport for [`KdcProtocol::Auto`]: one discovery, a TCP pass, then a UDP pass.

use super::{Config, Error, KdcProtocol, Tokio, password_discovery};

/// Discover once, try every TCP endpoint, then every UDP endpoint.
///
/// UDP is tried only after the TCP pass failed definitely. A TCP failure that
/// may have followed delivery ends the exchange. When the discovered list has
/// no UDP entry the TCP pass's failures are returned.
///
/// # Errors
/// Returns discovery errors, the uncertain TCP outcome, or the endpoint
/// failures of the last pass that ran.
///
/// # Cancel safety
/// NOT cancel-safe: a delivered password request may already have committed.
pub(super) async fn send(
    transport: &Tokio,
    config: &Config,
    realm: &str,
    request: &[u8],
) -> Result<Vec<u8>, Error> {
    let endpoints = password_discovery::discover_auto(transport, config, realm).await?;
    let (tcp, udp): (Vec<_>, Vec<_>) = endpoints
        .into_iter()
        .partition(|endpoint| endpoint.protocol == KdcProtocol::Tcp);
    if !tcp.is_empty() {
        match transport
            .send_to_password_endpoints(realm, KdcProtocol::Tcp, tcp, request)
            .await
        {
            Ok(response) => return Ok(response),
            Err(error @ Error::KpasswdOutcomeUnknown(_)) => return Err(error),
            Err(error) if udp.is_empty() => return Err(error),
            Err(_) => {}
        }
    }
    transport
        .send_to_password_endpoints(realm, KdcProtocol::Udp, udp, request)
        .await
}
