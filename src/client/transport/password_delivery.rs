//! Single-delivery password mutation transport.

use core::net::SocketAddr;
use std::io;

use tokio::net::{ToSocketAddrs, lookup_host};

use super::{
    Error, KdcEndpoint, KdcProtocol, MAX_UDP_DATAGRAM, TcpFraming, Tokio, non_empty_kdc_response,
    tcp_request_length, udp,
};

/// Try password endpoints only while delivery is definitely unattempted.
///
/// # Errors
/// Returns endpoint failures or the first uncertain mutation outcome.
///
/// # Cancel safety
/// NOT cancel-safe: a delivered password request may already have committed.
pub(super) async fn send_to_endpoints(
    transport: &Tokio,
    realm: &str,
    protocol: KdcProtocol,
    endpoints: Vec<KdcEndpoint>,
    request: &[u8],
) -> Result<Vec<u8>, Error> {
    let mut failures = Vec::new();
    for endpoint in endpoints {
        let result = transport
            .send_password_once(
                endpoint.protocol,
                (endpoint.host.as_str(), endpoint.port),
                request,
            )
            .await;
        match result {
            Ok(response) => return Ok(response),
            Err(error @ Error::KpasswdOutcomeUnknown(_)) => return Err(error),
            Err(error) => failures.push(format!("{}: {error}", endpoint.authority())),
        }
    }
    Err(Error::KdcEndpointFailures {
        realm: realm.to_owned(),
        protocol,
        failures,
    })
}

/// Send one password mutation with separate preparation and delivery budgets.
///
/// Each phase gets the full configured timeout, allowing twice that duration
/// in total. Preparation failure is definite; send/reply expiry is unknown.
/// [`KdcProtocol::Auto`] tries TCP, then UDP only after a definite TCP failure.
///
/// # Errors
/// Returns preparation errors before a send, or `KpasswdOutcomeUnknown` afterward.
///
/// # Cancel safety
/// NOT cancel-safe: a cancelled send or reply wait may already have committed.
pub(super) async fn send<A>(
    transport: &Tokio,
    protocol: KdcProtocol,
    addr: A,
    request: &[u8],
) -> Result<Vec<u8>, Error>
where
    A: ToSocketAddrs,
{
    match protocol {
        KdcProtocol::Tcp => send_tcp(transport, addr, request).await,
        KdcProtocol::Udp => send_udp(transport, addr, request).await,
        KdcProtocol::Auto => {
            let addrs: Vec<SocketAddr> = transport
                .with_transport_timeout(async {
                    Ok::<_, Error>(lookup_host(addr).await?.collect())
                })
                .await?;
            match send_tcp(transport, addrs.as_slice(), request).await {
                Ok(response) => Ok(response),
                Err(error @ Error::KpasswdOutcomeUnknown(_)) => Err(error),
                Err(_) => send_udp(transport, addrs.as_slice(), request).await,
            }
        }
    }
}

/// Send one password request over TCP.
///
/// # Errors
/// Returns preparation errors before a send, or `KpasswdOutcomeUnknown` afterward.
///
/// # Cancel safety
/// NOT cancel-safe: a cancelled send or reply wait may already have committed.
async fn send_tcp<A>(transport: &Tokio, addr: A, request: &[u8]) -> Result<Vec<u8>, Error>
where
    A: ToSocketAddrs,
{
    let _length = tcp_request_length(request.len(), TcpFraming::Kpasswd)?;
    let mut stream = transport
        .with_transport_timeout(Tokio::connect_tcp(addr))
        .await?;
    transport
        .with_transport_timeout(transport.exchange_tcp_framed(
            &mut stream,
            request,
            TcpFraming::Kpasswd,
        ))
        .await
        .map_err(|error| Error::KpasswdOutcomeUnknown(Box::new(error)))
}

/// Send one password request as a single UDP datagram.
///
/// A refusal while waiting for the reply (`ConnectionRefused`, or
/// `ConnectionReset` where Windows reports an ICMP port-unreachable that way)
/// is a plain endpoint failure; every other failure after the send is unknown.
///
/// # Errors
/// Returns preparation errors and refusals plainly, `KpasswdOutcomeUnknown` otherwise.
///
/// # Cancel safety
/// NOT cancel-safe: a cancelled send or reply wait may already have committed.
async fn send_udp<A>(transport: &Tokio, addr: A, request: &[u8]) -> Result<Vec<u8>, Error>
where
    A: ToSocketAddrs,
{
    if request.len() > MAX_UDP_DATAGRAM {
        return Err(Error::UdpRequestTooLarge {
            actual: request.len(),
            limit: MAX_UDP_DATAGRAM,
        });
    }
    let socket = transport.with_transport_timeout(udp::connect(addr)).await?;
    let reply = transport
        .with_transport_timeout(async {
            let _: usize = socket.send(request).await?;
            Ok::<_, Error>(udp::receive(&socket, transport.udp_response_limit).await)
        })
        .await
        .map_err(|error| Error::KpasswdOutcomeUnknown(Box::new(error)))?;
    match reply {
        Err(error) if is_udp_refusal(&error) => Err(error),
        other => other
            .and_then(non_empty_kdc_response)
            .map_err(|error| Error::KpasswdOutcomeUnknown(Box::new(error))),
    }
}

/// Whether a failed UDP reply wait is a definite refusal of the datagram.
///
/// Only an I/O error of kind `ConnectionRefused` or `ConnectionReset` proves
/// that the request was not accepted; every other failure after the datagram
/// was sent leaves the outcome unknown.
fn is_udp_refusal(error: &Error) -> bool {
    matches!(
        error,
        Error::Io(io_error)
            if matches!(
                io_error.kind(),
                io::ErrorKind::ConnectionRefused | io::ErrorKind::ConnectionReset
            )
    )
}

/// Endpoint attribution before any request can be delivered.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::error::Error as StdError;

    use tokio::net::TcpListener;

    use super::{Error, KdcEndpoint, KdcProtocol, Tokio, send_to_endpoints};

    /// Every pre-delivery failure identifies the endpoint that failed.
    #[tokio::test]
    async fn password_failures_name_each_endpoint() -> Result<(), Box<dyn StdError>> {
        // Given two distinct closed loopback endpoints.
        let first = TcpListener::bind("127.0.0.1:0").await?;
        let second = TcpListener::bind("127.0.0.1:0").await?;
        let addresses = [
            first.local_addr()?.to_string(),
            second.local_addr()?.to_string(),
        ];
        drop(first);
        drop(second);
        let endpoints = addresses
            .iter()
            .map(|address| KdcEndpoint::configured(KdcProtocol::Tcp, address))
            .collect::<Result<Vec<_>, _>>()?;
        // When failover exhausts both without sending a mutation.
        let outcome = send_to_endpoints(
            &Tokio::new(),
            "TEST.GOKRB5",
            KdcProtocol::Tcp,
            endpoints,
            b"request",
        )
        .await;
        // Then each diagnostic is attributed to its original authority.
        match outcome {
            Err(Error::KdcEndpointFailures {
                realm: _,
                protocol: _,
                failures,
            }) => {
                assert_eq!(failures.len(), 2);
                for (failure, address) in failures.iter().zip(addresses) {
                    assert!(
                        failure.starts_with(&format!("{address}: ")),
                        "missing endpoint attribution"
                    );
                }
            }
            other => return Err(format!("unexpected outcome: {other:?}").into()),
        }
        Ok(())
    }
}
