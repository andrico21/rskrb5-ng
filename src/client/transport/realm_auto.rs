//! Configured realm protocol preference.

use tokio::net::TcpStream;

use super::{
    Config, Error, KRB_ERR_RESPONSE_TOO_BIG, KdcProtocol, Tokio, auto_uses_udp_first,
    kdc_error_code,
};

/// Try configured transports in their preferred order.
///
/// # Errors
/// Returns the final discovery or exchange error.
///
/// # Cancel safety
/// cancel-safe: requests change no local state and sockets close on cancellation.
pub(super) async fn send(
    transport: &Tokio,
    config: &Config,
    realm: &str,
    request: &[u8],
) -> Result<(Vec<u8>, Option<TcpStream>), Error> {
    let udp_first = auto_uses_udp_first(config, request.len());
    let (first, second) = if udp_first {
        (KdcProtocol::Udp, KdcProtocol::Tcp)
    } else {
        (KdcProtocol::Tcp, KdcProtocol::Udp)
    };
    match send_explicit(transport, (config, realm, first), request).await {
        Ok((response, _))
            if first == KdcProtocol::Udp
                && kdc_error_code(&response) == Some(KRB_ERR_RESPONSE_TOO_BIG) =>
        {
            send_explicit(transport, (config, realm, second), request).await
        }
        Ok(response) => Ok(response),
        Err(_) => send_explicit(transport, (config, realm, second), request).await,
    }
}

/// Discover one protocol's endpoints and keep its winning TCP stream.
///
/// # Errors
/// Returns discovery or exchange errors.
///
/// # Cancel safety
/// cancel-safe: cancellation discards sockets without changing client state.
async fn send_explicit(
    transport: &Tokio,
    destination: (&Config, &str, KdcProtocol),
    request: &[u8],
) -> Result<(Vec<u8>, Option<TcpStream>), Error> {
    let (config, realm, protocol) = destination;
    if protocol == KdcProtocol::Udp {
        return transport
            .send_to_realm_explicit(config, protocol, realm, request)
            .await
            .map(|response| (response, None));
    }
    let endpoints = transport.discover_kdcs(config, realm, protocol).await?;
    transport
        .send_to_endpoints_pinned(realm, protocol, endpoints, request)
        .await
}

/// Configured Auto stream retention.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::{error::Error as StdError, time::Duration};
    use std::io;

    use tokio::{
        io::{AsyncReadExt as _, AsyncWriteExt as _},
        net::TcpListener,
        time::timeout,
    };

    use super::{Config, KdcProtocol, Tokio};

    /// Configured TCP-first Auto preserves the winning stream for preauthentication.
    #[tokio::test]
    async fn configured_auto_retains_tcp_stream() -> Result<(), Box<dyn StdError>> {
        // Given a configured TCP-first peer that answers on an open stream.
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let config = Config::parse(&format!(
            "[libdefaults]\ndns_lookup_kdc = false\nudp_preference_limit = 1\n[realms]\nTEST.GOKRB5 = {{\nkdc = {addr}\n}}\n"
        ))?;
        let transport = Tokio::new();
        let server = async {
            let (mut stream, _) = listener.accept().await?;
            let mut request = [0; 5];
            let _: usize = stream.read_exact(&mut request).await?;
            stream.write_all(&[0, 0, 0, 1, 42]).await?;
            Ok::<_, io::Error>(stream)
        };
        // When the shared configured login dispatch completes.
        let (peer, outcome) = tokio::join!(
            // A client that never connects or never sends fails here instead of hanging the suite.
            timeout(Duration::from_secs(10), server),
            transport.send_to_realm_pinned(&config, KdcProtocol::Auto, "TEST.GOKRB5", &[1])
        );
        let connection = peer??;
        let (response, stream) = outcome?;
        // Then the caller receives the original connected stream, not only its bytes.
        assert_eq!(response, [42]);
        assert!(
            stream.is_some(),
            "configured Auto discarded its TCP conversation"
        );
        drop(connection);
        Ok(())
    }
}
