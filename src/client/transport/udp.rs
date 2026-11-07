//! Bounded UDP socket primitives.

use std::io;

use tokio::net::{ToSocketAddrs, UdpSocket, lookup_host};

use super::Error;

/// Connect a datagram socket matching the selected address family.
///
/// # Errors
/// Returns resolution, bind or connection errors.
///
/// # Cancel safety
/// cancel-safe: dropping preparation closes sockets before any request is sent.
pub(super) async fn connect<A>(addr: A) -> Result<UdpSocket, Error>
where
    A: ToSocketAddrs,
{
    let mut last_error = io::Error::from(io::ErrorKind::AddrNotAvailable);
    let mut connected = None;
    for candidate in lookup_host(addr).await? {
        let wildcard = if candidate.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let attempt = async {
            let socket = UdpSocket::bind(wildcard).await?;
            socket.connect(candidate).await?;
            Ok::<_, io::Error>(socket)
        }
        .await;
        match attempt {
            Ok(socket) => {
                connected = Some(socket);
                break;
            }
            Err(error) => last_error = error,
        }
    }
    Ok(connected.ok_or(last_error)?)
}

/// Receive with one extra byte to detect datagrams exceeding the configured cap.
///
/// # Errors
/// Returns socket errors or `UdpResponseTooLarge` for an oversized datagram.
///
/// # Cancel safety
/// cancel-safe: Tokio recv leaves no partially consumed datagram on cancellation.
pub(super) async fn receive(socket: &UdpSocket, max: usize) -> Result<Vec<u8>, Error> {
    let capacity = max.min(usize::from(u16::MAX)).saturating_add(1);
    let mut response = vec![0; capacity];
    let length = socket
        .recv(&mut response)
        .await
        .map_err(|error| receive_error(error, max, cfg!(windows)))?;
    if length > max {
        return Err(Error::UdpResponseTooLarge { limit: max });
    }
    response.truncate(length);
    Ok(response)
}

/// Map Windows WSAEMSGSIZE without reclassifying unrelated platform errors.
fn receive_error(error: io::Error, max: usize, windows: bool) -> Error {
    if windows && error.raw_os_error() == Some(10_040) {
        Error::UdpResponseTooLarge { limit: max }
    } else {
        Error::Io(error)
    }
}

/// Platform receive-error classification.
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

    use tokio::{net::UdpSocket, time::timeout};

    use super::{Error, receive_error};
    use crate::client::transport::{KdcProtocol, Tokio};

    /// Both services enforce the common receive cap while preserving mutation uncertainty.
    async fn oversized(password: bool) -> Result<(), Box<dyn StdError>> {
        // Given a peer sending more bytes than the configured receive cap.
        let peer = UdpSocket::bind("127.0.0.1:0").await?;
        let addr = peer.local_addr()?;
        let transport = Tokio::new().with_udp_response_limit(4);
        let server = async {
            let mut request = [0; 32];
            let (_, client) = peer.recv_from(&mut request).await?;
            let _: usize = peer.send_to(&[42; 16], client).await?;
            Ok::<_, io::Error>(())
        };
        // When the service receives the oversized datagram.
        let client = async {
            if password {
                transport
                    .send_password_once(KdcProtocol::Udp, addr, &[1])
                    .await
            } else {
                transport.send_udp(addr, &[1]).await
            }
        };
        let (sent, outcome) = tokio::join!(server, client);
        sent?;
        // Then the shared size error remains definite only for the non-mutating service.
        match outcome {
            Err(Error::KpasswdOutcomeUnknown(source)) if password => {
                assert!(matches!(*source, Error::UdpResponseTooLarge { limit: 4 }));
            }
            Err(Error::UdpResponseTooLarge { limit: 4 }) if !password => {}
            other => return Err(format!("unexpected UDP outcome: {other:?}").into()),
        }
        Ok(())
    }

    /// KDC UDP rejects truncated responses through the common primitive.
    #[tokio::test]
    async fn common_bound_rejects_kdc_datagram() -> Result<(), Box<dyn StdError>> {
        oversized(false).await
    }

    /// Password UDP rejects truncated responses as uncertain outcomes.
    #[tokio::test]
    async fn common_bound_rejects_password_datagram() -> Result<(), Box<dyn StdError>> {
        oversized(true).await
    }

    /// Windows WSAEMSGSIZE must retain the advertised size-error taxonomy.
    #[test]
    fn windows_message_size_is_typed() {
        // Given an oversized Windows datagram, when mapped, then preserve the cap.
        assert!(matches!(
            receive_error(io::Error::from_raw_os_error(10_040), 16, true),
            Error::UdpResponseTooLarge { limit: 16 }
        ));
    }

    /// Only Windows maps WSAEMSGSIZE, and other Windows errors stay I/O errors.
    #[test]
    fn unrelated_receive_errors_preserve_io_kind() -> Result<(), Box<dyn StdError>> {
        for (code, windows) in [(10_040_i32, false), (10_061_i32, true)] {
            matches!(
                receive_error(io::Error::from_raw_os_error(code), 16, windows),
                Error::Io(error) if error.raw_os_error() == Some(code)
            )
            .ok_or("unrelated receive error must retain its I/O code")?;
        }
        Ok(())
    }

    /// Receiving a queued datagram returns its exact bytes rather than a placeholder.
    #[tokio::test]
    async fn receive_preserves_datagram_bytes() -> Result<(), Box<dyn StdError>> {
        let receiver = UdpSocket::bind("127.0.0.1:0").await?;
        let sender = UdpSocket::bind("127.0.0.1:0").await?;
        let _: usize = sender
            .send_to(&[42, 17, 99], receiver.local_addr()?)
            .await?;
        let payload = timeout(Duration::from_secs(1), super::receive(&receiver, 16)).await??;
        assert_eq!(payload, [42, 17, 99]);
        Ok(())
    }
}
