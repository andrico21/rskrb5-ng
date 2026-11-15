//! A loopback TCP listener and a UDP socket on one port number.
//!
//! A free TCP port number can already be taken for UDP, or excluded for it (Windows reports an
//! excluded port as `PermissionDenied`), so a collision retries with a fresh TCP port.

use std::io;

use tokio::net::{TcpListener, UdpSocket};

/// Attempts of [`bind_tcp_and_udp_pair`] before it gives up.
const ATTEMPTS: u8 = 32;

/// Bind a TCP listener on a free loopback port and a UDP socket on the same port number.
///
/// # Errors
/// Returns the error of a bind that is not a collision, and `AddrInUse` when every attempt
/// collided.
///
/// # Cancel safety
/// cancel-safe: dropping the future drops the sockets bound so far.
pub(crate) async fn bind_tcp_and_udp_pair() -> io::Result<(TcpListener, UdpSocket)> {
    bind_pair_with(ATTEMPTS, async || TcpListener::bind("127.0.0.1:0").await).await
}

/// Pair each listener of `next_listener` with a UDP socket on its port, for at most `attempts`
/// listeners, retrying only when the UDP bind collides.
///
/// # Errors
/// Returns the error of `next_listener` and of a UDP bind that is not a collision, and
/// `AddrInUse` naming the last collision when every attempt collided.
///
/// # Cancel safety
/// cancel-safe: dropping the future drops the sockets bound so far.
pub(crate) async fn bind_pair_with(
    attempts: u8,
    mut next_listener: impl AsyncFnMut() -> io::Result<TcpListener>,
) -> io::Result<(TcpListener, UdpSocket)> {
    let mut last = String::from("no attempt was allowed");
    for _ in 0..attempts {
        let listener = next_listener().await?;
        match UdpSocket::bind(listener.local_addr()?).await {
            Ok(udp) => return Ok((listener, udp)),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::AddrInUse | io::ErrorKind::PermissionDenied
                ) =>
            {
                last = error.to_string();
            }
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AddrInUse,
        format!("no loopback TCP and UDP port pair in {attempts} attempts; last UDP bind: {last}"),
    ))
}
