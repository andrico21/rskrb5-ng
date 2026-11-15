//! A loopback TCP listener and a UDP socket on one port number.
//!
//! A free TCP port number can already be taken for UDP, or refused for it (Windows reports an
//! excluded or reserved port as `PermissionDenied`). The Windows TCP allocator hands out port
//! numbers one after the other, so a block of numbers that UDP refuses is walked through in
//! order. This helper therefore chooses its own candidates, spread over the dynamic port range,
//! and alternates the bind order.

use core::{
    net::{Ipv4Addr, SocketAddr},
    sync::atomic::{AtomicU64, Ordering},
};
use std::{io, process};

use tokio::net::{TcpListener, UdpSocket};

/// Attempts of [`bind_tcp_and_udp_pair`] before it gives up.
const ATTEMPTS: u8 = 64;

/// First port number of the IANA dynamic range that candidates are drawn from.
pub(crate) const FIRST_PORT: u16 = 49_152;

/// Mask that keeps an offset inside the dynamic range (`49152..=65535` is 16384 numbers).
pub(crate) const PORT_MASK: u64 = 0x3FFF;

/// Which socket of a pair is bound first.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Order {
    /// The TCP listener first, the UDP socket second.
    TcpFirst,
    /// The UDP socket first, the TCP listener second.
    UdpFirst,
}

impl Order {
    /// The name used in the failure message.
    const fn name(self) -> &'static str {
        match self {
            Self::TcpFirst => "tcp-first",
            Self::UdpFirst => "udp-first",
        }
    }
}

/// Bind a TCP listener and a UDP socket on one free loopback port number.
///
/// # Errors
/// Returns the error of a bind that is not a collision, and `AddrInUse` listing every attempt
/// (port, order, error kind and OS code) when every attempt collided.
///
/// # Cancel safety
/// cancel-safe: dropping the future drops the sockets bound so far.
pub(crate) async fn bind_tcp_and_udp_pair() -> io::Result<(TcpListener, UdpSocket)> {
    static CALLS: AtomicU64 = AtomicU64::new(0);
    // The process id keeps concurrent test processes apart, the counter concurrent calls.
    let seed = (u64::from(process::id()) << 32_u32) ^ CALLS.fetch_add(1, Ordering::Relaxed);
    bind_pair_with(ATTEMPTS, seed, bind_on).await
}

/// Bind both sockets on `port` of the loopback address in the given order.
///
/// # Errors
/// Returns the error of the first bind that fails.
///
/// # Cancel safety
/// cancel-safe: dropping the future drops the socket bound so far.
pub(crate) async fn bind_on(port: u16, order: Order) -> io::Result<(TcpListener, UdpSocket)> {
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    match order {
        Order::TcpFirst => {
            let listener = TcpListener::bind(addr).await?;
            let udp = UdpSocket::bind(addr).await?;
            Ok((listener, udp))
        }
        Order::UdpFirst => {
            let udp = UdpSocket::bind(addr).await?;
            let listener = TcpListener::bind(addr).await?;
            Ok((listener, udp))
        }
    }
}

/// Draw candidate port numbers from `seed` and hand each to `bind`, alternating the order, for at
/// most `attempts` tries; retry only when the bind collides.
///
/// # Errors
/// Returns the error of a bind that is not a collision (`AddrInUse` or `PermissionDenied`), and
/// `AddrInUse` listing every attempt when every attempt collided.
///
/// # Cancel safety
/// cancel-safe: dropping the future drops the sockets bound so far.
pub(crate) async fn bind_pair_with(
    attempts: u8,
    seed: u64,
    mut bind: impl AsyncFnMut(u16, Order) -> io::Result<(TcpListener, UdpSocket)>,
) -> io::Result<(TcpListener, UdpSocket)> {
    let mut state = seed;
    let mut tried = Vec::new();
    for attempt in 0..attempts {
        let port =
            FIRST_PORT.saturating_add(u16::try_from(next(&mut state) & PORT_MASK).unwrap_or(0));
        let order = if attempt & 1_u8 == 0_u8 {
            Order::TcpFirst
        } else {
            Order::UdpFirst
        };
        match bind(port, order).await {
            Ok(pair) => return Ok(pair),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::AddrInUse | io::ErrorKind::PermissionDenied
                ) =>
            {
                let code = error
                    .raw_os_error()
                    .map_or_else(String::new, |code| format!("({code})"));
                tried.push(format!("{port} {} {:?}{code}", order.name(), error.kind()));
            }
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AddrInUse,
        format!(
            "no loopback TCP and UDP port pair in {attempts} attempts: {}",
            tried.join("; ")
        ),
    ))
}

/// The next value of the `SplitMix64` sequence that starts at `state`.
const fn next(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}
