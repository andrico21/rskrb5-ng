//! A loopback TCP listener and a UDP socket on one port number.
//!
//! A free TCP port number can already be taken for UDP, or refused for it (Windows reports an
//! excluded or reserved port as `PermissionDenied`). The Windows TCP allocator hands out port
//! numbers one after the other, so a block of numbers that UDP refuses is walked through in
//! order. This helper therefore chooses its own candidates, spread over the dynamic port range,
//! and alternates the bind order.
//!
//! A number that a test needs refused is a different case: a number that was bound and freed
//! again can be drawn by a test that runs in parallel and then answers. That number comes from a
//! reserved range that nothing else draws from.
//!
//! The DNS resolver binds its client sockets to random wildcard ports, and Windows lets such a
//! bind share the number of a socket bound to one address: a UDP socket that a test holds must
//! also keep a wildcard socket on its number. An IPv6 socket keeps an IPv6 wildcard socket
//! (`bind_udp_loopback_v6`).

use core::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::atomic::{AtomicU64, Ordering},
};
use std::{
    io,
    net::UdpSocket as StdUdpSocket,
    process,
    sync::{Mutex, PoisonError},
};

use tokio::net::{TcpListener, UdpSocket};

use crate::closed_port::next_reserved_port;

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
    bind_tcp_and_udp_pair_with(bind_on).await
}

/// The search of [`bind_tcp_and_udp_pair`] with its attempts, candidates and seed, and `bind` in
/// place of [`bind_on`], so that a test observes how many attempts the public helper makes.
///
/// # Errors
/// As [`bind_tcp_and_udp_pair`].
///
/// # Cancel safety
/// cancel-safe when `bind` is: dropping the future drops the sockets bound so far.
pub(crate) async fn bind_tcp_and_udp_pair_with(
    bind: impl AsyncFnMut(u16, Order) -> io::Result<(TcpListener, UdpSocket)>,
) -> io::Result<(TcpListener, UdpSocket)> {
    static CALLS: AtomicU64 = AtomicU64::new(0);
    // The process id keeps concurrent test processes apart, the counter concurrent calls.
    let seed = (u64::from(process::id()) << 32_u32) ^ CALLS.fetch_add(1, Ordering::Relaxed);
    bind_pair_with(ATTEMPTS, seed, bind).await
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
    let (listener, udp) = match order {
        Order::TcpFirst => {
            let listener = TcpListener::bind(addr).await?;
            (listener, UdpSocket::bind(addr).await?)
        }
        Order::UdpFirst => {
            let udp = UdpSocket::bind(addr).await?;
            (TcpListener::bind(addr).await?, udp)
        }
    };
    hold_wildcard(port);
    Ok((listener, udp))
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
            Err(error) if is_collision(&error) => {
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

/// Bind a UDP socket on a reserved loopback port number whose TCP side is free.
///
/// The socket is live for UDP and its TCP side is closed. No test that runs in parallel draws
/// the number: the reserved range is not the range of [`bind_tcp_and_udp_pair`] nor an ephemeral
/// range, and every attempt of the process takes the next number of one sequence. The DNS
/// resolver's random client ports can still take a reserved number (the FU-TST-R64 and FU-TST-P03
/// residual, see `closed_port.rs`), and the process-id offset of the sequence is probabilistic.
///
/// # Errors
/// Returns the error of a bind that is not a collision, and `AddrInUse` listing every attempt
/// when every attempt collided.
///
/// # Cancel safety
/// cancel-safe: dropping the future drops the socket bound so far.
pub(crate) async fn bind_udp_with_closed_tcp() -> io::Result<UdpSocket> {
    let udp = with_reserved_port(probe_tcp_then_udp).await?;
    hold_wildcard(udp.local_addr()?.port());
    Ok(udp)
}

/// A reserved loopback port number that is closed for TCP and UDP.
///
/// Nothing holds the number: the TCP side and the UDP side are bound once to prove them free and
/// dropped. No test that runs in parallel draws it, and the FU-TST-R64 residual applies (see
/// [`bind_udp_with_closed_tcp`]).
///
/// # Errors
/// Returns the error of a bind that is not a collision, and `AddrInUse` listing every attempt
/// when every attempt collided.
///
/// # Cancel safety
/// cancel-safe: dropping the future drops the socket bound so far.
pub(crate) async fn reserve_closed_port() -> io::Result<u16> {
    Ok(with_reserved_port(probe_tcp_then_udp)
        .await?
        .local_addr()?
        .port())
}

/// Bind a UDP socket on a loopback port number that the system chooses, and keep a wildcard
/// socket on the number (see [`hold_wildcard`]).
///
/// # Errors
/// Returns the error of the bind.
///
/// # Cancel safety
/// cancel-safe: dropping the future drops the socket bound so far.
pub(crate) async fn bind_udp_loopback() -> io::Result<UdpSocket> {
    let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    hold_wildcard(udp.local_addr()?.port());
    Ok(udp)
}

/// Bind a UDP socket on an IPv6 loopback port number that the system chooses, and keep a
/// wildcard socket on the number (see [`hold_wildcard_v6`]).
///
/// # Errors
/// Returns the error of the bind.
///
/// # Cancel safety
/// cancel-safe: dropping the future drops the socket bound so far.
pub(crate) async fn bind_udp_loopback_v6() -> io::Result<UdpSocket> {
    let udp = UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)).await?;
    hold_wildcard_v6(udp.local_addr()?.port());
    Ok(udp)
}

/// Wildcard sockets that keep the DNS resolver off the numbers of the UDP sockets of this process.
static WILDCARD_HOLDS: Mutex<Vec<StdUdpSocket>> = Mutex::new(Vec::new());

/// Keep a wildcard UDP socket on `port` until the process ends.
///
/// The DNS resolver binds its client sockets to random wildcard ports from 1024 to 65535.
/// Windows lets such a bind share the number of a socket that is bound to one address, so a
/// reply or a datagram meant for the resolver reaches the test's socket, or the resolver's
/// question reaches the fixture itself. A wildcard socket on the same number makes the
/// resolver's bind collide, and it picks another number. Linux and macOS refuse this second bind
/// because the first socket already holds the number, which protects it as well.
pub(crate) fn hold_wildcard(port: u16) {
    if let Ok(socket) = StdUdpSocket::bind((Ipv4Addr::UNSPECIFIED, port)) {
        WILDCARD_HOLDS
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(socket);
    }
}

/// Keep an IPv6 wildcard UDP socket on `port` until the process ends.
///
/// The same protection as [`hold_wildcard`] for the IPv6 family: a wildcard bind of that family
/// on a number whose socket is bound to `::1` collides instead of sharing the number.
pub(crate) fn hold_wildcard_v6(port: u16) {
    if let Ok(socket) = StdUdpSocket::bind((Ipv6Addr::UNSPECIFIED, port)) {
        WILDCARD_HOLDS
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(socket);
    }
}

/// Take the next numbers of the reserved sequence until `bind` succeeds on one.
///
/// The numbers come from `closed_port.rs`.
///
/// # Errors
/// Returns the error of a bind that is not a collision, and `AddrInUse` listing every attempt
/// when every attempt collided.
///
/// # Cancel safety
/// cancel-safe when `bind` is: dropping the future drops what `bind` returned so far.
pub(crate) async fn with_reserved_port<T>(
    mut bind: impl AsyncFnMut(SocketAddr) -> io::Result<T>,
) -> io::Result<T> {
    let mut tried = Vec::new();
    for _ in 0..ATTEMPTS {
        let port = next_reserved_port();
        match bind(SocketAddr::from((Ipv4Addr::LOCALHOST, port))).await {
            Ok(bound) => return Ok(bound),
            Err(error) if is_collision(&error) => tried.push(format!("{port} {:?}", error.kind())),
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AddrInUse,
        format!(
            "no reserved loopback port with a free TCP side in {ATTEMPTS} attempts: {}",
            tried.join("; ")
        ),
    ))
}

/// Prove the TCP side of `addr` free, without keeping it, and bind the UDP side.
///
/// # Errors
/// Returns the error of the first bind that fails.
///
/// # Cancel safety
/// cancel-safe: dropping the future drops the socket bound so far.
async fn probe_tcp_then_udp(addr: SocketAddr) -> io::Result<UdpSocket> {
    drop(TcpListener::bind(addr).await?);
    UdpSocket::bind(addr).await
}

/// Whether a failed bind is a collision that another number can avoid.
fn is_collision(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::AddrInUse | io::ErrorKind::PermissionDenied
    )
}

/// The next value of the `SplitMix64` sequence that starts at `state`.
const fn next(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}
