//! A loopback TCP listener and a UDP socket on one port number, for the in-crate tests.
//!
//! A free TCP port number can already be taken for UDP or refused for it. Windows reports an
//! excluded port as `PermissionDenied` and can carry a block of 200 consecutive numbers that UDP
//! refuses, while its TCP allocator hands out numbers one after the other. A walk over consecutive
//! numbers can therefore land in the block on every attempt. The candidates here are 64 numbers
//! of the dynamic range on an odd-stride permutation, so that no 200 consecutive numbers hold
//! more than one of them. `tests/support/loopback_pair.rs` is the same idea for the integration
//! tests; a `#[path]` into `tests/` is refused by the lint gates, so this crate keeps its own.

use alloc::collections::BTreeSet;
use core::{
    error::Error as StdError,
    net::{Ipv4Addr, SocketAddr},
};
use std::{io, process};

use tokio::net::{TcpListener, UdpSocket};

/// Candidates tried before the helper gives up.
const ATTEMPTS: u8 = 64;
/// First port number of the dynamic range (49152..=65535, 16384 numbers).
const FIRST_PORT: u16 = 0xC000;
/// Mask of an offset inside the dynamic range; the range holds `PORT_MASK + 1` numbers.
const PORT_MASK: u16 = 0x3FFF;
/// Distance between consecutive candidates: odd, so the walk visits distinct numbers.
const STRIDE: u16 = 255;

/// Which socket of a pair is bound first.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Order {
    /// The TCP listener first, the UDP socket second.
    TcpFirst,
    /// The UDP socket first, the TCP listener second.
    UdpFirst,
}

/// The candidate ports for the process `pid`, in the order they are tried.
fn candidates(pid: u32) -> impl Iterator<Item = u16> {
    let start = u16::try_from(pid & u32::from(PORT_MASK)).unwrap_or_default();
    (0..ATTEMPTS).map(move |attempt| {
        let offset = start.wrapping_add(u16::from(attempt).wrapping_mul(STRIDE)) & PORT_MASK;
        FIRST_PORT.saturating_add(offset)
    })
}

/// Bind a TCP listener and a UDP socket on one free loopback port number.
///
/// # Errors
/// Returns the error of a bind that is not a collision, and `AddrInUse` listing every attempt
/// (port, order, error kind and OS code) when every candidate collided.
///
/// # Cancel safety
/// cancel-safe: dropping the future drops the sockets bound so far.
pub(super) async fn bind_tcp_and_udp_pair() -> io::Result<(TcpListener, UdpSocket)> {
    first_pair(candidates(process::id()), bind_on).await
}

/// Bind both sockets on `port` of the loopback address in the given order.
async fn bind_on(port: u16, order: Order) -> io::Result<(TcpListener, UdpSocket)> {
    let address = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    match order {
        Order::TcpFirst => {
            let listener = TcpListener::bind(address).await?;
            Ok((listener, UdpSocket::bind(address).await?))
        }
        Order::UdpFirst => {
            let udp = UdpSocket::bind(address).await?;
            Ok((TcpListener::bind(address).await?, udp))
        }
    }
}

/// Hand each port to `bind`, alternating the order, until one bind succeeds.
///
/// Only `AddrInUse` and `PermissionDenied` are retried; any other error is returned at once.
async fn first_pair<T>(
    ports: impl IntoIterator<Item = u16>,
    mut bind: impl AsyncFnMut(u16, Order) -> io::Result<T>,
) -> io::Result<T> {
    let mut tried = Vec::new();
    for (attempt, port) in ports.into_iter().enumerate() {
        let order = if attempt & 1 == 0 {
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
                tried.push(format!("{port} {order:?} {:?}{code}", error.kind()));
            }
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AddrInUse,
        format!(
            "no loopback TCP and UDP port pair in {} attempts: {}",
            tried.len(),
            tried.join("; ")
        ),
    ))
}

/// Consecutive numbers of the dynamic range that a Windows runner can refuse for UDP.
const WINDOW: u32 = 200;
/// Process ids that the pure tests draw candidates for.
const PIDS: [u32; 5] = [0, 1, 4242, 0x3FFF, u32::MAX];

/// The refusal that Windows reports for an excluded UDP port.
fn refused() -> io::Error {
    io::Error::from(io::ErrorKind::PermissionDenied)
}

/// The numbers of the old walk: 16 consecutive numbers from `first`.
fn sequential(first: u16) -> impl Iterator<Item = u16> {
    (0_u16..16).map(move |step| first.saturating_add(step))
}

/// A bind that refuses the `WINDOW` consecutive numbers from `first` and accepts the rest.
fn refusing_block(first: u16) -> impl AsyncFnMut(u16, Order) -> io::Result<u16> {
    async move |port, _order| {
        let block = u32::from(first)..u32::from(first).saturating_add(WINDOW);
        if block.contains(&u32::from(port)) {
            Err(refused())
        } else {
            Ok(port)
        }
    }
}

/// The candidates of one process are 64 distinct numbers of the dynamic range.
#[test]
fn candidates_are_distinct_numbers_of_the_dynamic_range() -> Result<(), Box<dyn StdError>> {
    // Given the candidates of several process ids.
    for pid in PIDS {
        // When they are collected.
        let ports: BTreeSet<u16> = candidates(pid).collect();
        // Then there are 64 of them and each lies in 49152..=65535.
        assert_eq!(candidates(pid).count(), 64, "pid {pid}");
        let first = candidates(pid).next().ok_or("no candidate")?;
        assert!(ports.contains(&first), "pid {pid}");
        assert_eq!(ports.len(), 64, "pid {pid}");
        assert!(
            ports
                .iter()
                .all(|port| (FIRST_PORT..=FIRST_PORT | PORT_MASK).contains(port)),
            "pid {pid} leaves the range: {ports:?}"
        );
    }
    // And the stride, being odd, would visit every number of the range before repeating one.
    let visited: BTreeSet<u16> = (0..=PORT_MASK)
        .map(|step| step.wrapping_mul(STRIDE) & PORT_MASK)
        .collect();
    assert_eq!(visited.len(), usize::from(PORT_MASK) + 1);
    Ok(())
}

/// No 200 consecutive numbers hold more of the candidates than the stride allows.
#[test]
fn a_window_of_200_numbers_holds_at_most_the_bound_computed_from_the_stride()
-> Result<(), Box<dyn StdError>> {
    // Given the smallest circular distance between two candidates, which the stride fixes
    // (candidate k and k + d are d * STRIDE apart modulo the 16384 numbers of the range).
    let span = PORT_MASK.wrapping_add(1);
    let gap = (1..ATTEMPTS)
        .map(|distance| {
            let apart = u16::from(distance).wrapping_mul(STRIDE) & PORT_MASK;
            apart.min(span.saturating_sub(apart))
        })
        .min()
        .ok_or("no pair of candidates")?;
    // When the bound follows: points at least `gap` apart put at most ceil(200 / gap)
    // of them into 200 consecutive numbers.
    let bound = usize::try_from(WINDOW.div_ceil(u32::from(gap.max(1)))).unwrap_or(usize::MAX);
    // Then it is one candidate, and a count over every window of the range agrees.
    assert_eq!(bound, 1, "smallest distance between candidates: {gap}");
    for pid in PIDS {
        let ports: Vec<u32> = candidates(pid).map(u32::from).collect();
        let last_first = u32::from(FIRST_PORT | PORT_MASK).saturating_sub(WINDOW - 1);
        let busiest = (u32::from(FIRST_PORT)..=last_first)
            .map(|first| {
                ports
                    .iter()
                    .filter(|port| (first..first.saturating_add(WINDOW)).contains(port))
                    .count()
            })
            .max()
            .ok_or("no window")?;
        assert!(
            busiest <= bound,
            "pid {pid}: {busiest} candidates in a window"
        );
    }
    Ok(())
}

/// The process id moves the first candidate and with it the whole sequence.
#[test]
fn the_process_id_moves_the_start() -> Result<(), Box<dyn StdError>> {
    // Given two process ids.
    let first: Vec<u16> = candidates(1).collect();
    let second: Vec<u16> = candidates(2).collect();
    // Then their sequences start at different numbers and share none position-wise.
    assert_ne!(
        first.first().ok_or("no start")?,
        second.first().ok_or("no start")?
    );
    assert!(first.iter().zip(&second).all(|(left, right)| left != right));
    Ok(())
}

/// A refused block of 200 numbers defeats the old walk and not the candidates.
#[tokio::test]
async fn a_refused_block_of_200_numbers_is_walked_around() -> Result<(), Box<dyn StdError>> {
    // Given a refusal of 200 consecutive numbers that begins at each candidate in turn.
    for pid in PIDS {
        for first in candidates(pid) {
            // When the old walk (16 consecutive numbers) starts at the block.
            let walk = first_pair(sequential(first), refusing_block(first)).await;
            // Then it fails with every one of its 16 attempts listed.
            let message = walk
                .err()
                .ok_or("the old walk passed the block")?
                .to_string();
            assert_eq!(message.matches("PermissionDenied").count(), 16, "{message}");
            // And the candidates find a number outside the block.
            let port = first_pair(candidates(pid), refusing_block(first)).await?;
            assert!(
                !(first..first.saturating_add(200)).contains(&port),
                "pid {pid}, block {first}: {port}"
            );
        }
    }
    Ok(())
}

/// Only a collision is retried; any other error ends the search at once.
#[tokio::test]
async fn only_collisions_are_retried() -> Result<(), Box<dyn StdError>> {
    // Given a bind that collides twice and then fails with another kind.
    let mut calls = 0_u8;
    let result = first_pair(candidates(9), async |_port, _order| {
        calls = calls.saturating_add(1);
        match calls {
            1 => Err(io::Error::from(io::ErrorKind::AddrInUse)),
            2 => Err(refused()),
            _ => Err::<u16, _>(io::Error::from(io::ErrorKind::ConnectionRefused)),
        }
    })
    .await;
    // Then the search stopped at the third call with that error.
    assert_eq!(calls, 3);
    assert_eq!(
        result.err().map(|error| error.kind()),
        Some(io::ErrorKind::ConnectionRefused)
    );
    Ok(())
}

/// A failure names every attempt: the candidate, the bind order, the error kind and the OS code.
#[tokio::test]
async fn a_failure_lists_every_attempt() -> Result<(), Box<dyn StdError>> {
    // Given a held UDP socket, so that every bind on its number collides with an OS error.
    let held = UdpSocket::bind("127.0.0.1:0").await?;
    let address = held.local_addr()?;
    let collision = UdpSocket::bind(address).await.err().ok_or("no collision")?;
    let code = collision.raw_os_error().ok_or("no OS code")?;
    // When every candidate collides.
    let error = first_pair(candidates(5), async |_port, _order| {
        UdpSocket::bind(address).await
    })
    .await
    .err()
    .ok_or("a held number was bound")?;
    // Then the message lists the 64 attempts, in order, with the kind and the code.
    let message = error.to_string();
    let expected: Vec<String> = candidates(5)
        .enumerate()
        .map(|(attempt, port)| {
            let order = if attempt & 1 == 0 {
                Order::TcpFirst
            } else {
                Order::UdpFirst
            };
            format!("{port} {order:?} AddrInUse({code})")
        })
        .collect();
    assert_eq!(
        message,
        format!(
            "no loopback TCP and UDP port pair in 64 attempts: {}",
            expected.join("; ")
        )
    );
    Ok(())
}

/// The pair shares one number, in either bind order, and the helper draws it from the candidates.
#[tokio::test]
async fn the_pair_shares_a_candidate_number() -> Result<(), Box<dyn StdError>> {
    // Given each bind order, and then the helper itself.
    for order in [Some(Order::TcpFirst), Some(Order::UdpFirst), None] {
        // When a pair is bound.
        let (listener, udp) = match order {
            Some(only) => {
                first_pair(candidates(process::id()), async |port, _alternating| {
                    bind_on(port, only).await
                })
                .await?
            }
            None => bind_tcp_and_udp_pair().await?,
        };
        // Then both sockets sit on the same loopback number, drawn from the candidates.
        let port = listener.local_addr()?.port();
        assert_eq!(udp.local_addr()?.port(), port, "{order:?}");
        assert!(
            candidates(process::id()).any(|candidate| candidate == port),
            "{order:?}"
        );
    }
    Ok(())
}
