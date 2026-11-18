//! Loopback TCP port numbers that the in-crate tests need refused, drawn from a reserved range.
//!
//! A number that was bound on port 0 and freed again can be bound by a test that runs in
//! parallel, which then answers where a refusal is expected. The reserved range is not the range
//! of the operating system's ephemeral ports (Linux starts at 32768, Windows and macOS at 49152)
//! and not the range that the port pairs of `tests/loopback_pair.rs` are drawn from (49152 and
//! above), so no test of this crate draws a number of it. The DNS resolver's random UDP client
//! ports (1024 to 65535) cannot change a TCP refusal. `tests/support/closed_port.rs` is the same
//! idea for the integration tests; a `#[path]` into `tests/` is refused by the lint gates, so
//! this crate keeps its own. A TCP socket that is bound and does not listen is no substitute:
//! macOS does not refuse a connect to it.

use core::{
    error::Error as StdError,
    iter::repeat_with,
    net::{Ipv4Addr, SocketAddr},
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};
use std::{io, net, process};

use tokio::{net::TcpStream, time::timeout};

/// Attempts of [`reserve_closed_tcp_port`] before it gives up.
const ATTEMPTS: u8 = 64;

/// First port number of the reserved range (8192 numbers, below every ephemeral range).
const RESERVED_FIRST: u16 = 20_000;

/// Mask that keeps an offset inside the reserved range.
const RESERVED_MASK: u64 = 0x1FFF;

/// The next number of the reserved sequence.
///
/// The sequence is shared by every call of the process and starts at an offset that depends on
/// the process id, which keeps concurrent test processes apart only probabilistically.
/// `cargo test` runs the test binaries one after another.
fn next_reserved_port() -> u16 {
    static CALLS: AtomicU64 = AtomicU64::new(0);
    static START: AtomicU64 = AtomicU64::new(0);
    // The first call fixes the offset; a racing second call stores the same value.
    let start = match START.load(Ordering::Relaxed) {
        0 => {
            let mixed = u64::from(process::id()).wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
            START.store(mixed, Ordering::Relaxed);
            mixed
        }
        known => known,
    };
    let offset = start.wrapping_add(CALLS.fetch_add(1, Ordering::Relaxed)) & RESERVED_MASK;
    RESERVED_FIRST.saturating_add(u16::try_from(offset).unwrap_or(0))
}

/// A reserved loopback port number whose TCP side is closed.
///
/// Nothing holds the number: the TCP side is bound once to prove it free and dropped. No test
/// of this crate draws it, because nothing else draws from the reserved range.
///
/// # Errors
/// Returns the error of a bind that is not a collision, and `AddrInUse` when every attempt
/// collided.
pub(super) fn reserve_closed_tcp_port() -> io::Result<u16> {
    reserve_with(|address| net::TcpListener::bind(address).map(drop))
}

/// Take the next numbers of the reserved sequence until `probe` accepts one.
///
/// Only `AddrInUse` and `PermissionDenied` are collisions that another number avoids.
///
/// # Errors
/// Returns the error of a probe that is not a collision, and `AddrInUse` when every attempt
/// collided.
fn reserve_with(mut probe: impl FnMut(SocketAddr) -> io::Result<()>) -> io::Result<u16> {
    for _ in 0..ATTEMPTS {
        let port = next_reserved_port();
        match probe(SocketAddr::from((Ipv4Addr::LOCALHOST, port))) {
            Ok(()) => return Ok(port),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::AddrInUse | io::ErrorKind::PermissionDenied
                ) => {}
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AddrInUse,
        format!("no reserved loopback TCP port in {ATTEMPTS} attempts"),
    ))
}

/// The numbers of the reserved sequence stay in the reserved range, below every ephemeral
/// range, and never repeat.
#[test]
fn reserved_numbers_stay_in_the_reserved_range_and_never_repeat() -> Result<(), Box<dyn StdError>> {
    // Given calls of the sequence.
    let ports: Vec<u16> = repeat_with(next_reserved_port).take(64).collect();
    // Then no number repeats, each lies in 20000..=28191 and below 32768, the lowest
    // ephemeral start of the supported systems (Linux; Windows and macOS start at 49152).
    let mut sorted = ports.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), ports.len(), "{ports:?}");
    let lowest = sorted.first().ok_or("no number drawn")?;
    let highest = sorted.last().ok_or("no number drawn")?;
    assert!(*lowest >= 20_000 && *highest <= 28_191, "{ports:?}");
    Ok(())
}

/// A reserved number refuses a TCP connect, and the helper hands out a number each call.
///
/// # Cancel safety
/// Cancellation drops the one connect attempt; nothing is left bound.
#[tokio::test]
async fn a_reserved_number_refuses_a_connect() -> Result<(), Box<dyn StdError>> {
    // Given a reserved closed number.
    let first = reserve_closed_tcp_port()?;
    let second = reserve_closed_tcp_port()?;
    assert_ne!(first, second);
    // When a connection is attempted (Windows reports a refusal after about two seconds).
    let refused = timeout(
        Duration::from_secs(10),
        TcpStream::connect(("127.0.0.1", first)),
    )
    .await?;
    // Then it is refused.
    assert_eq!(
        refused.err().map(|error| error.kind()),
        Some(io::ErrorKind::ConnectionRefused)
    );
    Ok(())
}

/// The search stops after exactly the stated number of attempts and names the collision.
#[test]
fn the_search_stops_after_the_stated_attempts() -> Result<(), Box<dyn StdError>> {
    // Given a probe that collides on every number.
    let mut calls = 0_u8;
    // When the search runs.
    let result = reserve_with(|_address| {
        calls = calls.saturating_add(1);
        Err(io::Error::from(io::ErrorKind::AddrInUse))
    });
    // Then it made exactly 64 attempts and failed with `AddrInUse`.
    let error = result.err().ok_or("every attempt collided")?;
    assert_eq!(calls, 64);
    assert_eq!(error.kind(), io::ErrorKind::AddrInUse);
    Ok(())
}

/// A collision (`AddrInUse` or `PermissionDenied`) moves to the next number; any other error
/// ends the search at once.
#[test]
fn only_collisions_are_retried() -> Result<(), Box<dyn StdError>> {
    // Given a probe that collides twice, with each kind, and then succeeds.
    let mut drawn = Vec::new();
    let found = reserve_with(|address| {
        drawn.push(address.port());
        match drawn.len() {
            1 => Err(io::Error::from(io::ErrorKind::AddrInUse)),
            2 => Err(io::Error::from(io::ErrorKind::PermissionDenied)),
            _ => Ok(()),
        }
    });
    // Then the third number is the one returned.
    assert_eq!(drawn.len(), 3);
    assert_eq!(found?, *drawn.get(2).ok_or("no third number")?);
    // And a probe failing with another kind is not retried.
    let mut calls = 0_u8;
    let failed = reserve_with(|_address| {
        calls = calls.saturating_add(1);
        Err(io::Error::from(io::ErrorKind::InvalidInput))
    });
    assert_eq!(calls, 1);
    assert_eq!(
        failed.err().map(|error| error.kind()),
        Some(io::ErrorKind::InvalidInput)
    );
    Ok(())
}
