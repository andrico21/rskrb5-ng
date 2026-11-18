//! Loopback port numbers that tests need refused, drawn from a reserved range.
//!
//! A number that was bound and freed again can be bound by a test that runs in parallel, which
//! then answers where a refusal is expected. The reserved range is not the range of the
//! operating system's ephemeral ports and not the range that `loopback_pair.rs` draws from, so
//! no test draws a number of it. One residual remains (FU-TST-R64): the DNS resolver binds its
//! client sockets to random wildcard ports (1024 to 65535) and can take a reserved number while
//! a test that expects a refusal sends. A TCP connect to such a number is refused at once on
//! Linux and macOS and after about two seconds on Windows. A TCP socket that is bound and does
//! not listen is no substitute: macOS does not refuse a connect to it.

use core::{
    net::{Ipv4Addr, SocketAddr},
    sync::atomic::{AtomicU64, Ordering},
};
use std::{io, net::TcpListener, process};

/// Attempts of [`reserve_closed_tcp_port`] before it gives up.
const ATTEMPTS: u8 = 64;

/// First port number of the reserved range.
///
/// The range lies below the ephemeral range of every supported system (Windows and macOS start
/// at 49152, Linux at 32768) and below the range that `loopback_pair.rs` draws from.
pub(crate) const RESERVED_FIRST: u16 = 20_000;

/// Mask that keeps an offset inside the reserved range (8192 numbers).
const RESERVED_MASK: u64 = 0x1FFF;

/// The next number of the reserved sequence.
///
/// The sequence is shared by every call of the process and starts at an offset that depends on
/// the process id. That keeps concurrent test processes apart only probabilistically: two
/// offsets can lie close together. `cargo test` runs the test binaries one after another.
pub(crate) fn next_reserved_port() -> u16 {
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
/// that runs in parallel draws it, because nothing else draws from the reserved range; the DNS
/// resolver's random client ports can still take it (the FU-TST-R64 residual of the module
/// comment).
///
/// # Errors
/// Returns the error of a bind that is not a collision, and `AddrInUse` when every attempt
/// collided.
pub(crate) fn reserve_closed_tcp_port() -> io::Result<u16> {
    for _ in 0..ATTEMPTS {
        let port = next_reserved_port();
        match TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, port))) {
            Ok(probe) => {
                drop(probe);
                return Ok(port);
            }
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
