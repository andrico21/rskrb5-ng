//! Loopback port numbers that tests need refused, drawn from a reserved range.
//!
//! A number that was bound and freed again can be bound by a test that runs in parallel, which
//! then answers where a refusal is expected. The reserved range is not the range of the
//! operating system's ephemeral ports and not the range that `loopback_pair.rs` draws from, so
//! no test draws a number of it. One residual remains (FU-TST-R64, FU-TST-P03): the DNS resolver
//! binds its client sockets to random wildcard ports (1024 to 65535) and can take a reserved
//! number while a test that expects a refusal sends. That matters only for a refusal over UDP (a
//! UDP socket does not change a TCP connect) and the tests cannot remove it: the crate builds
//! its resolver with the default options. A TCP connect to a reserved number is refused at once
//! on Linux and macOS and after about two seconds on Windows. A TCP socket that is bound and
//! does not listen is no substitute: macOS does not refuse a connect to it.
//!
//! Binding the number and dropping the socket does not prove it closed (FU-TST-P07). macOS gives
//! a socket its close-on-exec flag in a second call after `socket()`, so a test thread that
//! spawns a child process (`support/env.rs`) in between hands the child the proof listener: the
//! number keeps answering until that child exits, a few milliseconds after the drop, and the
//! child of another test that connects there is accepted instead of refused. The proof therefore
//! also connects to the number once and rejects a number that answers.

use core::{
    net::{Ipv4Addr, SocketAddr},
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};
use std::{
    io,
    net::{TcpListener, TcpStream},
    process,
};

/// Attempts of [`reserve_closed_tcp_port`] before it gives up.
const ATTEMPTS: u8 = 64;

/// First port number of the reserved range.
///
/// The range lies below the ephemeral range of every supported system (Windows and macOS start
/// at 49152, Linux at 32768) and below the range that `loopback_pair.rs` draws from.
pub(crate) const RESERVED_FIRST: u16 = 20_000;

/// Longest wait for the answer of the connect that proves a number closed.
///
/// A listener answers a loopback connect at once and a closed number is refused at once. Windows
/// refuses after about two seconds: the bound ends that wait, and a number that has not answered
/// by then counts as closed (a Windows handle is not inherited by a child, so no listener
/// outlives the proof there).
const ANSWER_BOUND: Duration = Duration::from_millis(100);

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
/// Nothing holds the number: the TCP side is bound once to prove it free, dropped, and a connect
/// to it must not be answered (see [`prove_closed_with`]). No test that runs in parallel draws
/// it, because nothing else draws from the reserved range; the DNS resolver's random client
/// ports can still take it (the FU-TST-R64 residual of the module comment).
///
/// # Errors
/// Returns the error of a bind that is not a collision, and `AddrInUse` when every attempt
/// collided.
pub(crate) fn reserve_closed_tcp_port() -> io::Result<u16> {
    reserve_closed_tcp_port_with(|address| {
        prove_closed_with(
            address,
            |bound| TcpListener::bind(bound).map(drop),
            tcp_answers,
        )
    })
}

/// Whether a TCP connect to `address` is answered within [`ANSWER_BOUND`].
pub(crate) fn tcp_answers(address: SocketAddr) -> bool {
    TcpStream::connect_timeout(&address, ANSWER_BOUND).is_ok()
}

/// Prove that no listener holds `address`: `bind` takes and frees it, then `answers` must say no.
///
/// A bind that succeeds is not enough: a child process that inherited the freed socket (see the
/// module comment) still answers.
///
/// # Errors
/// Returns the error of `bind`, and `AddrInUse` when the number answers.
pub(crate) fn prove_closed_with(
    address: SocketAddr,
    bind: impl FnOnce(SocketAddr) -> io::Result<()>,
    answers: impl FnOnce(SocketAddr) -> bool,
) -> io::Result<()> {
    bind(address)?;
    if answers(address) {
        return Err(io::Error::new(
            io::ErrorKind::AddrInUse,
            format!("a TCP connect to {address} is answered"),
        ));
    }
    Ok(())
}

/// Take the next numbers of the reserved sequence until `probe` accepts one.
///
/// Only `AddrInUse` and `PermissionDenied` are collisions that another number avoids.
///
/// # Errors
/// Returns the error of a probe that is not a collision, and `AddrInUse` when every attempt
/// collided.
pub(crate) fn reserve_closed_tcp_port_with(
    mut probe: impl FnMut(SocketAddr) -> io::Result<()>,
) -> io::Result<u16> {
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
