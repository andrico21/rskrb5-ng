//! A UDP socket on a loopback port with a wildcard socket kept on its number.
//!
//! This is the `bind_udp_loopback` and `bind_udp_loopback_v6` rule of
//! `support/loopback_pair.rs` (FU-TST-P03: the DNS resolver binds random wildcard client
//! ports, and Windows lets such a bind share a number that is bound to one address). The shared
//! file cannot be included whole here: every `pub(crate)` item of a test crate must be used,
//! and only `client_transport.rs` carries the self-test that uses them all.

use core::net::{Ipv4Addr, Ipv6Addr};
use std::{
    io,
    net::UdpSocket as StdUdpSocket,
    sync::{Mutex, PoisonError},
};

use tokio::net::UdpSocket;

/// Wildcard sockets that keep the resolver off the numbers of this process's UDP sockets.
static HOLDS: Mutex<Vec<StdUdpSocket>> = Mutex::new(Vec::new());

/// Bind a UDP socket on `127.0.0.1` (or `::1`), a number the system chooses, and keep a wildcard
/// socket on that number.
///
/// # Errors
/// Returns the error of the bind. An IPv6 loopback that the host does not have is an error.
pub(crate) async fn bind(v6: bool) -> io::Result<UdpSocket> {
    let (socket, wildcard) = if v6 {
        let socket = UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)).await?;
        let port = socket.local_addr()?.port();
        (socket, StdUdpSocket::bind((Ipv6Addr::UNSPECIFIED, port)))
    } else {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let port = socket.local_addr()?.port();
        (socket, StdUdpSocket::bind((Ipv4Addr::UNSPECIFIED, port)))
    };
    if let Ok(held) = wildcard {
        HOLDS
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(held);
    }
    Ok(socket)
}
