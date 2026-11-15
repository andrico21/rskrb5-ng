//! The loopback port-pair helper retries a collision on the UDP side with a fresh TCP port.

use super::*;
use crate::loopback_pair::bind_pair_with;

/// A UDP socket that holds the first TCP port's number makes the first attempt fail and the next
/// attempt succeed on another port: the proof that the helper retries.
#[test]
fn pair_retries_when_the_udp_side_of_the_first_tcp_port_is_held() -> Result<(), TestError> {
    runtime()?.block_on(async {
        // Given a TCP listener whose port number is already taken for UDP by a socket we hold.
        let (first_listener, held_udp) = bind_tcp_and_udp_pair().await?;
        let held_port = held_udp.local_addr()?.port();
        let mut first = Some(first_listener);
        let mut attempts = 0_u8;
        // When the helper starts with that listener.
        let (listener, udp) = bind_pair_with(4, async || {
            attempts += 1;
            match first.take() {
                Some(listener) => Ok(listener),
                None => TcpListener::bind("127.0.0.1:0").await,
            }
        })
        .await?;
        // Then it left the held port and paired a fresh TCP port with a UDP socket on that number.
        assert!(
            attempts >= 2,
            "the first attempt cannot succeed: {attempts}"
        );
        assert_ne!(listener.local_addr()?.port(), held_port);
        assert_eq!(udp.local_addr()?, listener.local_addr()?);
        drop(held_udp);
        Ok::<_, TestError>(())
    })
}

/// A pair that never forms stops after the stated number of attempts with a collision error.
#[test]
fn pair_gives_up_after_the_stated_attempts() -> Result<(), TestError> {
    runtime()?.block_on(async {
        // Given TCP listeners whose port numbers are all held for UDP.
        let mut held = Vec::new();
        let mut attempts = 0_u8;
        // When every attempt collides.
        let result = bind_pair_with(3, async || {
            attempts += 1;
            let (listener, udp) = bind_tcp_and_udp_pair().await?;
            held.push(udp);
            Ok(listener)
        })
        .await;
        // Then exactly three attempts ran and the failure is an address collision.
        let error = result.err().ok_or("every attempt collided")?;
        assert_eq!(error.kind(), io::ErrorKind::AddrInUse);
        assert_eq!(attempts, 3);
        assert_eq!(held.len(), 3, "each attempt held its UDP port number");
        Ok::<_, TestError>(())
    })
}

/// A failure of the TCP bind is not a collision and is not retried.
#[test]
fn pair_does_not_retry_a_tcp_bind_failure() -> Result<(), TestError> {
    runtime()?.block_on(async {
        let mut attempts = 0_u8;
        let result = bind_pair_with(4, async || {
            attempts += 1;
            Err(io::Error::from(io::ErrorKind::InvalidInput))
        })
        .await;
        let error = result.err().ok_or("a failed TCP bind formed a pair")?;
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(attempts, 1);
        Ok::<_, TestError>(())
    })
}
