//! The loopback port-pair helper retries a collision, spreads its candidates over the dynamic
//! range and tries both bind orders.

use super::*;
use crate::loopback_pair::{FIRST_PORT, Order, bind_on, bind_pair_with};

/// A UDP socket that holds the number of the first candidate makes the first attempt fail and a
/// later attempt succeed on another port: the proof that the helper retries.
#[test]
fn pair_retries_when_the_udp_side_of_a_candidate_is_held() -> Result<(), TestError> {
    runtime()?.block_on(async {
        // Given a UDP socket that holds a port number whose TCP side is free.
        let held_udp = UdpSocket::bind("127.0.0.1:0").await?;
        let held_port = held_udp.local_addr()?.port();
        let mut attempts = 0_u8;
        // When the helper's first candidate is that number.
        let (listener, udp) = bind_pair_with(4, 1, async |port, order| {
            attempts += 1;
            if attempts == 1 {
                bind_on(held_port, order).await
            } else {
                bind_on(port, order).await
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

/// A pair that never forms stops after the stated number of attempts, and the error lists every
/// attempt with its port, order and error.
#[test]
fn pair_gives_up_after_the_stated_attempts_and_lists_each() -> Result<(), TestError> {
    runtime()?.block_on(async {
        // Given binds that all collide, one kind per attempt.
        let mut tried = Vec::new();
        // When every attempt collides.
        let result = bind_pair_with(3, 9, async |port, order| {
            let kind = if tried.len() == 1 {
                io::ErrorKind::PermissionDenied
            } else {
                io::ErrorKind::AddrInUse
            };
            tried.push((port, order));
            Err(io::Error::from(kind))
        })
        .await;
        // Then exactly three attempts ran, in alternating orders, and the message names them all.
        let error = result.err().ok_or("every attempt collided")?;
        assert_eq!(error.kind(), io::ErrorKind::AddrInUse);
        let orders: Vec<_> = tried.iter().map(|&(_, order)| order).collect();
        assert_eq!(orders, [Order::TcpFirst, Order::UdpFirst, Order::TcpFirst]);
        let message = error.to_string();
        assert!(message.contains("in 3 attempts"), "{message}");
        for &(port, order) in &tried {
            let name = if order == Order::TcpFirst {
                "tcp-first"
            } else {
                "udp-first"
            };
            assert!(message.contains(&format!("{port} {name}")), "{message}");
        }
        assert!(message.contains("PermissionDenied"), "{message}");
        assert!(message.contains("AddrInUse"), "{message}");
        Ok::<_, TestError>(())
    })
}

/// A failure that is not a collision is not retried.
#[test]
fn pair_does_not_retry_a_bind_failure_that_is_not_a_collision() -> Result<(), TestError> {
    runtime()?.block_on(async {
        let mut attempts = 0_u8;
        let result = bind_pair_with(4, 1, async |_, _| {
            attempts += 1;
            Err(io::Error::from(io::ErrorKind::InvalidInput))
        })
        .await;
        let error = result.err().ok_or("a failed bind formed a pair")?;
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(attempts, 1);
        Ok::<_, TestError>(())
    })
}

/// A block of consecutive refused port numbers, longer than the attempts, is left.
///
/// This is the failure the Windows runner shows: UDP refuses a block of consecutive numbers and
/// the sequential TCP allocator walks through it one number at a time. Candidates spread over
/// the range leave the block.
#[test]
fn pair_leaves_a_block_of_refused_ports_longer_than_the_attempts() -> Result<(), TestError> {
    const BLOCK: u16 = 8_192;
    runtime()?.block_on(async {
        for seed in 0..16_u64 {
            // Given the lower half of the dynamic range refused for UDP with 10013's kind.
            let mut refused = 0_u32;
            // When the helper draws its candidates.
            let (listener, udp) = bind_pair_with(64, seed, async |port, order| {
                if port < FIRST_PORT + BLOCK {
                    refused += 1;
                    return Err(io::Error::from(io::ErrorKind::PermissionDenied));
                }
                bind_on(port, order).await
            })
            .await?;
            // Then the pair sits outside the block.
            assert!(
                listener.local_addr()?.port() >= FIRST_PORT + BLOCK,
                "seed {seed}"
            );
            assert_eq!(udp.local_addr()?, listener.local_addr()?);
            assert!(refused < 64, "seed {seed}: every attempt fell in the block");
        }
        Ok::<_, TestError>(())
    })
}

/// A bind order that the system refuses is skipped: the other order forms the pair.
#[test]
fn pair_uses_the_order_that_the_system_accepts() -> Result<(), TestError> {
    runtime()?.block_on(async {
        for refused in [Order::TcpFirst, Order::UdpFirst] {
            // Given one bind order that always fails.
            let mut seen = Vec::new();
            // When the helper alternates the orders.
            let (listener, udp) = bind_pair_with(8, 3, async |port, order| {
                seen.push(order);
                if order == refused {
                    return Err(io::Error::from(io::ErrorKind::PermissionDenied));
                }
                bind_on(port, order).await
            })
            .await?;
            // Then the pair came from the other order.
            assert_ne!(seen.last(), Some(&refused), "{refused:?}");
            assert_eq!(udp.local_addr()?, listener.local_addr()?);
        }
        Ok::<_, TestError>(())
    })
}

/// The candidates lie in the dynamic range, are not consecutive, and depend on the seed, so that
/// concurrent callers and concurrent test processes do not walk the same numbers.
#[test]
fn pair_candidates_spread_over_the_range_and_follow_the_seed() -> Result<(), TestError> {
    runtime()?.block_on(async {
        let mut firsts = Vec::new();
        for seed in 1..=8_u64 {
            // Given binds that all collide, so that every candidate is drawn.
            let mut ports = Vec::new();
            // When the helper draws its 64 candidates for this seed.
            let _refused = bind_pair_with(64, seed, async |port, _| {
                ports.push(port);
                Err(io::Error::from(io::ErrorKind::AddrInUse))
            })
            .await;
            // Then they stay in the dynamic range and are not a run of consecutive numbers.
            assert_eq!(ports.len(), 64);
            assert!(ports.iter().all(|&port| port >= FIRST_PORT), "seed {seed}");
            assert!(
                ports
                    .iter()
                    .zip(ports.iter().skip(1))
                    .any(|(left, right)| left.abs_diff(*right) > 64),
                "seed {seed}: the candidates walk the range in order"
            );
            firsts.extend(ports.first().copied());
        }
        // And another seed starts elsewhere.
        firsts.sort_unstable();
        firsts.dedup();
        assert!(firsts.len() > 1, "every seed drew the same first candidate");
        Ok::<_, TestError>(())
    })
}
