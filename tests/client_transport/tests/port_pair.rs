//! The loopback port-pair helper retries a collision, spreads its candidates over the dynamic
//! range and tries both bind orders.

use std::{net::UdpSocket as StdUdpSocket, sync::mpsc, thread};

use tokio::net::TcpSocket;

use super::{kpasswd_order::closed_port, *};
use crate::loopback_pair::{
    FIRST_PORT, Order, RESERVED_FIRST, bind_on, bind_pair_with, hold_wildcard,
};

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

/// Seeds that [`seed_drawing_first`] tries: the first draw of a call is uniform over 16384
/// numbers, so a given number is missed by all of them with a probability of about `e^-16`.
const SEEDS: u64 = 1 << 18;

/// The seed of a pair helper call whose first draw is `port`, if there is one.
async fn seed_drawing_first(port: u16) -> Option<u64> {
    for seed in 0..SEEDS {
        let mut first = 0_u16;
        drop(
            bind_pair_with(1, seed, async |candidate, _| {
                first = candidate;
                Err(io::Error::from(io::ErrorKind::InvalidInput))
            })
            .await,
        );
        if first == port {
            return Some(seed);
        }
    }
    None
}

/// Whether a pair helper call with `seed` takes `port` on its own thread, as a parallel test
/// would, and a connection to the port is then accepted. `None` when the bind collided.
async fn parallel_pair_answers(port: u16, seed: u64) -> Result<Option<bool>, TestError> {
    let (bound_tx, bound_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel::<()>();
    let parallel = thread::spawn(move || -> Result<(), TestError> {
        runtime()?.block_on(async {
            let pair = bind_pair_with(1, seed, bind_on).await;
            bound_tx.send(pair.is_ok())?;
            // The pair stays bound until the connecting side is done.
            done_rx.recv().unwrap_or_default();
            drop(pair);
            Ok(())
        })
    });
    let bound = bound_rx.recv()?;
    let answered = if bound {
        let connected = bounded(
            Duration::from_secs(10),
            "connect to the taken port",
            TcpStream::connect(("127.0.0.1", port)),
        )
        .await?;
        Some(connected.is_ok())
    } else {
        None
    };
    drop(done_tx);
    parallel
        .join()
        .map_err(|_panic| "the parallel thread panicked")??;
    Ok(answered)
}

/// A port number that was freed again is taken by a parallel test that draws it and then
/// answers; a closed port is a number that no parallel draw can reach and stays refused.
#[test]
fn a_parallel_draw_takes_a_freed_number_but_never_a_closed_port() -> Result<(), TestError> {
    runtime()?.block_on(async {
        // Given a number of the dynamic range that was bound and freed again, the old way of
        // making a closed port, and a parallel call whose first draw is that number.
        let mut answered = None;
        for _ in 0..8_u8 {
            let (listener, udp) = bind_tcp_and_udp_pair().await?;
            let freed = udp.local_addr()?.port();
            drop((udp, listener));
            let seed = seed_drawing_first(freed)
                .await
                .ok_or("no seed draws the freed number")?;
            // When that call runs on its own thread.
            answered = parallel_pair_answers(freed, seed).await?;
            if answered.is_some() {
                break;
            }
        }
        // Then it holds the number and answers: a refusal expected there would see a reply.
        assert_eq!(
            answered,
            Some(true),
            "the control did not take a freed number"
        );
        // And no call can draw a closed port, whatever its seed, so its connect is refused.
        let closed: SocketAddr = closed_port().await?.parse()?;
        assert_eq!(
            seed_drawing_first(closed.port()).await,
            None,
            "a parallel call can draw the closed port {closed}"
        );
        let refused = bounded(
            Duration::from_secs(10),
            "connect to the closed port",
            TcpStream::connect(closed),
        )
        .await?;
        assert_eq!(
            refused.err().map(|error| error.kind()),
            Some(io::ErrorKind::ConnectionRefused)
        );
        Ok::<_, TestError>(())
    })
}

/// The numbers of the reserved range come from one sequence: a number that was freed is not
/// handed to the next call, so two tests that overlap never share a closed port.
#[test]
fn reserved_numbers_do_not_repeat_and_stay_below_the_pair_range() -> Result<(), TestError> {
    runtime()?.block_on(async {
        // Given calls that each drop their socket at once.
        let mut ports = Vec::new();
        for _ in 0..64_u8 {
            // When the next call binds.
            ports.push(bind_udp_with_closed_tcp().await?.local_addr()?.port());
        }
        // Then no number repeats and every number is in the reserved range, below the pair range.
        let mut sorted = ports.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), ports.len(), "{ports:?}");
        assert!(
            ports
                .iter()
                .all(|&port| (RESERVED_FIRST..FIRST_PORT).contains(&port)),
            "{ports:?}"
        );
        Ok::<_, TestError>(())
    })
}

/// A held reserved socket is live for UDP and its TCP side is refused.
#[test]
fn a_reserved_udp_socket_is_live_and_its_tcp_side_is_closed() -> Result<(), TestError> {
    runtime()?.block_on(async {
        // Given a reserved socket that is kept.
        let udp = bind_udp_with_closed_tcp().await?;
        let addr = udp.local_addr()?;
        // When a datagram is sent to it and a connection is attempted on the same number.
        let peer = UdpSocket::bind("127.0.0.1:0").await?;
        assert_eq!(peer.send_to(b"ping", addr).await?, 4);
        let connected = bounded(
            Duration::from_secs(10),
            "connect to the closed TCP side",
            TcpStream::connect(addr),
        )
        .await?;
        // Then the socket received the datagram and the connection was refused.
        let mut bytes = [0_u8; 8];
        let (length, from) = bounded(
            Duration::from_secs(10),
            "datagram",
            udp.recv_from(&mut bytes),
        )
        .await??;
        assert_eq!(bytes.get(..length), Some(&b"ping"[..]));
        assert_eq!(from, peer.local_addr()?);
        assert_eq!(
            connected.err().map(|error| error.kind()),
            Some(io::ErrorKind::ConnectionRefused)
        );
        Ok::<_, TestError>(())
    })
}

/// A TCP socket that is bound and does not listen refuses a connection and keeps its number
/// against a parallel bind: the hold that tests which need a refused TCP number take.
#[test]
fn a_bound_tcp_socket_that_does_not_listen_refuses_and_holds_its_number() -> Result<(), TestError> {
    runtime()?.block_on(async {
        // Given a bound TCP socket that never listens.
        let held = TcpSocket::new_v4()?;
        held.bind(SocketAddr::from(([127, 0, 0, 1], 0)))?;
        let addr = held.local_addr()?;
        // When a connection is attempted and a parallel thread binds the same number.
        let refused = bounded(
            Duration::from_secs(10),
            "connect to the bound socket",
            TcpStream::connect(addr),
        )
        .await?;
        let parallel = thread::spawn(move || runtime()?.block_on(TcpListener::bind(addr)));
        let rebound = parallel.join().map_err(|_panic| "the thread panicked")?;
        // Then the connection is refused and the number is not available.
        assert_eq!(
            refused.err().map(|error| error.kind()),
            Some(io::ErrorKind::ConnectionRefused)
        );
        assert!(
            rebound.as_ref().is_err_and(|error| matches!(
                error.kind(),
                io::ErrorKind::AddrInUse | io::ErrorKind::PermissionDenied
            )),
            "the parallel bind took a held number: {rebound:?}"
        );
        Ok::<_, TestError>(())
    })
}

/// Whether a wildcard UDP bind on `port` is refused, the way the DNS resolver's bind meets it.
fn assert_wildcard_bind_collides(port: u16) {
    let bound = StdUdpSocket::bind(("0.0.0.0", port));
    assert!(
        bound.as_ref().is_err_and(|error| matches!(
            error.kind(),
            io::ErrorKind::AddrInUse | io::ErrorKind::PermissionDenied
        )),
        "a wildcard bind took the number {port}: {bound:?}"
    );
}

/// The resolver's wildcard bind collides with the number of every UDP socket that a helper hands
/// out, so the resolver never shares a number with a fixture (Windows would let it).
#[test]
fn a_wildcard_bind_collides_with_every_helper_socket() -> Result<(), TestError> {
    runtime()?.block_on(async {
        // Given a UDP socket from each helper.
        let reserved = bind_udp_with_closed_tcp().await?;
        let loopback = bind_udp_loopback().await?;
        let (_listener, paired) = bind_tcp_and_udp_pair().await?;
        for socket in [&reserved, &loopback, &paired] {
            // When a wildcard socket binds the same number, then it collides.
            assert_wildcard_bind_collides(socket.local_addr()?.port());
        }
        Ok::<_, TestError>(())
    })
}

/// A wildcard socket held on a number makes a wildcard bind collide: the protection that the
/// helpers give a number on Windows, where a wildcard bind would otherwise share the number.
#[test]
fn a_held_wildcard_socket_keeps_a_wildcard_bind_off_the_number() -> Result<(), TestError> {
    runtime()?.block_on(async {
        // Given a number that nothing holds.
        let probe = UdpSocket::bind("127.0.0.1:0").await?;
        let port = probe.local_addr()?.port();
        drop(probe);
        // When a wildcard socket is held on it.
        hold_wildcard(port);
        // Then a wildcard bind on the number collides.
        assert_wildcard_bind_collides(port);
        Ok::<_, TestError>(())
    })
}
