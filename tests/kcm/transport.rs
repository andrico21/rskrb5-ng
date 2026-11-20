//! A scripted daemon: partial frames, daemon error ids, disconnects, an
//! oversized reply, slow peers and the one reconnect of an idle connection.

use core::time::Duration;
use std::{
    fs,
    io::{self, Write as _},
    net::Shutdown,
    os::unix::{fs::MetadataExt as _, net::UnixStream},
    path::Path,
    sync::mpsc,
};

use rskrb5_ng::{
    ccache::{
        kcm::{Store, socket::Trust, wire::MAX_REPLY_SIZE},
        stores::CredentialStore as _,
    },
    error::{Ccache as CcacheError, Kcm as Error, KcmStage},
};

use super::mock::{Script, Scripted, TestError, ok, reply, skip_request};

/// A store for the daemon at `path` that trusts the user owning it, so the
/// tests also pass where this process's own user cannot be read.
pub(super) fn store(path: &Path) -> Result<Store, TestError> {
    let owner = fs::metadata(path)?.uid();
    Ok(Store::new(path).with_trust(Trust::new().with_uid(owner)))
}

/// What the client's primary-cache request returns, as an error or a name.
fn primary(store: &Store) -> Result<String, CcacheError> {
    store.collection("")?.primary().map(|cache| cache.name())
}

/// A script that answers each request with the next canned reply.
fn answers(replies: Vec<Vec<u8>>) -> Script {
    Box::new(move |stream| {
        for payload in replies {
            skip_request(stream)?;
            ok(stream, &payload)?;
        }
        Ok(())
    })
}

/// Requests of one connection share it, and the name comes back as the daemon gave it.
#[test]
fn one_connection_serves_every_request_of_a_store() -> Result<(), TestError> {
    let daemon = Scripted::start(
        "shared",
        vec![answers(vec![b"0:5\0".to_vec(), b"0:6\0".to_vec()])],
    )?;
    let store = store(daemon.path())?;
    assert_eq!(primary(&store)?, "KCM:0:5");
    assert_eq!(primary(&store)?, "KCM:0:6");
    daemon.finish()
}

/// Header and code without the whole body, or half a length, then a close.
#[test]
fn partial_frames_fail_as_short_reads() -> Result<(), TestError> {
    let halves: [fn(&mut UnixStream) -> io::Result<()>; 3] = [
        |stream| stream.write_all(&[0_u8, 0]),
        |stream| stream.write_all(&[0_u8, 0, 0, 12, 0, 0, 0, 0]),
        |stream| stream.write_all(&[0_u8, 0, 0, 12, 0, 0, 0, 0, 0, 0, 0, 0, b'0']),
    ];
    for half in halves {
        let script: Script = Box::new(move |stream| {
            skip_request(stream)?;
            half(stream)
        });
        let daemon = Scripted::start("partial", vec![script])?;
        let outcome = primary(&store(daemon.path())?);
        assert!(matches!(
            outcome,
            Err(CcacheError::Kcm(Error::Io { stage: KcmStage::Read, source })) if source.kind() == io::ErrorKind::UnexpectedEof
        ));
        daemon.finish()?;
    }
    Ok(())
}

/// A reply lost to a request that changes the daemon is an unknown outcome.
#[test]
fn a_lost_reply_to_a_mutation_is_an_unknown_outcome() -> Result<(), TestError> {
    let script: Script = Box::new(|stream| {
        skip_request(stream)?;
        stream.write_all(&[0, 0, 0])
    });
    let daemon = Scripted::start("mutation", vec![script])?;
    let outcome = store(daemon.path())?
        .collection("")?
        .new_unique()
        .map(|_cache| ());
    assert!(matches!(
        outcome,
        Err(CcacheError::Kcm(Error::OutcomeUnknown { opcode: 3, cause })) if matches!(*cause, Error::Io { stage: KcmStage::Read, source: _ })
    ));
    daemon.finish()
}

/// An unknown opcode is answered with a close (SSSD) or with a status code
/// (Heimdal); neither is mistaken for a reply.
#[test]
fn unknown_opcodes_and_error_ids_are_typed() -> Result<(), TestError> {
    let closes: Script = Box::new(skip_request);
    // A daemon error leaves the connection usable, so the client sends the
    // next request on it: one script answers both requests and closes only
    // after the second, as a daemon that keeps its connection open would.
    let errors: Script = Box::new(|stream| {
        skip_request(stream)?;
        reply(stream, -1_765_328_188, 0, &[])?;
        skip_request(stream)?;
        reply(stream, 0, -1_765_328_189, &[])
    });
    let daemon = Scripted::start("errors", vec![closes, errors])?;
    let store = store(daemon.path())?;
    assert!(matches!(
        primary(&store),
        Err(CcacheError::Kcm(Error::Io {
            stage: KcmStage::Read,
            source: _
        }))
    ));
    assert!(matches!(
        primary(&store),
        Err(CcacheError::Kcm(Error::Daemon {
            opcode: 20,
            code: -1_765_328_188_i32
        }))
    ));
    assert!(matches!(
        store.resolve("0:9")?.load(),
        Err(CcacheError::CacheNotFound { name }) if name == "KCM:0:9"
    ));
    daemon.finish()
}

/// A daemon that closed an idle connection is reconnected once.
#[test]
fn an_idle_connection_closed_by_the_daemon_is_reconnected_once() -> Result<(), TestError> {
    let (closed, wait) = mpsc::channel();
    let first: Script = Box::new(move |stream| {
        skip_request(stream)?;
        ok(stream, b"0:1\0")?;
        stream.shutdown(Shutdown::Both)?;
        closed.send(()).map_err(io::Error::other)
    });
    let daemon = Scripted::start("idle", vec![first, answers(vec![b"0:2\0".to_vec()])])?;
    let store = store(daemon.path())?;
    assert_eq!(primary(&store)?, "KCM:0:1");
    wait.recv()?;
    assert_eq!(primary(&store)?, "KCM:0:2");
    daemon.finish()
}

/// A peer that never answers is cut off by the deadline, and so is one that
/// sends a byte and stops.
#[test]
fn slow_peers_are_bounded_by_the_deadline() -> Result<(), TestError> {
    for dribble in [false, true] {
        let (release, held) = mpsc::channel::<()>();
        let script: Script = Box::new(move |stream| {
            skip_request(stream)?;
            if dribble {
                stream.write_all(&[0])?;
            }
            held.recv().map_err(io::Error::other)
        });
        let daemon = Scripted::start("slow", vec![script])?;
        let store = store(daemon.path())?.with_timeout(Duration::from_millis(100));
        let outcome = primary(&store);
        assert!(matches!(
            outcome,
            Err(CcacheError::Kcm(Error::Io { stage: KcmStage::Read, source })) if source.kind() == io::ErrorKind::TimedOut
        ));
        release.send(())?;
        daemon.finish()?;
    }
    Ok(())
}

/// A length above the cap is refused although the daemon sends no body: the
/// client does not wait for or allocate one.
#[test]
fn an_oversized_reply_fails_without_waiting_for_the_body() -> Result<(), TestError> {
    let (release, held) = mpsc::channel::<()>();
    let announced = u32::try_from(MAX_REPLY_SIZE)? + 1;
    let script: Script = Box::new(move |stream| {
        skip_request(stream)?;
        stream.write_all(&announced.to_be_bytes())?;
        held.recv().map_err(io::Error::other)
    });
    let daemon = Scripted::start("oversized", vec![script])?;
    let outcome = primary(&store(daemon.path())?);
    assert!(matches!(
        outcome,
        Err(CcacheError::Kcm(Error::ReplyTooBig { length, limit })) if length == announced && limit == MAX_REPLY_SIZE
    ));
    release.send(())?;
    daemon.finish()
}

/// After a failure that desynchronizes the stream, the next request uses a
/// new connection and never sees the stale reply.
#[test]
fn a_failed_exchange_never_leaks_into_the_next_request() -> Result<(), TestError> {
    let stale: Script = Box::new(|stream| {
        skip_request(stream)?;
        stream.write_all(&[0, 0, 0, 12, 0, 0, 0, 0, 0, 0])?;
        stream.shutdown(Shutdown::Both)
    });
    let daemon = Scripted::start("stale", vec![stale, answers(vec![b"0:7\0".to_vec()])])?;
    let store = store(daemon.path())?;
    assert!(matches!(
        primary(&store),
        Err(CcacheError::Kcm(Error::Io {
            stage: KcmStage::Read,
            source: _
        }))
    ));
    assert_eq!(primary(&store)?, "KCM:0:7");
    daemon.finish()?;
    Ok(())
}
