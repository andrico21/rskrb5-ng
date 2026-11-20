//! The Tokio client: round trips, the reply limit, deadlines and cancellation.

use core::time::Duration;
use std::{fs, io, os::unix::fs::MetadataExt as _, path::Path};

use rskrb5_ng::{
    ccache::kcm::{
        async_client::Client,
        socket::Trust,
        wire::{MAX_REPLY_SIZE, calls},
    },
    error::{Kcm as Error, KcmRefusal, KcmStage},
};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _, duplex},
    net::{UnixListener, UnixStream},
    task, time,
};

use super::mock::{TestError, scratch};

/// A trust that names the owner of the test socket.
fn trust(path: &Path) -> Result<Trust, TestError> {
    Ok(Trust::new().with_uid(fs::metadata(path)?.uid()))
}

/// Read one request from `stream`.
async fn read_request(stream: &mut UnixStream) -> io::Result<()> {
    let mut length = [0_u8; 4];
    let header = stream.read_exact(&mut length).await?;
    let mut request =
        vec![0_u8; usize::try_from(u32::from_be_bytes(length)).map_err(io::Error::other)?];
    let body = stream.read_exact(&mut request).await?;
    debug_assert!(header == 4 && body == request.len(), "whole frame read");
    Ok(())
}

/// A request and its reply over a real socket, from a peer the check accepts.
#[tokio::test]
async fn a_request_round_trips_over_a_unix_socket() -> Result<(), TestError> {
    let directory = scratch("tokio")?;
    let path = directory.join("kcm.sock");
    let listener = UnixListener::bind(&path)?;
    let server = task::spawn(async move {
        let (mut stream, _peer) = listener.accept().await?;
        read_request(&mut stream).await?;
        stream
            .write_all(&[0_u8, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, b'0', b':', b'4', 0])
            .await?;
        io::Result::Ok(())
    });
    let mut client = Client::connect(&path, &trust(&path)?).await?;
    assert_eq!(
        client.call(&calls::get_default_cache()).await?.as_str(),
        "0:4"
    );
    server.await??;
    fs::remove_dir_all(directory)?;
    Ok(())
}

/// Connecting needs a socket whose owner and peer are trusted.
#[tokio::test]
async fn connecting_checks_the_socket() -> Result<(), TestError> {
    let directory = scratch("tokio-trust")?;
    let missing = directory.join("none");
    assert!(matches!(
        Client::connect(&missing, &Trust::new()).await,
        Err(Error::NoServer)
    ));
    let plain = directory.join("plain");
    fs::write(&plain, b"x")?;
    assert!(matches!(
        Client::connect(&plain, &Trust::new()).await,
        Err(Error::Untrusted(KcmRefusal::NotASocket))
    ));
    fs::remove_dir_all(directory)?;
    Ok(())
}

/// A reply over the limit breaks the client before any body is read.
#[tokio::test]
async fn an_oversized_reply_breaks_the_client() -> Result<(), TestError> {
    let announced = u32::try_from(MAX_REPLY_SIZE)?.saturating_add(1);
    let (mut daemon, near) = duplex(64);
    daemon.write_all(&announced.to_be_bytes()).await?;
    let mut client = Client::new(near);
    assert!(matches!(
        client.call(&calls::get_default_cache()).await,
        Err(Error::ReplyTooBig { length, limit: _ }) if length == announced
    ));
    assert!(client.is_broken());
    assert!(matches!(
        client.call(&calls::get_default_cache()).await,
        Err(Error::Broken)
    ));
    Ok(())
}

/// A deadline on a request that changes the daemon is an unknown outcome.
#[tokio::test]
async fn a_deadline_cuts_off_a_silent_daemon() -> Result<(), TestError> {
    let (_daemon, near) = duplex(64);
    let mut client = Client::new(near).with_timeout(Duration::from_millis(50));
    assert!(matches!(
        client.call(&calls::gen_new()).await,
        Err(Error::OutcomeUnknown { opcode: 3, cause }) if matches!(*cause, Error::Io { stage: KcmStage::Read, source: _ })
    ));
    assert!(client.is_broken());
    Ok(())
}

/// A call dropped before it finishes leaves the client refusing further
/// calls, so a late reply is never paired with a later request.
#[tokio::test]
async fn a_cancelled_call_breaks_the_client() -> Result<(), TestError> {
    let (_daemon, near) = duplex(64);
    let mut client = Client::new(near);
    let abandoned = time::timeout(
        Duration::from_millis(20),
        client.call(&calls::get_default_cache()),
    )
    .await;
    assert!(matches!(abandoned, Err(_elapsed)));
    assert!(matches!(
        client.call(&calls::get_default_cache()).await,
        Err(Error::Broken)
    ));
    Ok(())
}
