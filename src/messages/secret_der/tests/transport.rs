//! TCP request frame ownership regressions.

use core::error::Error;

use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::TcpListener,
    sync::oneshot,
};

use super::ERASED;
use crate::{
    client::transport::{KdcProtocol, Tokio},
    config::Config,
    error::Client as ClientError,
    kadmin::Request,
};

/// Local fixture failures.
type TestError = Box<dyn Error + Send + Sync>;

/// Observer label of the TCP record the transport frames and writes.
const FRAME: &str = "tcp request frame";

/// Bytes of the record mark in front of the request.
const MARK: usize = 4;

/// Larger than any loopback socket buffering, so a peer that stops reading stalls the write.
const STALLING_REQUEST: usize = 1 << 26;

/// A completed exchange erases the framed request, record mark included.
#[tokio::test]
async fn framed_request_is_erased_after_success() -> Result<(), TestError> {
    // Given a peer that answers one framed request.
    let request = b"request-allocation-canary";
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let peer = async {
        let (mut stream, _) = listener.accept().await?;
        let mut received = vec![0; request.len().saturating_add(MARK)];
        let _: usize = stream.read_exact(&mut received).await?;
        stream.write_all(&[0, 0, 0, 3]).await?;
        stream.write_all(b"abc").await?;
        Ok::<_, TestError>(received)
    };
    let transport = Tokio::new();
    ERASED.with_borrow_mut(Vec::clear);
    // When the real transport exchanges it.
    let (received, response) = tokio::join!(peer, transport.send_tcp(address, request));
    // Then the peer saw the record and the whole frame was erased.
    assert_eq!(response?, b"abc");
    let mut expected = vec![0, 0, 0, 25];
    expected.extend_from_slice(request);
    assert_eq!(received?, expected);
    ERASED.with_borrow(|events| {
        assert_eq!(
            events.as_slice(),
            [(FRAME, request.len().saturating_add(MARK))]
        );
    });
    Ok(())
}

/// A write that fails on a closed peer still erases the framed request.
#[tokio::test]
async fn framed_request_is_erased_after_io_failure() -> Result<(), TestError> {
    // Given a peer that closes the connection without reading.
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let peer = async {
        let (stream, _) = listener.accept().await?;
        drop(stream);
        Ok::<_, TestError>(())
    };
    let request = vec![0x5a; STALLING_REQUEST];
    let transport = Tokio::new();
    ERASED.with_borrow_mut(Vec::clear);
    // When the transport writes a request that cannot fit.
    let (peer_result, response) = tokio::join!(peer, transport.send_tcp(address, &request));
    // Then the stream failed and the frame was erased on that exit.
    peer_result?;
    assert!(matches!(response, Err(ClientError::Io(_))), "{response:?}");
    ERASED.with_borrow(|events| {
        assert_eq!(
            events.as_slice(),
            [(FRAME, STALLING_REQUEST.saturating_add(MARK))]
        );
    });
    Ok(())
}

/// Dropping the future in the middle of the write erases the framed request.
#[tokio::test]
async fn framed_request_is_erased_after_cancellation() -> Result<(), TestError> {
    // Given a peer that reads one byte and then stops, so the write stalls.
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let (started, stalled) = oneshot::channel();
    let peer = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let _: u8 = stream.read_u8().await?;
        started
            .send(stream)
            .map_err(|_stream| "test dropped the receiver")?;
        Ok::<_, TestError>(())
    });
    let request = vec![0x5a; STALLING_REQUEST];
    let transport = Tokio::new();
    ERASED.with_borrow_mut(Vec::clear);
    // When the exchange is dropped once the peer has seen the first byte.
    let stream = tokio::select! {
        stream = stalled => stream?,
        response = transport.send_tcp(address, &request) => {
            return Err(format!("the stalled write finished: {response:?}").into());
        }
    };
    // Then the frame was erased by the drop, with the peer still connected.
    ERASED.with_borrow(|events| {
        assert_eq!(
            events.as_slice(),
            [(FRAME, STALLING_REQUEST.saturating_add(MARK))]
        );
    });
    drop(stream);
    peer.await??;
    Ok(())
}

/// The kpasswd encoding stages and both frames are erased, on both raw entry points.
#[tokio::test]
async fn kpasswd_request_frames_are_erased_after_failure() -> Result<(), TestError> {
    // Given a kpasswd request.
    let request = Request::parse(&hex::decode(
        include_str!("../../../../tests/fixtures/kpasswd-request.hex").trim(),
    )?)?;
    let encoded = request.encode()?;
    let length = encoded.len();
    let [_, _, _, _, high, low, ..] = encoded.as_slice() else {
        return Err("encoded request shorter than its header".into());
    };
    let ap_req_length = usize::from(u16::from_be_bytes([*high, *low]));
    let transport = Tokio::new();
    for configured in [false, true] {
        // And a peer that reads it and then closes.
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let peer = async {
            let (mut stream, _) = listener.accept().await?;
            let mut received = vec![0; length.saturating_add(MARK)];
            let _: usize = stream.read_exact(&mut received).await?;
            Ok::<_, TestError>(())
        };
        let config = Config::parse(&format!(
            "[libdefaults]\n dns_lookup_kdc = false\n[realms]\n TEST.GOKRB5 = {{\n kpasswd_server = {address}\n }}\n"
        ))?;
        ERASED.with_borrow_mut(Vec::clear);
        // When the real raw exchange sends it, directly or through the configuration.
        let (peer_result, response) = if configured {
            tokio::join!(
                peer,
                transport.exchange_kpasswd_request_with_config(
                    &config,
                    KdcProtocol::Tcp,
                    "TEST.GOKRB5",
                    &request
                )
            )
        } else {
            tokio::join!(
                peer,
                transport.exchange_kpasswd_request(KdcProtocol::Tcp, address, &request)
            )
        };
        // Then the reply never arrived and both owners were erased.
        peer_result?;
        assert!(
            matches!(response, Err(ClientError::KpasswdOutcomeUnknown(_))),
            "{response:?}"
        );
        ERASED.with_borrow(|events| {
            assert_eq!(
                events.as_slice(),
                [
                    (
                        "kpasswd krb-priv",
                        length.saturating_sub(6).saturating_sub(ap_req_length)
                    ),
                    ("kpasswd ap-req", ap_req_length),
                    (FRAME, length.saturating_add(MARK)),
                    ("kpasswd request frame", length),
                ],
                "configured: {configured}"
            );
        });
    }
    Ok(())
}
