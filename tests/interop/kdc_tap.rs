//! A recording relay between the client under test and a KDC (Y1-04).
//!
//! A scenario that names a pre-authentication mechanism must observe the exchange it ran, not
//! only what the KDC offered and the flags of the ticket it got. The client logs in against
//! the relay's endpoint, the relay forwards every request to the KDC unchanged and keeps the
//! PA-DATA types of every AS-REQ it forwarded, in order, so the scenario asserts that the
//! request the KDC answered with a TGT carried the mechanism (`assert_negotiated_padata`). Other
//! messages are forwarded and not recorded.

extern crate alloc;

use alloc::sync::Arc;
use core::time::Duration;
use std::{
    io,
    sync::{Mutex, PoisonError},
};

use rskrb5_ng::{client::transport::KdcProtocol, kdc_req::decode_as_req};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::{TcpListener, TcpStream, UdpSocket},
    task::{JoinHandle, JoinSet},
    time::timeout,
};

/// Longest a forwarded request waits for the KDC's answer.
const KDC_ANSWER: Duration = Duration::from_secs(10);

/// Longest message the relay forwards (the RFC 4120 TCP framing limit used by the client).
const MAX_MESSAGE: usize = 0x10_0000;

/// PA-DATA types of the AS-REQs forwarded so far, and the error that stopped the relay.
#[derive(Default)]
struct Seen {
    /// One entry per AS-REQ: the PA-DATA types it carried.
    requests: Vec<Vec<i32>>,
    /// The error that ended the relay task, when it ended with one.
    failure: Option<String>,
}

/// The shared record of a relay.
type Record = Arc<Mutex<Seen>>;

/// A relay that records the AS-REQs it forwards; dropping it stops the relay.
pub(crate) struct KdcTap {
    /// `host:port` the client connects to.
    endpoint: String,
    /// What the relay saw.
    seen: Record,
    /// The relay task.
    task: JoinHandle<()>,
}

impl KdcTap {
    /// Starts a relay on a free loopback port that forwards `protocol` messages to `upstream`.
    ///
    /// # Errors
    ///
    /// Returns the error of the bind, or `InvalidInput` for a protocol other than UDP and TCP.
    pub(crate) async fn start(protocol: KdcProtocol, upstream: &str) -> io::Result<Self> {
        let seen = Record::default();
        let (endpoint, task) = match protocol {
            KdcProtocol::Udp => {
                let front = UdpSocket::bind("127.0.0.1:0").await?;
                let endpoint = front.local_addr()?.to_string();
                (
                    endpoint,
                    tokio::spawn(run(
                        relay_udp(front, upstream.to_owned(), Arc::clone(&seen)),
                        Arc::clone(&seen),
                    )),
                )
            }
            KdcProtocol::Tcp => {
                let front = TcpListener::bind("127.0.0.1:0").await?;
                let endpoint = front.local_addr()?.to_string();
                (
                    endpoint,
                    tokio::spawn(run(
                        relay_tcp(front, upstream.to_owned(), Arc::clone(&seen)),
                        Arc::clone(&seen),
                    )),
                )
            }
            KdcProtocol::Auto | _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "the relay needs UDP or TCP",
                ));
            }
        };
        Ok(Self {
            endpoint,
            seen,
            task,
        })
    }

    /// The `host:port` the client under test must use as its KDC.
    pub(crate) fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// The PA-DATA types of every AS-REQ forwarded so far, in order.
    ///
    /// # Errors
    ///
    /// Returns the error that stopped the relay, so a relay failure is not mistaken for a
    /// client that sent no pre-authentication.
    pub(crate) fn as_req_padata(&self) -> io::Result<Vec<Vec<i32>>> {
        let seen = self.seen.lock().unwrap_or_else(PoisonError::into_inner);
        seen.failure.as_ref().map_or_else(
            || Ok(seen.requests.clone()),
            |failure| Err(io::Error::other(failure.clone())),
        )
    }
}

impl Drop for KdcTap {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Runs a relay and records the error it ends with.
async fn run(relay: impl Future<Output = io::Result<()>>, seen: Record) {
    if let Err(error) = relay.await {
        seen.lock().unwrap_or_else(PoisonError::into_inner).failure = Some(error.to_string());
    }
}

/// Records `message` when it is an AS-REQ.
fn record(seen: &Record, message: &[u8]) {
    if let Ok(request) = decode_as_req(message) {
        let types = request
            .0
            .padata
            .iter()
            .flatten()
            .map(|padata| padata.r#type)
            .collect();
        seen.lock()
            .unwrap_or_else(PoisonError::into_inner)
            .requests
            .push(types);
    }
}

/// Forwards each datagram of `front` to `upstream` and the answer back to its sender.
async fn relay_udp(front: UdpSocket, upstream: String, seen: Record) -> io::Result<()> {
    let back = UdpSocket::bind("127.0.0.1:0").await?;
    back.connect(&upstream).await?;
    let mut request = vec![0_u8; 0x1_0000];
    let mut answer = vec![0_u8; 0x1_0000];
    loop {
        let (length, client) = front.recv_from(&mut request).await?;
        let message = request.get(..length).unwrap_or_default();
        record(&seen, message);
        let _forwarded = back.send(message).await?;
        let received =
            timeout(KDC_ANSWER, back.recv(&mut answer))
                .await
                .map_err(|_elapsed| {
                    io::Error::new(io::ErrorKind::TimedOut, "the KDC did not answer")
                })??;
        let _returned = front
            .send_to(answer.get(..received).unwrap_or_default(), client)
            .await?;
    }
}

/// Accepts connections on `front` and relays each one on its own task.
async fn relay_tcp(front: TcpListener, upstream: String, seen: Record) -> io::Result<()> {
    let mut connections = JoinSet::new();
    loop {
        let (client, _peer) = front.accept().await?;
        let _abort = connections.spawn(relay_connection(
            client,
            upstream.clone(),
            Arc::clone(&seen),
        ));
    }
}

/// Relays one client connection and records the error it ends with before the client sees the
/// connection close.
async fn relay_connection(mut client: TcpStream, upstream: String, seen: Record) {
    if let Err(error) = relay_frames(&mut client, &upstream, &seen).await {
        seen.lock().unwrap_or_else(PoisonError::into_inner).failure = Some(error.to_string());
    }
}

/// Relays the length-prefixed messages of `client` until it closes.
async fn relay_frames(client: &mut TcpStream, upstream: &str, seen: &Record) -> io::Result<()> {
    let mut server = TcpStream::connect(upstream).await?;
    loop {
        let Some(request) = read_frame(client).await? else {
            return Ok(());
        };
        record(seen, &request);
        write_frame(&mut server, &request).await?;
        // A KDC that closes its end (MIT closes a TCP connection after some answers) ends the
        // relayed connection the same way; the client opens a new one for its next request.
        let Some(answer) = timeout(KDC_ANSWER, read_frame(&mut server))
            .await
            .map_err(|_elapsed| {
                io::Error::new(io::ErrorKind::TimedOut, "the KDC did not answer")
            })??
        else {
            return Ok(());
        };
        write_frame(client, &answer).await?;
    }
}

/// Reads one length-prefixed message, or `None` when the peer closed between messages.
async fn read_frame(stream: &mut TcpStream) -> io::Result<Option<Vec<u8>>> {
    let mut header = [0_u8; 4];
    match stream.read_exact(&mut header).await {
        Ok(_read) => {}
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error),
    }
    let length = usize::try_from(u32::from_be_bytes(header))
        .map_err(|_cause| io::Error::from(io::ErrorKind::InvalidData))?;
    if length > MAX_MESSAGE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "a message is longer than 1 MiB",
        ));
    }
    let mut message = vec![0_u8; length];
    let _read = stream.read_exact(&mut message).await?;
    Ok(Some(message))
}

/// Writes one length-prefixed message.
async fn write_frame(stream: &mut TcpStream, message: &[u8]) -> io::Result<()> {
    let length = u32::try_from(message.len())
        .map_err(|_cause| io::Error::from(io::ErrorKind::InvalidData))?;
    stream.write_all(&length.to_be_bytes()).await?;
    stream.write_all(message).await
}
