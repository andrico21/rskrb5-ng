//! Live KDC probe exchange implementation.

use rskrb5_ng::client::transport::kdc_tcp_record_length;

use super::*;

/// A diagnostic probe must not wait indefinitely for an untrusted peer.
pub(super) const PROBE_TIMEOUT: Duration = Duration::from_millis(200);

/// Send one bare AS-REQ on an existing stream and classify the outcome.
pub(super) async fn probe_exchange(
    stream: &mut TcpStream,
    realm: &str,
    user: &str,
    nonce: u32,
) -> Result<ProbeOutcome, TestError> {
    timeout(PROBE_TIMEOUT, exchange(stream, realm, user, nonce))
        .await
        .unwrap_or_else(|_| {
            Ok(ProbeOutcome::Closed(
                "probe deadline expired; discard stream".to_owned(),
            ))
        })
}

/// Exchange a bounded record within the caller's probe deadline.
async fn exchange(
    stream: &mut TcpStream,
    realm: &str,
    user: &str,
    nonce: u32,
) -> Result<ProbeOutcome, TestError> {
    let client = Principal::user(realm, user);
    let request = build_tgt_as_req(client, AsReq::new(SystemTime::now(), nonce))?;

    let mut framed = Vec::with_capacity(request.der.len().saturating_add(4));
    framed.extend_from_slice(&u32::try_from(request.der.len())?.to_be_bytes());
    framed.extend_from_slice(&request.der);
    if let Err(error) = stream.write_all(&framed).await {
        return Ok(ProbeOutcome::Closed(format!("write failed: {error}")));
    }

    let mut header = [0; 4];
    if let Err(error) = stream.read_exact(&mut header).await {
        return Ok(ProbeOutcome::Closed(format!(
            "no response length: {} ({error})",
            error.kind()
        )));
    }

    let length = match kdc_tcp_record_length(header, 0x0001_0000) {
        Ok(length) => length,
        Err(error) => {
            return Ok(ProbeOutcome::Closed(format!(
                "invalid record mark: {error}"
            )));
        }
    };
    let mut response = vec![0; length];
    if let Err(error) = stream.read_exact(&mut response).await {
        return Ok(ProbeOutcome::Closed(format!(
            "truncated response: {} ({error})",
            error.kind()
        )));
    }

    Ok(ProbeOutcome::Answered {
        len: response.len(),
        error_code: krb_error_code(&response),
    })
}

/// A peer that never answers cannot hold a live diagnostic probe forever.
#[test]
fn silent_probe_is_bounded() -> Result<(), TestError> {
    runtime()?.block_on(async {
        // Given a connected peer that consumes the request but sends no reply.
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let (connection, accepted) = tokio::join!(
            bounded(
                Duration::from_secs(10),
                "probe connection",
                TcpStream::connect(addr)
            ),
            bounded(Duration::from_secs(10), "probe accept", listener.accept())
        );
        let mut client = connection??;
        let (mut peer, _) = accepted??;
        let server = async {
            drop(read_framed(&mut peer).await?);
            Ok::<_, TestError>(())
        };
        // When the probe waits on a silent peer, an outer watchdog detects missing bounds.
        let probe = timeout(
            Duration::from_millis(500),
            probe_exchange(&mut client, "TEST.GOKRB5", "testuser1", 1),
        );
        let (received, result) = tokio::join!(server, probe);
        received?;
        // Then the probe's own deadline finishes before the watchdog.
        assert!(
            matches!(result, Ok(Ok(ProbeOutcome::Closed(_)))),
            "probe exceeded its own deadline"
        );
        Ok(())
    })
}

/// Hostile record marks are rejected before waiting for their declared bodies.
#[test]
fn hostile_probe_headers_are_bounded() -> Result<(), TestError> {
    runtime()?.block_on(async {
        for header in [0x8000_0001_u32, 0x0001_0001] {
            // Given a peer advertising a reserved-bit or oversized record.
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let (connection, accepted) = tokio::join!(
                bounded(Duration::from_secs(10), "hostile probe connection", TcpStream::connect(listener.local_addr()?)),
                bounded(Duration::from_secs(10), "hostile probe accept", listener.accept())
            );
            let mut client = connection??;
            let (mut peer, _) = accepted??;
            let server = async {
                drop(read_framed(&mut peer).await?);
                peer.write_all(&header.to_be_bytes()).await?;
                Ok::<_, TestError>(())
            };
            // When no body follows the hostile header.
            let (sent, outcome) = tokio::join!(server, probe_exchange(&mut client, "TEST.GOKRB5", "testuser1", 1));
            sent?;
            // Then framing fails without allocating or reading the claimed body.
            assert!(matches!(outcome?, ProbeOutcome::Closed(reason) if reason.starts_with("invalid record mark:")));
        }
        Ok(())
    })
}
