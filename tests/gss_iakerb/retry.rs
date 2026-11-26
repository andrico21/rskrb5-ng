//! The `KRB_ERR_RESPONSE_TOO_BIG` retry is the relay's duty.
//!
//! MIT's acceptor sends a relayed request again over TCP when the KDC answers
//! a datagram with `KRB_ERR_RESPONSE_TOO_BIG` (`iakerb.c:416-435`). Here the
//! application's [`KdcRelay`] owns the transport: it retries over a stream
//! (RFC 4120 section 7.2.1, the four-byte length of section 7.2.2), and the
//! library calls it once per request and never retries itself.

use std::io::{Cursor, Read as _, Write as _};

use rskrb5_ng::{
    gss::{
        InitiatorOptions,
        iakerb::{KdcRelay, RelayFailure},
    },
    krb_error,
};

use super::{
    context::TestError,
    kdc::Kdc,
    seal::REALM,
    support::{Setup, config, establish_under, password_credential, policy},
};

/// `KRB_ERR_RESPONSE_TOO_BIG`.
const RESPONSE_TOO_BIG: i32 = 52;

/// A relay whose datagram path is always too small, and which retries over a
/// stream when `retries`.
#[derive(Debug)]
struct Datagram<'kdc> {
    /// The KDC behind both paths.
    kdc: &'kdc Kdc,
    /// Whether it retries over the stream.
    retries: bool,
    /// The calls the acceptor made.
    calls: usize,
    /// The requests sent over the stream.
    streamed: usize,
}

impl Datagram<'_> {
    /// One request over the stream: a four-byte big-endian length and the
    /// message each way.
    fn stream(&mut self, realm: &str, request: &[u8]) -> Result<Vec<u8>, TestError> {
        self.streamed = self.streamed.saturating_add(1);
        let mut outbound = Cursor::new(Vec::new());
        outbound.write_all(&u32::try_from(request.len())?.to_be_bytes())?;
        outbound.write_all(request)?;
        let answer = self
            .kdc
            .answer(realm, &read_record(outbound.into_inner())?)?;
        let mut inbound = Cursor::new(Vec::new());
        inbound.write_all(&u32::try_from(answer.len())?.to_be_bytes())?;
        inbound.write_all(&answer)?;
        read_record(inbound.into_inner())
    }
}

/// The message of one length-prefixed record.
fn read_record(bytes: Vec<u8>) -> Result<Vec<u8>, TestError> {
    let mut reader = Cursor::new(bytes);
    let mut length = [0; 4];
    reader.read_exact(&mut length)?;
    let mut message = vec![0; usize::try_from(u32::from_be_bytes(length))?];
    reader.read_exact(&mut message)?;
    Ok(message)
}

impl KdcRelay for Datagram<'_> {
    fn relay(&mut self, realm: &str, request: &[u8]) -> Result<Vec<u8>, RelayFailure> {
        self.calls = self.calls.saturating_add(1);
        let failed = |cause: TestError| RelayFailure::Other(cause.to_string());
        let datagram_answer =
            Kdc::error(RESPONSE_TOO_BIG, (2_i32, &["krbtgt", REALM]), None).map_err(failed)?;
        let too_big = krb_error::decode(&datagram_answer)
            .is_ok_and(|error| error.error_code == RESPONSE_TOO_BIG);
        if too_big && self.retries {
            return self.stream(realm, request).map_err(failed);
        }
        Ok(datagram_answer)
    }
}

/// Establish a context through `relay`.
fn establish(relay: &mut Datagram<'_>) -> Result<(), TestError> {
    let setup = Setup {
        config: config()?,
        options: InitiatorOptions::new(),
        policy: policy()?,
        responder: None,
        relay: Some(relay),
    };
    establish_under(&password_credential(true)?, &Kdc::new(), setup).map(drop)
}

/// A relay that retries over a stream completes the context, called once per
/// request; one that hands back the error fails it, as the library does not
/// retry for it.
#[test]
fn iakerb_relay_retries_response_too_big_over_tcp() -> Result<(), TestError> {
    let kdc = Kdc::new();
    // Given a relay whose datagrams are always too big for the answer,
    let mut retrying = Datagram {
        kdc: &kdc,
        retries: true,
        calls: 0,
        streamed: 0,
    };
    // when it retries over a stream, the context completes,
    establish(&mut retrying)?;
    // with one call per relayed request (two AS, one TGS), each streamed,
    assert_eq!((retrying.calls, retrying.streamed), (3, 3));
    assert_eq!(kdc.log().len(), 3);
    // and a relay that returns the error ends the context at the first request.
    let mut passing = Datagram {
        kdc: &kdc,
        retries: false,
        calls: 0,
        streamed: 0,
    };
    assert!(establish(&mut passing).is_err());
    assert_eq!((passing.calls, passing.streamed), (1, 0));
    Ok(())
}
