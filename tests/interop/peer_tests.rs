//! Regressions of the adapter client against a scripted stream (no socket).
//!
//! They pin the frame layout against hard-coded bytes taken from the protocol
//! block of `peer.c`, then check that every command sends the command byte and
//! fields the protocol names and that every reply type decodes, so the module
//! that test files include has no unused item.

use core::error::Error;
use std::io::{self, Cursor, Read, Write};

use super::{
    Peer, PrfKey,
    cred::{CredRequest, Name, Usage},
    frame::{MAX_FRAME, encode_request, read_reply},
    types::{AcceptRequest, ContextHandle, InitRequest, PeerError},
};

/// A stream that replays canned reply bytes and records what is written.
#[derive(Debug)]
struct Scripted {
    /// The replies still to be read.
    replies: Cursor<Vec<u8>>,
    /// Everything written so far.
    written: Vec<u8>,
}

impl Read for Scripted {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.replies.read(buf)
    }
}

impl Write for Scripted {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.written.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// One reply frame: length, status, fields.
fn reply(status: u8, fields: &[&[u8]]) -> Vec<u8> {
    let mut payload = vec![status];
    for field in fields {
        payload.extend_from_slice(&u32::try_from(field.len()).unwrap_or(0).to_be_bytes());
        payload.extend_from_slice(field);
    }
    let mut frame = u32::try_from(payload.len())
        .unwrap_or(0)
        .to_be_bytes()
        .to_vec();
    frame.extend_from_slice(&payload);
    frame
}

/// A client that reads `replies` one after the other.
fn peer(replies: &[Vec<u8>]) -> Peer<Scripted> {
    Peer::new(Scripted {
        replies: Cursor::new(replies.concat()),
        written: Vec::new(),
    })
}

/// What the client wrote.
fn written(client: &Peer<Scripted>) -> &[u8] {
    &client.stream().written
}

/// Credential, step and inquire commands.
#[path = "peer_tests_steps.rs"]
mod steps;

/// Message commands.
#[path = "peer_tests_messages.rs"]
mod messages;

/// A request is the length, the command byte and the length-prefixed fields.
#[test]
fn request_frames_follow_the_documented_layout() -> Result<(), PeerError> {
    assert_eq!(
        encode_request(b'P', &[])?,
        [0, 0, 0, 1, b'P'],
        "a bare command"
    );
    assert_eq!(
        encode_request(b'm', &[b"ab", b""])?,
        [0, 0, 0, 11, b'm', 0, 0, 0, 2, b'a', b'b', 0, 0, 0, 0],
        "two fields, the second empty"
    );
    let too_many = vec![&b""[..]; 17];
    assert!(
        matches!(encode_request(b'm', &too_many), Err(PeerError::Limit(_))),
        "17 fields exceed the adapter's limit"
    );
    let huge = vec![0_u8; MAX_FRAME];
    assert!(
        matches!(encode_request(b'm', &[&huge]), Err(PeerError::Limit(_))),
        "a payload above 1 MiB is refused before it is sent"
    );
    Ok(())
}

/// A reply length of 0 or above 1 MiB, a short body and a cut-off field fail.
#[test]
fn reply_frames_outside_the_bounds_are_malformed() -> Result<(), PeerError> {
    assert_eq!(
        read_reply(&mut Cursor::new(vec![0, 0, 0, 2, 7, 9]))?,
        (7, vec![9]),
        "a well-formed reply splits into status and the bytes after it"
    );
    assert!(
        matches!(
            read_reply(&mut Cursor::new(vec![0, 0, 0, 0])),
            Err(PeerError::Malformed(_))
        ),
        "length 0"
    );
    assert!(
        matches!(
            read_reply(&mut Cursor::new(vec![0, 0x10, 0, 1])),
            Err(PeerError::Malformed(_))
        ),
        "length above 1 MiB"
    );
    assert!(
        matches!(
            read_reply(&mut Cursor::new(vec![0, 0, 0, 5, 0, 1, 2])),
            Err(PeerError::Io(_))
        ),
        "a body shorter than its length"
    );
    let mut client = peer(&[vec![0, 0, 0, 6, 0, 0, 0, 0, 9, 9]]);
    assert!(
        matches!(client.ping(), Err(PeerError::Malformed(_))),
        "a field that runs past the frame"
    );
    Ok(())
}

/// Status 2 and 3 become typed errors; an unknown status and a CONTINUE for a
/// step-less command are malformed.
#[test]
fn status_bytes_map_to_typed_errors() -> Result<(), PeerError> {
    let mut client = peer(&[
        reply(2, &[&[0, 0x0d, 0, 0], &[0, 0, 0, 7], b"no key"]),
        reply(3, &[b"unknown command"]),
        reply(9, &[]),
        reply(1, &[]),
        reply(0, &[]),
    ]);
    assert!(
        matches!(client.ping(), Err(PeerError::Gss { major, minor, text })
            if major == 0x000d_0000 && minor == 7 && text == "no key"),
        "status 2 carries major, minor and text"
    );
    assert!(
        matches!(client.ping(), Err(PeerError::Protocol(text)) if text == "unknown command"),
        "status 3 carries the text"
    );
    assert!(
        matches!(client.ping(), Err(PeerError::Malformed(_))),
        "an unknown status byte"
    );
    assert!(
        matches!(client.ping(), Err(PeerError::Malformed(_))),
        "ping has no steps"
    );
    client.set_env("HOPS", "1")?;
    Ok(())
}

/// `ping`, `mechs`, `set_env` and `trace`.
#[test]
fn session_commands_encode_and_decode() -> Result<(), Box<dyn Error>> {
    let mut client = peer(&[
        reply(
            0,
            &[
                b"rskrb5-peer/1",
                &[0, 0x10, 0, 0],
                &[0, 0, 0, 16],
                &[0, 0, 0, 16],
            ],
        ),
        reply(0, &[b"1.2.840.113554.1.2.2", b"1.3.6.1.5.5.2"]),
        reply(0, &[]),
        reply(0, &[b"NegoEx sending [0]"]),
    ]);
    let ping = client.ping()?;
    assert_eq!(
        (ping.version(), ping.limits()),
        ("rskrb5-peer/1", (0x10_0000, 16, 16)),
        "the ping reply"
    );
    assert_eq!(
        client.mechs()?,
        ["1.2.840.113554.1.2.2", "1.3.6.1.5.5.2"],
        "the mechanism list"
    );
    client.set_env("HOPS", "2")?;
    assert_eq!(client.trace()?, "NegoEx sending [0]", "the trace tail");
    assert_eq!(
        written(&client),
        [
            encode_request(b'P', &[])?,
            encode_request(b'M', &[])?,
            encode_request(b'E', &[b"HOPS", b"2"])?,
            encode_request(b'T', &[])?,
        ]
        .concat(),
        "command bytes and fields"
    );
    Ok(())
}

/// A password credential and an enterprise name travel as documented, and an
/// unnamed initiator step uses the defaults.
#[test]
fn password_credentials_and_default_steps_use_the_documented_fields() -> Result<(), PeerError> {
    let password = CredRequest::new(Usage::Initiate)
        .named(Name::enterprise("user"))
        .with_password(b"pw");
    assert_eq!(
        password.fields(),
        [
            b"i".to_vec(),
            b"e".to_vec(),
            b"user".to_vec(),
            Vec::new(),
            b"password".to_vec(),
            b"pw".to_vec()
        ],
        "a password credential"
    );
    assert_eq!(
        InitRequest::new(Name::default_name()).fields().len(),
        9,
        "an init step has nine fields"
    );
    assert_eq!(
        AcceptRequest::new(b"")
            .stepping(Some(ContextHandle::new(4)), b"next")
            .fields()
            .get(4)
            .map(Vec::as_slice),
        Some(&b"next"[..]),
        "a repeated accept step carries the new token"
    );
    let fields = password.fields();
    let borrowed: Vec<&[u8]> = fields.iter().map(Vec::as_slice).collect();
    assert_eq!(
        encode_request(b'A', &borrowed)?.get(4),
        Some(&b'A'),
        "a credential request frames as an A command"
    );
    Ok(())
}

/// The raw calls send unframed bytes and return the status and the bytes after it;
/// a full-key PRF request names key kind 0.
#[test]
fn raw_exchange_and_full_key_prf() -> Result<(), Box<dyn Error>> {
    let mut client = peer(&[reply(0, &[&[0, 0, 0, 9]]), reply(0, &[b"out"])]);
    let (status, body) = client.exchange_raw(&[0, 0, 0, 1, b'P'])?;
    assert_eq!(
        (status, body.len()),
        (0, 8),
        "the raw exchange returns the status and the field bytes"
    );
    assert_eq!(
        client.pseudo_random(ContextHandle::new(1), PrfKey::Full, (b"x", 1))?,
        b"out",
        "the full-key PRF"
    );
    assert_eq!(
        written(&client).get(..5),
        Some(&[0, 0, 0, 1, b'P'][..]),
        "the raw bytes went out unchanged"
    );
    Ok(())
}
