//! The wire format: request bytes against frames SSSD 2.10.1 accepted live
//! (recorded in `task-12-rskrb5-ng-parity.log`), reply decoding and the
//! reply size limit.

use core::{array, error, fmt::Write as _, str};
use std::io::{self, Cursor, Read, Write};

use rskrb5_ng::{
    ccache::{
        CCache, Credential, CredentialTimes, EncryptionKey, HeaderField, Principal,
        kcm::{
            client::Client,
            wire::{
                self, MAX_REPLY_SIZE, Opcode, Reply, Residual, Uuid,
                calls::{self, Call},
                shape::{Credentials, DefaultPrincipal, Empty, KdcOffset, Name, Shape as _, Uuids},
            },
        },
    },
    error::Kcm as Error,
};
use zeroize::Zeroizing;

/// Error type of the `Result`-returning tests.
type TestError = Box<dyn error::Error>;

/// The name every golden frame uses.
fn name() -> Result<Residual, TestError> {
    Residual::new("0:777").ok_or_else(|| "name".into())
}

/// `alice@TEST.RSKRB5`.
fn alice() -> Principal {
    Principal::new("TEST.RSKRB5", 1, vec!["alice".to_owned()])
}

/// A TGT of `alice` with a recognizable key and ticket.
fn credential() -> Credential {
    let mut times = CredentialTimes::default();
    times.auth_time = 1000;
    times.start_time = 1000;
    times.end_time = 2_000_000_000;
    Credential::new(
        alice(),
        Principal::new(
            "TEST.RSKRB5",
            1,
            vec!["krbtgt".to_owned(), "TEST.RSKRB5".to_owned()],
        ),
        EncryptionKey::new(18, (0..32).collect::<Vec<u8>>()),
        times,
        [0x40, 0xe0, 0, 0],
        b"TKT".to_vec().into(),
    )
}

/// The frame of `call` as lowercase hex.
fn frame<T>(call: &Call<T>) -> Result<String, TestError> {
    let mut hex = String::new();
    for byte in call.request().frame()?.iter() {
        write!(hex, "{byte:02x}")?;
    }
    Ok(hex)
}

/// The principal `alice@TEST.RSKRB5`, version 4 encoding.
const PRINCIPAL: &str = "00000001000000010000000b544553542e52534b52423500000005616c696365";
/// The credential of [`credential`], version 4 encoding.
const CREDENTIAL: &str = "00000001000000010000000b544553542e52534b52423500000005616c69636500000001000000020000000b544553542e52534b524235000000066b72627467740000000b544553542e52534b524235001200000020000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f000003e8000003e877359400000000000040e00000000000000000000000000003544b5400000000";
/// The cache name `0:777`, zero-terminated.
const NAME: &str = "303a37373700";

/// Each request encodes to the bytes a real daemon accepted.
#[test]
fn requests_match_the_frames_sssd_accepted() -> Result<(), TestError> {
    let name = name()?;
    let uuid = Uuid::new(array::from_fn(|index| u8::try_from(index).unwrap_or(0_u8)));
    let uuid_hex = "000102030405060708090a0b0c0d0e0f";
    assert_eq!(frame(&calls::get_default_cache())?, "0000000402000014");
    assert_eq!(
        frame(&calls::get_principal(&name))?,
        format!("0000000a02000008{NAME}")
    );
    assert_eq!(
        frame(&calls::initialize(&name, &alice())?)?,
        format!("0000002a02000004{NAME}{PRINCIPAL}")
    );
    assert_eq!(
        frame(&calls::store(&name, &credential())?)?,
        format!("000000a802000006{NAME}{CREDENTIAL}")
    );
    assert_eq!(
        frame(&calls::set_kdc_offset(&name, -5))?,
        format!("0000000e02000017{NAME}fffffffb")
    );
    assert_eq!(
        frame(&calls::get_cache_by_uuid(uuid))?,
        format!("0000001402000013{uuid_hex}")
    );
    assert_eq!(
        frame(&calls::get_cred_by_uuid(&name, uuid))?,
        format!("0000001a0200000a{NAME}{uuid_hex}")
    );
    assert_eq!(
        frame(&calls::get_cred_list(&name))?,
        format!("0000000a020032c9{NAME}")
    );
    assert_eq!(
        frame(&calls::destroy(&name))?,
        format!("0000000a02000005{NAME}")
    );
    assert_eq!(
        frame(&calls::set_default_cache(&name))?,
        format!("0000000a02000015{NAME}")
    );
    assert_eq!(frame(&calls::gen_new())?, "0000000402000003");
    Ok(())
}

/// `REPLACE` carries the KDC offset of the header, the principal and the
/// counted credentials.
#[test]
fn replace_carries_offset_principal_and_counted_credentials() -> Result<(), TestError> {
    let mut cache = CCache::new(alice());
    cache.credentials_mut().push(credential());
    cache.header_mut().fields.push(HeaderField::new(
        1,
        [0xff, 0xff, 0xff, 0xfb, 0, 0, 0, 0].to_vec(),
    )?);
    assert_eq!(
        frame(&calls::replace(&name()?, &cache)?)?,
        format!("000000d4020032ca{NAME}fffffffb{PRINCIPAL}000000010000009e{CREDENTIAL}")
    );
    Ok(())
}

/// A reply frame of the daemon: transport code, then body.
fn reply(opcode: Opcode, transport: i32, body: &[u8]) -> Result<Reply, Error> {
    Reply::from_frame(opcode, transport, Zeroizing::new(body.to_vec()))
}

/// A body of `status` followed by `payload`.
fn body(status: i32, payload: &[u8]) -> Vec<u8> {
    let mut bytes = status.to_be_bytes().to_vec();
    bytes.extend_from_slice(payload);
    bytes
}

/// A daemon status, in either position, is the error of the request.
#[test]
fn status_codes_become_daemon_errors() {
    let nofile = -1_765_328_189_i32;
    assert!(matches!(
        reply(Opcode::GetPrincipal, nofile, &[]),
        Err(Error::Daemon { opcode: 8, code }) if code == nofile
    ));
    assert!(matches!(
        reply(Opcode::GetPrincipal, 0, &body(nofile, &[])),
        Err(Error::Daemon { opcode: 8, code }) if code == nofile
    ));
    assert!(matches!(
        reply(Opcode::GetPrincipal, 0, &[0, 0, 0]),
        Err(Error::MalformedReply { opcode: 8, what: _ })
    ));
    assert!(wire::is_unsupported(&Error::Daemon {
        opcode: 13_002,
        code: -1_765_328_188_i32
    }));
    assert!(!wire::is_unsupported(&Error::Daemon {
        opcode: 8,
        code: nofile
    }));
}

/// Each decoder accepts its shape and refuses malformed ones.
#[test]
fn replies_decode_strictly() -> Result<(), TestError> {
    let named = reply(Opcode::GetDefaultCache, 0, &body(0, b"0:84974\0"))?;
    assert_eq!(Name::decode(&named)?.as_str(), "0:84974");
    for payload in [&b"no-terminator"[..], b"a\0b\0", b"trailing\0x", b"\xff\0"] {
        let bad = reply(Opcode::GetDefaultCache, 0, &body(0, payload))?;
        assert!(matches!(
            Name::decode(&bad),
            Err(Error::MalformedReply {
                opcode: 20,
                what: _
            })
        ));
    }
    let listed = reply(Opcode::GetCacheUuidList, 0, &body(0, &[7; 32]))?;
    assert_eq!(Uuids::decode(&listed)?.len(), 2);
    let ragged = reply(Opcode::GetCacheUuidList, 0, &body(0, &[7; 17]))?;
    assert!(matches!(
        Uuids::decode(&ragged),
        Err(Error::MalformedReply {
            opcode: 18,
            what: _
        })
    ));
    assert_eq!(
        KdcOffset::decode(&reply(Opcode::GetKdcOffset, 0, &body(0, &[]))?)?,
        None
    );
    assert_eq!(
        KdcOffset::decode(&reply(Opcode::GetKdcOffset, 0, &body(0, &[0_u8, 0, 0, 5]))?)?,
        Some(5_i32)
    );
    assert!(matches!(
        Empty::decode(&reply(Opcode::Destroy, 0, &body(0, &[1]))?),
        Err(Error::MalformedReply { opcode: 5, what: _ })
    ));
    Ok(())
}

/// A counted credential list as a reply to `GET_CRED_LIST`.
fn counted(count: u32, entries: &[u8]) -> Result<Reply, Error> {
    reply(
        Opcode::GetCredList,
        0,
        &body(0, &[&count.to_be_bytes()[..], entries].concat()),
    )
}

/// Whether `bytes` fail to decode as a credential list.
fn list_refused(bytes: Result<Reply, Error>) -> Result<bool, TestError> {
    Ok(matches!(
        Credentials::decode(&bytes?),
        Err(Error::MalformedReply {
            opcode: 13_001,
            what: _
        })
    ))
}

/// A principal, a credential and a credential list decode; a count larger
/// than the payload, a truncated entry and trailing bytes do not.
#[test]
fn principals_and_credentials_decode_strictly() -> Result<(), TestError> {
    let (principal, credential_bytes) = (hex(PRINCIPAL), hex(CREDENTIAL));
    let principal_reply = |payload: &[u8]| reply(Opcode::GetPrincipal, 0, &body(0, payload));
    assert_eq!(
        DefaultPrincipal::decode(&principal_reply(&principal)?)?,
        Some(alice())
    );
    assert_eq!(DefaultPrincipal::decode(&principal_reply(&[])?)?, None);
    let trailing = [principal, vec![0_u8]].concat();
    assert!(matches!(
        DefaultPrincipal::decode(&principal_reply(&trailing)?),
        Err(Error::MalformedReply { opcode: 8, what: _ })
    ));
    let entry = [
        &u32::try_from(credential_bytes.len())?.to_be_bytes()[..],
        &credential_bytes,
    ]
    .concat();
    let listed = Credentials::decode(&counted(1, &entry)?)?;
    assert_eq!(listed, [credential()]);
    assert!(list_refused(counted(u32::MAX, &entry))?);
    assert!(list_refused(counted(2, &entry))?);
    let truncated = entry.split_last().map_or(&[][..], |(_last, rest)| rest);
    assert!(list_refused(counted(1, truncated))?);
    assert!(list_refused(counted(1, &[entry, vec![0_u8]].concat()))?);
    Ok(())
}

/// Hex text as bytes.
fn hex(text: &str) -> Vec<u8> {
    text.as_bytes()
        .chunks(2)
        .filter_map(|pair| u8::from_str_radix(str::from_utf8(pair).ok()?, 16).ok())
        .collect()
}

/// A stream that serves a fixed reply and counts the bytes it hands out.
struct Counting {
    /// The bytes to serve.
    reply: Cursor<Vec<u8>>,
    /// How many bytes were read.
    served: usize,
}

impl Read for Counting {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let read = self.reply.read(buf)?;
        self.served = self.served.saturating_add(read);
        Ok(read)
    }
}

impl Write for Counting {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// A reply longer than the limit is refused after its four length bytes:
/// nothing is read for the body and nothing is allocated for it.
#[test]
fn an_oversized_reply_is_rejected_before_the_body_is_read() -> Result<(), TestError> {
    let over = u32::try_from(MAX_REPLY_SIZE)?.saturating_add(1);
    for announced in [over, u32::MAX] {
        let mut frame = announced.to_be_bytes().to_vec();
        frame.extend_from_slice(&[0_u8; 64]);
        let mut client = Client::new(Counting {
            reply: Cursor::new(frame),
            served: 0,
        });
        let outcome = client.call(&calls::get_default_cache());
        assert!(
            matches!(outcome, Err(Error::ReplyTooBig { length, limit }) if length == announced && limit == MAX_REPLY_SIZE)
        );
        assert_eq!(client.stream_mut().served, 4);
        assert!(client.is_broken());
        assert!(matches!(
            client.call(&calls::get_default_cache()),
            Err(Error::Broken)
        ));
    }
    let mut limited = Client::new(Counting {
        reply: Cursor::new(vec![0_u8, 0, 4, 1]),
        served: 0,
    })
    .with_reply_limit(1024);
    assert!(matches!(
        limited.call(&calls::get_default_cache()),
        Err(Error::ReplyTooBig {
            length: 1025,
            limit: 1024
        })
    ));
    assert_eq!(wire::reply_length([0_u8, 0, 0, 0], 8)?, 0_usize);
    Ok(())
}
