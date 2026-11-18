//! Message commands against a scripted stream.

use core::error::Error;

use super::{peer, reply, written};
use crate::peer::{PrfKey, frame::encode_request, reply::Protection, types::ContextHandle};

/// MIC, wrap, IOV, AEAD, PRF, export and import carry their documented fields.
#[test]
fn message_commands_carry_their_fields() -> Result<(), Box<dyn Error>> {
    let ctx = ContextHandle::new(1);
    let mut client = peer(&[
        reply(0, &[b"mic"]),
        reply(0, &[&[0, 0, 0, 0]]),
        reply(0, &[&[1], b"tok"]),
        reply(0, &[&[1], &[0, 0, 0, 0], b"msg"]),
        reply(0, &[&[1], b"hdr", b"dat", b"", b"trl"]),
        reply(0, &[&[1], &[0, 0, 0, 0], b"msg"]),
        reply(0, &[&[0], b"aead"]),
        reply(0, &[&[0], &[0, 0, 0, 0], b"msg"]),
        reply(0, &[b"prf-output"]),
        reply(0, &[b"exported"]),
        reply(0, &[&[0, 0, 0, 2]]),
    ]);
    assert_eq!(client.get_mic(ctx, b"msg")?, b"mic", "the MIC token");
    assert_eq!(client.verify_mic(ctx, b"msg", b"mic")?, 0, "the QOP");
    let sealed = client.wrap(ctx, Protection::new(true), b"msg")?;
    assert_eq!(
        (sealed.confidential(), sealed.token()),
        (true, &b"tok"[..]),
        "the wrap token"
    );
    let plain = client.unwrap(ctx, b"tok")?;
    assert_eq!(
        (plain.confidential(), plain.qop(), plain.message()),
        (true, 0, &b"msg"[..]),
        "the unwrapped message"
    );
    let iov = client.wrap_iov(ctx, Protection::new(true), (b"msg", b"sign"))?;
    assert_eq!(
        (iov.confidential(), iov.buffers()),
        (true, (&b"hdr"[..], &b"dat"[..], &b""[..], &b"trl"[..])),
        "the IOV buffers"
    );
    assert_eq!(
        client.unwrap_iov(ctx, &iov, b"sign")?.message(),
        b"msg",
        "the IOV message"
    );
    let aead = client.wrap_aead(ctx, Protection::new(false), (b"assoc", b"msg"))?;
    assert!(!aead.confidential(), "integrity only");
    assert_eq!(
        client.unwrap_aead(ctx, b"assoc", b"aead")?.message(),
        b"msg",
        "the AEAD message"
    );
    assert_eq!(
        client.pseudo_random(ctx, PrfKey::Partial, (b"in", 10))?,
        b"prf-output",
        "the PRF output"
    );
    assert_eq!(
        client.export_context(ctx)?,
        b"exported",
        "the exported token"
    );
    assert_eq!(
        client.import_context(b"exported")?,
        ContextHandle::new(2),
        "the imported handle"
    );
    let handle = [0, 0, 0, 1];
    assert_eq!(
        written(&client),
        [
            encode_request(b'm', &[&handle, &[0; 4], b"msg"])?,
            encode_request(b'v', &[&handle, b"msg", b"mic"])?,
            encode_request(b'w', &[&handle, &[1], &[0; 4], b"msg"])?,
            encode_request(b'u', &[&handle, b"tok"])?,
            encode_request(b'W', &[&handle, &[1], &[0; 4], b"msg", b"sign"])?,
            encode_request(b'U', &[&handle, b"hdr", b"sign", b"dat", b"", b"trl"])?,
            encode_request(b'a', &[&handle, &[0], &[0; 4], b"assoc", b"msg"])?,
            encode_request(b'b', &[&handle, b"assoc", b"aead"])?,
            encode_request(b'p', &[&handle, &[0, 0, 0, 1], b"in", &[0, 0, 0, 10]])?,
            encode_request(b'x', &[&handle])?,
            encode_request(b'y', &[b"exported"])?,
        ]
        .concat(),
        "command bytes and fields of the message commands"
    );
    Ok(())
}
