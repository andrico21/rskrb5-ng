//! Message operations of an established context, checked in both directions.
//!
//! The initiator and the acceptor are adapter peers (MIT on both ends); a
//! tampered token, message or associated data must fail, so a no-op cannot pass.

use core::error::Error;
use std::net::TcpStream;

use super::{Established, is_gss_error};
use crate::peer::{Peer, PrfKey, reply::Protection};

/// The message every operation protects.
const MESSAGE: &[u8] = b"interop message of the mit-peer fixture";

/// Data that is signed but not encrypted.
const SIGN_ONLY: &[u8] = b"sign-only header data";

/// Associated data of the AEAD wrap.
const ASSOCIATED: &[u8] = b"associated data";

/// MIC tokens verify in both directions and a changed message does not.
fn mic(
    initiator: &mut Peer<TcpStream>,
    acceptor: &mut Peer<TcpStream>,
    pair: &Established,
) -> Result<(), Box<dyn Error>> {
    let forward = initiator.get_mic(pair.init_ctx, MESSAGE)?;
    assert_eq!(
        acceptor.verify_mic(pair.accept_ctx, MESSAGE, &forward)?,
        0,
        "the acceptor verifies the initiator's MIC with QOP 0"
    );
    let backward = acceptor.get_mic(pair.accept_ctx, MESSAGE)?;
    assert_eq!(
        initiator.verify_mic(pair.init_ctx, MESSAGE, &backward)?,
        0,
        "the initiator verifies the acceptor's MIC with QOP 0"
    );
    let tampered = initiator.get_mic(pair.init_ctx, MESSAGE)?;
    assert!(
        is_gss_error(&acceptor.verify_mic(pair.accept_ctx, b"another message", &tampered)),
        "a MIC over another message must not verify"
    );
    assert_eq!(
        acceptor.verify_mic(pair.accept_ctx, MESSAGE, &tampered)?,
        0,
        "the same token verifies over the right message, so the failure was the message"
    );
    Ok(())
}

/// Wrap and unwrap with and without confidentiality, both directions, plus a
/// flipped token byte.
fn wrap(
    initiator: &mut Peer<TcpStream>,
    acceptor: &mut Peer<TcpStream>,
    pair: &Established,
) -> Result<(), Box<dyn Error>> {
    for confidential in [true, false] {
        let sealed = initiator.wrap(pair.init_ctx, Protection::new(confidential), MESSAGE)?;
        assert_eq!(
            sealed.confidential(),
            confidential,
            "the wrap reports the protection it applied"
        );
        let plain = acceptor.unwrap(pair.accept_ctx, sealed.token())?;
        assert_eq!(
            (plain.message(), plain.confidential()),
            (MESSAGE, confidential),
            "the acceptor recovers the message and the protection"
        );
        let back = acceptor.wrap(pair.accept_ctx, Protection::new(confidential), MESSAGE)?;
        assert_eq!(
            initiator.unwrap(pair.init_ctx, back.token())?.message(),
            MESSAGE,
            "the initiator recovers the acceptor's message"
        );
    }
    let sealed = initiator.wrap(pair.init_ctx, Protection::new(true), MESSAGE)?;
    let mut flipped = sealed.token().to_vec();
    if let Some(byte) = flipped.last_mut() {
        *byte ^= 1;
    }
    assert!(
        is_gss_error(&acceptor.unwrap(pair.accept_ctx, &flipped)),
        "a wrap token with a flipped byte must not unwrap"
    );
    assert_eq!(
        acceptor.unwrap(pair.accept_ctx, sealed.token())?.message(),
        MESSAGE,
        "the unflipped token unwraps, so the failure was the flipped byte"
    );
    Ok(())
}

/// IOV wrap with sign-only data: encrypted in place, and the sign-only data is bound.
fn iov(
    initiator: &mut Peer<TcpStream>,
    acceptor: &mut Peer<TcpStream>,
    pair: &Established,
) -> Result<(), Box<dyn Error>> {
    let sealed = initiator.wrap_iov(pair.init_ctx, Protection::new(true), (MESSAGE, SIGN_ONLY))?;
    let (_header, data, _padding, _trailer) = sealed.buffers();
    assert_ne!(data, MESSAGE, "the IOV data buffer is encrypted in place");
    assert_eq!(
        acceptor
            .unwrap_iov(pair.accept_ctx, &sealed, SIGN_ONLY)?
            .message(),
        MESSAGE,
        "the acceptor recovers the IOV data"
    );
    let bound = initiator.wrap_iov(pair.init_ctx, Protection::new(true), (MESSAGE, SIGN_ONLY))?;
    assert!(
        is_gss_error(&acceptor.unwrap_iov(pair.accept_ctx, &bound, b"other sign-only data")),
        "changed sign-only data must not unwrap"
    );
    assert_eq!(
        acceptor
            .unwrap_iov(pair.accept_ctx, &bound, SIGN_ONLY)?
            .message(),
        MESSAGE,
        "the same buffers unwrap with the right sign-only data"
    );
    let clear = acceptor.wrap_iov(pair.accept_ctx, Protection::new(false), (MESSAGE, b""))?;
    assert_eq!(
        clear.buffers().1,
        MESSAGE,
        "without confidentiality the IOV data stays in the clear"
    );
    assert_eq!(
        initiator.unwrap_iov(pair.init_ctx, &clear, b"")?.message(),
        MESSAGE,
        "the initiator verifies the integrity-only IOV"
    );
    Ok(())
}

/// AEAD wrap binds the associated data.
fn aead(
    initiator: &mut Peer<TcpStream>,
    acceptor: &mut Peer<TcpStream>,
    pair: &Established,
) -> Result<(), Box<dyn Error>> {
    let sealed =
        initiator.wrap_aead(pair.init_ctx, Protection::new(true), (ASSOCIATED, MESSAGE))?;
    assert_eq!(
        acceptor
            .unwrap_aead(pair.accept_ctx, ASSOCIATED, sealed.token())?
            .message(),
        MESSAGE,
        "the acceptor recovers the AEAD message"
    );
    let bound = initiator.wrap_aead(pair.init_ctx, Protection::new(true), (ASSOCIATED, MESSAGE))?;
    assert!(
        is_gss_error(&acceptor.unwrap_aead(
            pair.accept_ctx,
            b"other associated data",
            bound.token()
        )),
        "changed associated data must not unwrap"
    );
    assert_eq!(
        acceptor
            .unwrap_aead(pair.accept_ctx, ASSOCIATED, bound.token())?
            .message(),
        MESSAGE,
        "the same token unwraps with the right associated data"
    );
    Ok(())
}

/// Both ends derive byte-identical pseudo-random output, which depends on the input.
fn prf(
    initiator: &mut Peer<TcpStream>,
    acceptor: &mut Peer<TcpStream>,
    pair: &Established,
) -> Result<(), Box<dyn Error>> {
    for key in [PrfKey::Full, PrfKey::Partial] {
        let theirs = initiator.pseudo_random(pair.init_ctx, key, (b"prf input", 48))?;
        let ours = acceptor.pseudo_random(pair.accept_ctx, key, (b"prf input", 48))?;
        assert_eq!(theirs.len(), 48, "the requested PRF length");
        assert_eq!(theirs, ours, "both ends derive the same {key:?} PRF output");
        let other = acceptor.pseudo_random(pair.accept_ctx, key, (b"another input", 48))?;
        assert_ne!(ours, other, "the PRF output depends on its input");
    }
    Ok(())
}

/// Runs every message operation in both directions; `with_aead` is false for a
/// DCE-style context, whose tokens MIT cannot unwrap as a stream (`EINVAL`).
///
/// A tampered input is always followed by the genuine one: a token that was never
/// accepted would leave a gap in the sequence numbers.
///
/// # Errors
///
/// Returns the adapter's error of a failed operation.
pub(super) fn exercise(
    initiator: &mut Peer<TcpStream>,
    acceptor: &mut Peer<TcpStream>,
    pair: &Established,
    with_aead: bool,
) -> Result<(), Box<dyn Error>> {
    mic(initiator, acceptor, pair)?;
    wrap(initiator, acceptor, pair)?;
    iov(initiator, acceptor, pair)?;
    if with_aead {
        aead(initiator, acceptor, pair)?;
    }
    prf(initiator, acceptor, pair)
}
