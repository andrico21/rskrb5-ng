//! Rust GSS-API II per-message calls against the MIT peer adapter.
//!
//! IOV and AEAD tokens both ways and byte-identical `gss_pseudo_random` output.

use core::error::Error;
use std::net::TcpStream;

use rskrb5_ng::gss::{EstablishedContext, IovBuffer, IovKind, PrfKey};

use self::support::{MIT_KDC, PEER, layout, mit_initiated, mit_unwrap_iov, part, rust_initiated};
use crate::{
    harness,
    peer::{
        self, Peer,
        reply::Protection,
        types::{ContextHandle, CredHandle},
    },
};

/// Helpers: fixture names, credentials, context pairs, raw adapter requests.
#[path = "support.rs"]
mod support;

/// DCE style, context transfer and delegation.
#[path = "legs.rs"]
mod legs;

/// Authentication indicators of the MIT KDC on the Rust acceptor.
#[path = "indicators.rs"]
mod indicators;

/// A Rust context and the adapter's context on the other end of it.
#[derive(Debug)]
pub(super) struct Pair {
    /// The Rust end.
    context: EstablishedContext,
    /// The adapter connection that holds the MIT end.
    adapter: Peer<TcpStream>,
    /// The MIT end's handle.
    handle: ContextHandle,
}

/// The reply of the adapter's `D` command: an accept step that keeps the
/// delegated credential (`scripts/interop/peer-mit/peer/peer_deleg.c`).
#[derive(Debug)]
pub(super) struct DelegAccept {
    /// The AP-REP.
    token: Vec<u8>,
    /// The `ret_flags`.
    flags: u32,
    /// The mechanism, dotted.
    mech: String,
    /// The authenticated initiator.
    source: String,
    /// The delegated credential's handle; `None` when nothing was delegated.
    delegated: Option<CredHandle>,
}

/// IOV tokens of both kinds, sealed and integrity-only, in both directions of
/// `pair`.
fn iov_both_ways(pair: &mut Pair) -> Result<(), Box<dyn Error>> {
    for confidential in [true, false] {
        // Rust wraps HEADER, SIGN_ONLY, DATA, PADDING, TRAILER; MIT unwraps.
        let mut ours = layout(b"rust sign-only header", b"rust iov payload");
        assert_eq!(
            pair.context.wrap_iov(&mut ours, confidential)?,
            confidential
        );
        let opened = mit_unwrap_iov(pair, &ours)?;
        assert_eq!(opened.message(), b"rust iov payload");
        assert_eq!(
            opened.confidential(),
            confidential,
            "MIT sees the protection"
        );
        // A changed SIGN_ONLY buffer fails MIT's checksum.
        let mut forged = ours.clone();
        if let Some(sign) = forged.get_mut(1) {
            *sign = IovBuffer::new(IovKind::SignOnly, b"another header".to_vec());
        }
        assert!(
            mit_unwrap_iov(pair, &forged).is_err(),
            "MIT refuses a token whose SIGN_ONLY data changed"
        );
        // MIT wraps; Rust unwraps the same layout.
        let sealed = pair.adapter.wrap_iov(
            pair.handle,
            Protection::new(confidential),
            (b"mit iov payload", b"mit sign-only header"),
        )?;
        assert_eq!(sealed.confidential(), confidential);
        let (header, data, padding, trailer) = sealed.buffers();
        let mut theirs = vec![
            IovBuffer::new(IovKind::Header, header.to_vec()),
            IovBuffer::new(IovKind::SignOnly, b"mit sign-only header".to_vec()),
            IovBuffer::new(IovKind::Data, data.to_vec()),
            IovBuffer::new(IovKind::Padding, padding.to_vec()),
            IovBuffer::new(IovKind::Trailer, trailer.to_vec()),
        ];
        assert_eq!(pair.context.unwrap_iov(&mut theirs)?, confidential);
        assert_eq!(part(&theirs, IovKind::Data), b"mit iov payload");
    }
    Ok(())
}

/// AEAD tokens both ways; MIT refuses other associated data.
fn aead_both_ways(pair: &mut Pair) -> Result<(), Box<dyn Error>> {
    for confidential in [true, false] {
        let token =
            pair.context
                .wrap_aead(b"rust associated", b"rust aead payload", confidential)?;
        // Under other associated data MIT refuses the token and keeps its
        // sequence state, so the same token then opens.
        assert!(
            pair.adapter
                .unwrap_aead(pair.handle, b"other associated", &token)
                .is_err(),
            "MIT refuses a token under other associated data"
        );
        let opened = pair
            .adapter
            .unwrap_aead(pair.handle, b"rust associated", &token)?;
        assert_eq!(opened.message(), b"rust aead payload");
        assert_eq!(
            opened.confidential(),
            confidential,
            "MIT sees the protection"
        );
        let sealed = pair.adapter.wrap_aead(
            pair.handle,
            Protection::new(confidential),
            (b"mit associated", b"mit aead payload"),
        )?;
        let unwrapped = pair
            .context
            .unwrap_aead(sealed.token(), b"mit associated")?;
        assert_eq!(unwrapped.message(), b"mit aead payload");
        assert_eq!(
            unwrapped.confidential(),
            confidential,
            "Rust sees the protection"
        );
    }
    Ok(())
}

/// The PRF output of both ends of `pair` for both keys and several lengths.
pub(super) fn prf_matches(pair: &mut Pair) -> Result<(), Box<dyn Error>> {
    let long = [0x5a_u8; 300];
    for (ours, theirs) in [
        (PrfKey::Full, peer::PrfKey::Full),
        (PrfKey::Partial, peer::PrfKey::Partial),
    ] {
        for (input, length) in [
            (b"".as_slice(), 1_u32),
            (b"rskrb5 prf".as_slice(), 44),
            (long.as_slice(), 200),
        ] {
            let rust = pair
                .context
                .pseudo_random(ours, input, usize::try_from(length)?)?;
            let mit = pair
                .adapter
                .pseudo_random(pair.handle, theirs, (input, length))?;
            assert_eq!(
                rust.as_slice(),
                mit.as_slice(),
                "{ours:?} {length} bytes: Rust and MIT agree"
            );
        }
    }
    Ok(())
}

/// Rust and MIT exchange IOV and AEAD tokens in both directions, with the
/// Rust end as initiator and as acceptor; MIT refuses changed `SIGN_ONLY` data
/// and other associated data.
#[test]
fn iov_and_aead_tokens_cross_between_rust_and_mit() -> Result<(), Box<dyn Error>> {
    if !harness::require(
        "iov_and_aead_tokens_cross_between_rust_and_mit",
        &[MIT_KDC, PEER],
    )? {
        return Ok(());
    }
    for mut pair in [rust_initiated()?, mit_initiated()?] {
        iov_both_ways(&mut pair)?;
        aead_both_ways(&mut pair)?;
    }
    Ok(())
}

/// `pseudo_random` (RFC 4402) gives the bytes MIT's `gss_pseudo_random`
/// gives, for the full and the partial key, on both context roles.
#[test]
fn pseudo_random_output_is_byte_identical_with_mit() -> Result<(), Box<dyn Error>> {
    if !harness::require(
        "pseudo_random_output_is_byte_identical_with_mit",
        &[MIT_KDC, PEER],
    )? {
        return Ok(());
    }
    for mut pair in [rust_initiated()?, mit_initiated()?] {
        prf_matches(&mut pair)?;
    }
    Ok(())
}
