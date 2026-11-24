//! IOV and AEAD per-message tokens.
//!
//! `gss_wrap_iov`, `gss_unwrap_iov`, `gss_get_mic_iov`, `gss_verify_mic_iov`,
//! `gss_wrap_aead` and `gss_unwrap_aead` with the RFC 4121 section 4.2 layout
//! and MIT 1.22.2's buffer semantics (`k5sealv3iov.c:32-308`,
//! `k5unsealiov.c:275-600`, `util_crypt.c:418-524`): the token header and the
//! Kerberos confounder in the HEADER buffer, the filler, the encrypted header
//! copy and the integrity tag in the TRAILER buffer, or rotated into the HEADER
//! buffer by the RRC when there is no TRAILER; SIGN_ONLY buffers are protected
//! by the tag and sent in the clear. A token is a parser of attacker bytes: a
//! mutated header, a short trailer, a duplicated buffer type or an
//! inconsistent length is refused, and a refused token does not move the
//! sequence window.

use rskrb5_ng::{
    crypto::CryptoPolicy,
    error::Gss,
    gss::{IovBuffer, IovKind},
};

use super::{
    context::{Context as _, TestError},
    support::{AES128_SHA1, AES256_SHA384, Pair, establish, establish_with, refused, sequenced},
};

/// The contexts every layout is tried on: AES256-SHA1, AES128-SHA1 and
/// AES256-SHA384.
fn contexts() -> Result<Vec<Pair>, TestError> {
    let policy = CryptoPolicy::default();
    Ok(vec![
        establish(sequenced())?,
        establish_with(AES128_SHA1, sequenced(), &policy)?,
        establish_with(AES256_SHA384, sequenced(), &policy)?,
    ])
}

/// A buffer of `kind` holding `bytes`.
fn buffer(kind: IovKind, bytes: &[u8]) -> IovBuffer {
    IovBuffer::new(kind, bytes.to_vec())
}

/// The value of the buffer at `index`.
fn value(buffers: &[IovBuffer], index: usize) -> Vec<u8> {
    buffers
        .get(index)
        .map_or_else(Vec::new, |buffer| buffer.value().to_vec())
}

/// `HEADER | SIGN_ONLY | DATA | PADDING | TRAILER`, with an empty header,
/// padding and trailer for the mechanism to fill.
fn detached(data: &[u8]) -> Vec<IovBuffer> {
    vec![
        IovBuffer::empty(IovKind::Header),
        buffer(IovKind::SignOnly, b"associated header"),
        buffer(IovKind::Data, data),
        IovBuffer::empty(IovKind::Padding),
        IovBuffer::empty(IovKind::Trailer),
    ]
}

/// Sealed and integrity-only IOV tokens with a TRAILER round-trip in both
/// directions; the sign-only buffer stays in the clear and the data is
/// encrypted only when confidentiality is asked for.
#[test]
fn iov_tokens_with_a_trailer_round_trip() -> Result<(), TestError> {
    for mut ends in contexts()? {
        for confidential in [true, false] {
            let mut buffers = detached(b"the payload of the message");
            // Given a wrapped IOV array,
            let sealed = ends.initiator.wrap_iov(&mut buffers, confidential)?;
            assert_eq!(sealed, confidential);
            assert_eq!(value(&buffers, 1), b"associated header");
            assert_eq!(
                value(&buffers, 2) != b"the payload of the message",
                confidential
            );
            // when the acceptor unwraps it, the data is restored.
            let opened = ends.acceptor.unwrap_iov(&mut buffers)?;
            assert_eq!(opened, confidential);
            assert_eq!(value(&buffers, 2), b"the payload of the message");
            // And the acceptor's tokens unwrap at the initiator.
            let mut back = detached(b"reply");
            assert_eq!(
                ends.acceptor.wrap_iov(&mut back, confidential)?,
                confidential
            );
            assert_eq!(ends.initiator.unwrap_iov(&mut back)?, confidential);
            assert_eq!(value(&back, 2), b"reply");
        }
    }
    Ok(())
}

/// Without a TRAILER the trailer is rotated into the HEADER (RRC), and
/// HEADER | DATA is exactly the token `wrap` would send: `unwrap` opens it, and
/// a `wrap` token opens through a STREAM buffer.
#[test]
fn rotated_iov_tokens_are_ordinary_wrap_tokens() -> Result<(), TestError> {
    for mut ends in contexts()? {
        for confidential in [true, false] {
            let mut buffers = vec![
                IovBuffer::empty(IovKind::Header),
                buffer(IovKind::Data, b"rotated"),
            ];
            assert_eq!(
                ends.initiator.wrap_iov(&mut buffers, confidential)?,
                confidential
            );
            let token = [value(&buffers, 0), value(&buffers, 1)].concat();
            let opened = ends.acceptor.unwrap(&token)?;
            assert_eq!(opened.message(), b"rotated");
            assert_eq!(opened.confidential(), confidential);
            // The other way: a wrap token through STREAM and DATA buffers.
            let streamed = ends.acceptor.wrap(b"streamed", confidential)?;
            let mut stream = vec![
                buffer(IovKind::Stream, &streamed),
                IovBuffer::empty(IovKind::Data),
            ];
            assert_eq!(ends.initiator.unwrap_iov(&mut stream)?, confidential);
            assert_eq!(value(&stream, 1), b"streamed");
        }
    }
    Ok(())
}

/// `wrap_iov_length` sizes the header, padding and trailer as `wrap_iov`
/// fills them.
#[test]
fn iov_lengths_match_the_wrapped_buffers() -> Result<(), TestError> {
    for mut ends in contexts()? {
        for confidential in [true, false] {
            let mut sized = detached(b"sized data");
            assert_eq!(
                ends.initiator.wrap_iov_length(&mut sized, confidential)?,
                confidential
            );
            let mut wrapped = detached(b"sized data");
            assert_eq!(
                ends.initiator.wrap_iov(&mut wrapped, confidential)?,
                confidential
            );
            for (length, filled) in sized.iter().zip(&wrapped) {
                assert_eq!(length.value().len(), filled.value().len());
            }
        }
    }
    Ok(())
}

/// A MIC over IOV buffers covers the `DATA` and `SIGN_ONLY` buffers in order and
/// equals a plain MIC over their concatenation.
#[test]
fn iov_mics_cover_the_buffers_in_order() -> Result<(), TestError> {
    for mut ends in contexts()? {
        let mut buffers = vec![
            buffer(IovKind::Data, b"one "),
            buffer(IovKind::SignOnly, b"two "),
            buffer(IovKind::Data, b"three"),
            IovBuffer::empty(IovKind::MicToken),
        ];
        ends.initiator.get_mic_iov(&mut buffers)?;
        ends.acceptor.verify_mic_iov(&buffers)?;
        // The same MIC verifies as an ordinary MIC over the concatenation.
        let mut next = vec![
            buffer(IovKind::Data, b"one two three"),
            IovBuffer::empty(IovKind::MicToken),
        ];
        ends.initiator.get_mic_iov(&mut next)?;
        ends.acceptor
            .verify_mic(b"one two three", &value(&next, 1))?;
        // A reordered buffer list is another message.
        let mic = ends.initiator.get_mic(b"one two three")?;
        let swapped = vec![
            buffer(IovKind::Data, b"three"),
            buffer(IovKind::Data, b"one two "),
            buffer(IovKind::MicToken, &mic),
        ];
        refused(ends.acceptor.verify_mic_iov(&swapped))?;
    }
    Ok(())
}

/// AEAD tokens authenticate the associated data, which is not sent.
#[test]
fn aead_tokens_authenticate_the_associated_data() -> Result<(), TestError> {
    for mut ends in contexts()? {
        for confidential in [true, false] {
            let token = ends
                .initiator
                .wrap_aead(b"associated", b"secret", confidential)?;
            let opened = ends.acceptor.unwrap_aead(&token, b"associated")?;
            assert_eq!(opened.message(), b"secret");
            assert_eq!(opened.confidential(), confidential);
            // Other associated data is refused.
            let second = ends
                .initiator
                .wrap_aead(b"associated", b"secret", confidential)?;
            refused(ends.acceptor.unwrap_aead(&second, b"other data"))?;
            // and the refusal did not consume the sequence number.
            let again = ends.acceptor.unwrap_aead(&second, b"associated")?;
            assert_eq!(again.message(), b"secret");
        }
    }
    Ok(())
}

/// A mutated header, data, sign-only buffer or trailer, a short trailer, a
/// duplicated buffer type and inconsistent lengths are refused, and the
/// window still admits the intact token afterwards.
#[test]
fn mutated_and_inconsistent_iov_tokens_are_refused() -> Result<(), TestError> {
    for mut ends in contexts()? {
        for confidential in [true, false] {
            let mut good = detached(b"protected data");
            assert_eq!(
                ends.initiator.wrap_iov(&mut good, confidential)?,
                confidential
            );
            let mutate = |index: usize, offset: usize| -> Vec<IovBuffer> {
                good.iter()
                    .enumerate()
                    .map(|(at, item)| {
                        let mut bytes = item.value().to_vec();
                        if at == index
                            && let Some(byte) = bytes.get_mut(offset)
                        {
                            *byte ^= 0x01;
                        }
                        IovBuffer::new(item.kind(), bytes)
                    })
                    .collect()
            };
            // Mutated header fields, data, sign-only data and trailer.
            for (index, offset) in [(0, 2), (0, 4), (0, 9), (0, 15), (1, 0), (2, 0), (4, 0)] {
                let mut bad = mutate(index, offset);
                refused(ends.acceptor.unwrap_iov(&mut bad))
                    .context(&format!("{index}/{offset}"))?;
            }
            // A short trailer.
            let mut short = mutate(9, 0);
            if let Some(trailer) = short.get_mut(4) {
                let bytes = trailer.value();
                *trailer = IovBuffer::new(
                    IovKind::Trailer,
                    bytes
                        .get(..bytes.len().saturating_sub(1))
                        .unwrap_or_default()
                        .to_vec(),
                );
            }
            refused(ends.acceptor.unwrap_iov(&mut short))?;
            // A header that is too long.
            let mut long = mutate(9, 0);
            if let Some(header) = long.get_mut(0) {
                *header = IovBuffer::new(IovKind::Header, [header.value(), &[0]].concat());
            }
            refused(ends.acceptor.unwrap_iov(&mut long))?;
            // A duplicated header or trailer.
            for kind in [IovKind::Header, IovKind::Trailer, IovKind::Padding] {
                let mut doubled = mutate(9, 0);
                doubled.push(IovBuffer::empty(kind));
                refused(ends.acceptor.unwrap_iov(&mut doubled))?;
                let mut wrap = detached(b"x");
                wrap.push(IovBuffer::empty(kind));
                refused(ends.initiator.wrap_iov(&mut wrap, confidential))?;
            }
            // No header at all.
            let mut headless = mutate(9, 0);
            drop(headless.remove(0));
            refused(ends.acceptor.unwrap_iov(&mut headless))?;
            // The intact token still unwraps: no refusal moved the window.
            let mut intact = mutate(9, 0);
            assert_eq!(ends.acceptor.unwrap_iov(&mut intact)?, confidential);
            assert_eq!(value(&intact, 2), b"protected data");
        }
    }
    Ok(())
}

/// A STREAM unwrap needs exactly one DATA buffer, and a STREAM that is too
/// short or carries a bad rotation is refused.
#[test]
fn defective_streams_are_refused() -> Result<(), TestError> {
    for mut ends in contexts()? {
        let token = ends.initiator.wrap(b"streamed", true)?;
        let mut two_data = vec![
            buffer(IovKind::Stream, &token),
            IovBuffer::empty(IovKind::Data),
            IovBuffer::empty(IovKind::Data),
        ];
        refused(ends.acceptor.unwrap_iov(&mut two_data))?;
        let mut no_data = vec![buffer(IovKind::Stream, &token)];
        refused(ends.acceptor.unwrap_iov(&mut no_data))?;
        for cut in [0, 1, 15, 16, 31] {
            let mut short = vec![
                buffer(IovKind::Stream, token.get(..cut).unwrap_or_default()),
                IovBuffer::empty(IovKind::Data),
            ];
            refused(ends.acceptor.unwrap_iov(&mut short))?;
        }
        let mut intact = vec![
            buffer(IovKind::Stream, &token),
            IovBuffer::empty(IovKind::Data),
        ];
        assert!(ends.acceptor.unwrap_iov(&mut intact)?);
    }
    Ok(())
}

/// Every small layout of attacker buffers is refused or accepted without a
/// panic: random bytes in every combination of buffer kinds.
#[test]
fn arbitrary_buffer_layouts_never_panic() -> Result<(), TestError> {
    let mut ends = establish(sequenced())?;
    let kinds = [
        IovKind::Empty,
        IovKind::Data,
        IovKind::Header,
        IovKind::MechParams,
        IovKind::Trailer,
        IovKind::Padding,
        IovKind::Stream,
        IovKind::SignOnly,
        IovKind::MicToken,
    ];
    let mut seed = 0x9e37_79b9_u32;
    for round in 0..2000_usize {
        let mut buffers = Vec::new();
        for slot in 0..round.wrapping_rem(5) {
            seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            let kind = kinds
                .get(
                    usize::try_from(seed >> 28_u32)
                        .unwrap_or(0)
                        .wrapping_rem(kinds.len()),
                )
                .copied()
                .unwrap_or(IovKind::Data);
            let length = usize::try_from(seed.wrapping_rem(96))
                .unwrap_or(0)
                .saturating_add(slot);
            let bytes: Vec<u8> = (0..length)
                .map(|at| {
                    u8::try_from((usize::try_from(seed).unwrap_or(0) ^ at) & 0xff_usize)
                        .unwrap_or(0)
                })
                .collect();
            buffers.push(IovBuffer::new(kind, bytes));
        }
        drop(ends.acceptor.unwrap_iov(&mut buffers.clone()));
        drop(ends.acceptor.verify_mic_iov(&buffers));
        drop(
            ends.initiator
                .wrap_iov(&mut buffers.clone(), round.wrapping_rem(2) == 0),
        );
        drop(ends.initiator.get_mic_iov(&mut buffers));
    }
    // A refused layout reports a GSS error, not a crypto panic.
    let mut nothing: Vec<IovBuffer> = Vec::new();
    assert!(matches!(
        ends.acceptor.unwrap_iov(&mut nothing),
        Err(Gss::BadIov(_))
    ));
    Ok(())
}
