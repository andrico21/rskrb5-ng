//! The GSS pseudo-random function.
//!
//! `gss_pseudo_random` of RFC 4402 over the context key (MIT 1.22.2
//! `prf.c:34-139`): `GSS_C_PRF_KEY_FULL` takes the acceptor subkey when the
//! acceptor sent one, `GSS_C_PRF_KEY_PARTIAL` the initiator subkey; the stream
//! is the four-octet-counter `PRF+` of RFC 4402 section 2, never the one-octet
//! counter of RFC 6113.

use rskrb5_ng::{
    crypto::{
        KerberosEtype,
        prf::{self, Key},
    },
    error::Gss,
    gss::{ContextFlags, PrfKey},
};

use super::{
    context::{Context as _, TestError},
    support::{AES256_SHA384, establish, establish_with, sequenced},
};

/// Both ends derive the same bytes, for either key and any length.
#[test]
fn both_ends_derive_the_same_stream() -> Result<(), TestError> {
    let ends = establish(sequenced())?;
    for key in [PrfKey::Full, PrfKey::Partial] {
        for length in [0, 1, 16, 17, 100, 1024] {
            // Given the same input on both ends, when each derives `length` bytes,
            let ours = ends.initiator.pseudo_random(key, b"channel", length)?;
            let theirs = ends.acceptor.pseudo_random(key, b"channel", length)?;
            // then the streams agree and have the asked length.
            assert_eq!(ours.as_slice(), theirs.as_slice());
            assert_eq!(ours.len(), length);
        }
    }
    Ok(())
}

/// `GSS_C_PRF_KEY_FULL` uses the acceptor subkey, so it differs from the
/// partial key under mutual authentication and equals it without.
#[test]
fn the_full_key_is_the_acceptor_subkey() -> Result<(), TestError> {
    let mutual = establish(sequenced())?;
    let full = mutual.initiator.pseudo_random(PrfKey::Full, b"x", 32)?;
    let partial = mutual.initiator.pseudo_random(PrfKey::Partial, b"x", 32)?;
    assert_ne!(full.as_slice(), partial.as_slice());
    // Without mutual authentication there is no acceptor subkey.
    let single = establish(ContextFlags::CONF | ContextFlags::INTEG)?;
    let full = single.acceptor.pseudo_random(PrfKey::Full, b"x", 32)?;
    let partial = single.acceptor.pseudo_random(PrfKey::Partial, b"x", 32)?;
    assert_eq!(full.as_slice(), partial.as_slice());
    Ok(())
}

/// The stream is RFC 4402 `PRF+` over the context key: for the full key that
/// is the key `session_key` reports, for AES-SHA1 and AES-SHA2 alike.
#[test]
fn the_stream_is_rfc_4402_prf_plus() -> Result<(), TestError> {
    for ends in [
        establish(sequenced())?,
        establish_with(AES256_SHA384, sequenced(), &Default::default())?,
    ] {
        let key = ends.initiator.session_key();
        let etype = KerberosEtype::from_etype_id(key.etype()).context("known enctype")?;
        let expected = prf::gss_prf_plus(&Key::new(etype, key.value()), b"input", 77)?;
        let actual = ends.initiator.pseudo_random(PrfKey::Full, b"input", 77)?;
        assert_eq!(actual.as_slice(), expected.as_slice());
        // The RFC 6113 one-octet-counter expansion is a different stream.
        let fast = prf::fast_prf_plus(&Key::new(etype, key.value()), b"input", 77)?;
        assert_ne!(actual.as_slice(), fast.as_slice());
    }
    Ok(())
}

/// An output above the `PRF+` bound is refused, not truncated.
#[test]
fn an_oversized_output_is_refused() -> Result<(), TestError> {
    let ends = establish(sequenced())?;
    let refused =
        ends.initiator
            .pseudo_random(PrfKey::Full, b"x", prf::GSS_PRF_PLUS_MAX_OUTPUT + 1);
    assert!(matches!(refused, Err(Gss::Crypto(_))));
    Ok(())
}
