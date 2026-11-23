//! The GSS pseudo-random function.
//!
//! `gss_pseudo_random` (RFC 4401; the Kerberos mechanism's RFC 4402 `PRF+`;
//! MIT 1.22.2 `prf.c:34-139`): four-octet counters from zero over the
//! enctype's PRF of the chosen context key, never the one-octet RFC 6113
//! expansion.

use zeroize::Zeroizing;

use super::{Error, EstablishedContext, PrfKey, context};
use crate::crypto::{KerberosEtype, Use, prf};

/// `gss_pseudo_random`.
///
/// # Errors
///
/// Returns the errors of [`super::EstablishedContext::pseudo_random`].
pub(super) fn pseudo_random(
    context: &EstablishedContext,
    key: PrfKey,
    input: &[u8],
    length: usize,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    context::established(context)?;
    let partial = context
        .initiator_subkey
        .as_ref()
        .unwrap_or(&context.session_key);
    let chosen = match key {
        PrfKey::Full => context.acceptor_subkey.as_ref().unwrap_or(partial),
        PrfKey::Partial => partial,
    };
    context
        .crypto_policy
        .check_use(chosen.etype(), Use::SessionKey)?;
    let etype = KerberosEtype::from_etype_id(chosen.etype())
        .ok_or(Error::NotNegotiated("the context key's enctype has no PRF"))?;
    Ok(prf::gss_prf_plus(
        &prf::Key::new(etype, chosen.value()),
        input,
        length,
    )?)
}
