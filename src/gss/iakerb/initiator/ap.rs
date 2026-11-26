//! The AP exchange of the IAKERB initiator.
//!
//! It is the krb5 mechanism's, with the transcript in its extension record (MIT `iakerb_initiator_step` hands
//! `krb5_gss_init_sec_context_ext` the conversation, `iakerb.c:1028-1045`), so
//! the AP-REQ carries the `IAKERB-FINISHED` and both tokens the IAKERB frame.

use super::{
    super::{AP_REP_TOKEN_ID, Error, unframe},
    Phase, State, acquired,
};
use crate::{
    ap_rep,
    client::TgsRepSession,
    error::Gss,
    gss::{
        ContextFlags, Credential, InitStep,
        checksum::Extensions,
        initiator::{self, Pending},
    },
};

/// The AP-REQ with `ticket`, carrying the finished checksum of the transcript.
///
/// A requested delegation carries the forwardable TGT of `credential` or the
/// one the AS exchange acquired, through the krb5 mechanism's delegation.
///
/// # Errors
///
/// Returns [`Gss::NotNegotiated`] for a DCE-style request, and the policy,
/// delegation, checksum and AP-REQ errors.
pub(super) fn ap_request(
    state: &mut State,
    credential: &Credential,
    ticket: TgsRepSession,
) -> Result<InitStep, Error> {
    if state.options.flags().contains(ContextFlags::DCE_STYLE) {
        return Err(Gss::NotNegotiated("DCE-style establishment").into());
    }
    let holding = acquired::holding(state, credential)?;
    let (token, pending) = initiator::request(
        &state.options,
        (holding.as_ref().unwrap_or(credential), ticket),
        Extensions::iakerb(state.conversation.transcript()),
    )?;
    if pending.awaits_reply() {
        state.phase = Phase::Reply(Box::new(pending));
        return Ok(InitStep::Continue(token));
    }
    state.phase = Phase::Established(Box::new(pending.into_context()));
    Ok(InitStep::Complete(Some(token)))
}

/// The acceptor's AP-REP: verify it and complete the context.
///
/// # Errors
///
/// Returns [`Error::UnexpectedStep`] for another token, and the AP-REP
/// decoding, decryption, policy and echo errors.
pub(super) fn reply(state: &mut State, pending: Pending, token: &[u8]) -> Result<InitStep, Error> {
    let (id, body) = unframe(token)?;
    if id != AP_REP_TOKEN_ID {
        return Err(Error::UnexpectedStep(
            "the acceptor did not answer with an AP-REP",
        ));
    }
    let wire = ap_rep::decode(body)?;
    let (context, step) = initiator::complete(pending, &wire)?;
    state.phase = Phase::Established(Box::new(context));
    Ok(step)
}
