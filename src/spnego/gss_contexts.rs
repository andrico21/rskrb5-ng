//! SPNEGO over the GSS Kerberos mechanism.
//!
//! SPNEGO (RFC 4178) over the GSS Kerberos mechanism: the negotiation tokens
//! wrap the [`crate::gss`] context tokens, and the `mechListMIC` is a GSS MIC of
//! the established context (MIT 1.22.2 `spnego_mech.c`, `handle_mic`).

use zeroize::Zeroizing;

use super::{
    AcceptStep, Acceptor, Error, Initiator, NegState, NegTokenInit, NegTokenResp, ObjectIdentifier,
    Token, ensure_kerberos_mechanism, negotiation, raw_krb5_negotiate_token,
};
use crate::{error::Gss as GssError, gss};

/// Decode a SPNEGO token, or wrap a raw Kerberos token in the SPNEGO shape.
///
/// # Errors
///
/// Returns the token decode errors.
fn decode(bytes: &[u8]) -> Result<Token, Error> {
    Token::decode(bytes).or_else(|spnego_error| raw_krb5_negotiate_token(bytes, spnego_error))
}

/// Verify the peer's `mechListMIC` over `list` with the context.
///
/// # Errors
///
/// Returns [`Error::InvalidMechListMic`] when it does not verify.
fn verify_mic(context: &mut gss::EstablishedContext, list: &[u8], mic: &[u8]) -> Result<(), Error> {
    context
        .verify_mic(list, mic)
        .map_err(|_invalid| Error::InvalidMechListMic)
}

/// One step of a SPNEGO [`Initiator`].
///
/// # Errors
///
/// Returns the errors of [`Initiator::init_sec_context`].
pub(super) fn initiate(
    spnego: &mut Initiator,
    credential: &gss::Credential,
    input: Option<&[u8]>,
) -> Result<gss::InitStep, GssError> {
    let Some(bytes) = input else {
        let (token, waiting) = match spnego.inner.init_sec_context(credential, None)? {
            gss::InitStep::Continue(token) => (token, true),
            gss::InitStep::Complete(Some(token)) => (token, false),
            gss::InitStep::Complete(None) => {
                return Err(GssError::UnexpectedStep(
                    "the mechanism sent no first token",
                ));
            }
        };
        let encoded = Token::Init(NegTokenInit::krb5(token)).encode()?;
        spnego.offered = Some(negotiation::received_mech_types(&encoded)?);
        return Ok(if waiting {
            gss::InitStep::Continue(encoded)
        } else {
            gss::InitStep::Complete(Some(encoded))
        });
    };
    let response = match decode(bytes)? {
        Token::Resp(response) => response,
        Token::Init(_) => {
            return Err(Error::WrongNegotiationToken {
                expected: "NegTokenResp",
                actual: "NegTokenInit",
            }
            .into());
        }
    };
    if response.neg_state != Some(NegState::AcceptCompleted) {
        return Err(Error::NegotiationRequiresState.into());
    }
    if let Some(mechanism) = &response.supported_mech
        && !mechanism.is_kerberos_mechanism()
    {
        return Err(Error::UnsupportedMechanism(mechanism.clone()).into());
    }
    let step = if spnego.inner.is_established() {
        gss::InitStep::Complete(None)
    } else {
        let token = response
            .response_token
            .as_ref()
            .map(|value| value.as_slice())
            .ok_or(Error::MissingApRep)?;
        spnego.inner.init_sec_context(credential, Some(token))?
    };
    if let Some(mic) = response
        .mech_list_mic
        .as_ref()
        .map(|value| value.as_slice())
    {
        let list = spnego
            .offered
            .as_deref()
            .ok_or(GssError::UnexpectedStep("no mechanism list was offered"))?;
        let context = spnego
            .inner
            .established_mut()
            .ok_or(GssError::UnexpectedStep("the context is not established"))?;
        verify_mic(context, list, mic)?;
    }
    Ok(step)
}

/// Accept `token` with the Kerberos acceptor and answer `accept-completed`,
/// exchanging MICs when the initiator sent one.
///
/// # Errors
///
/// Returns the errors of [`gss::Acceptor::accept_sec_context`] and
/// [`Error::InvalidMechListMic`].
fn complete(
    spnego: &mut Acceptor<'_>,
    token: &[u8],
    selected: ObjectIdentifier,
    mic: Option<(Vec<u8>, &[u8])>,
) -> Result<AcceptStep, GssError> {
    let mut accepted = spnego.inner.accept_sec_context(token)?;
    let mut response = NegTokenResp::accept_completed();
    response.supported_mech = Some(selected);
    response.response_token = accepted
        .output_token()
        .map(|reply| Zeroizing::new(reply.to_vec()));
    if let Some((list, received)) = mic {
        verify_mic(accepted.context_mut(), &list, received)?;
        response.mech_list_mic = Some(Zeroizing::new(accepted.context_mut().get_mic(&list)?));
    }
    let answer = response.encode()?;
    Ok(AcceptStep::Complete(Box::new(
        accepted.with_output_token(Some(answer)),
    )))
}

/// One step of a SPNEGO [`Acceptor`].
///
/// # Errors
///
/// Returns the errors of [`Acceptor::accept_sec_context`].
pub(super) fn accept(spnego: &mut Acceptor<'_>, bytes: &[u8]) -> Result<AcceptStep, GssError> {
    match decode(bytes)? {
        Token::Init(init) => {
            ensure_kerberos_mechanism(&init.mech_types)?;
            let selected = init
                .mech_types
                .iter()
                .find(|oid| oid.is_kerberos_mechanism())
                .cloned()
                .ok_or(Error::MissingMechTypes)?;
            let first = init
                .mech_types
                .first()
                .is_some_and(ObjectIdentifier::is_kerberos_mechanism);
            if init.mech_token.is_none() {
                let list = negotiation::received_mech_types(bytes)?;
                spnego.waiting = Some((list, selected.clone(), !first));
                let mut response = NegTokenResp::accept_incomplete_krb5();
                response.supported_mech = Some(selected);
                return Ok(AcceptStep::Continue(response.encode()?));
            }
            let _optimistic = negotiation::optimistic_token(&init)?;
            let token = init
                .mech_token
                .as_ref()
                .map(|value| value.as_slice())
                .ok_or(Error::MissingMechToken)?;
            let mic = match init.mech_list_mic.as_ref().map(|value| value.as_slice()) {
                Some(received) => Some((negotiation::received_mech_types(bytes)?, received)),
                None => None,
            };
            complete(spnego, token, selected, mic)
        }
        Token::Resp(response) => {
            let (list, selected, mic_required) = spnego
                .waiting
                .take()
                .ok_or(Error::NegotiationRequiresState)?;
            let token = response
                .response_token
                .as_ref()
                .map(|value| value.as_slice())
                .ok_or(Error::MissingMechToken)?;
            let mic = match response
                .mech_list_mic
                .as_ref()
                .map(|value| value.as_slice())
            {
                Some(received) => Some((list, received)),
                None if mic_required => return Err(Error::MissingMechListMic.into()),
                None => None,
            };
            complete(spnego, token, selected, mic)
        }
    }
}
