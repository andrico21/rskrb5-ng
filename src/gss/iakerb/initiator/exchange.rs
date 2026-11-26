//! The relayed AS and TGS exchanges of the IAKERB initiator.
//!
//! Each request goes out as a proxy token and each reply comes back in one
//! (MIT `iakerb_initiator_step`, `iakerb.c:571-706`); a prompt of the AS
//! exchange goes to the caller's responder.

use core::mem;
use std::time::{SystemTime, UNIX_EPOCH};

use super::{
    super::{Error, Token},
    Phase, Sources, State, acquired,
    ap::ap_request,
};
use crate::{
    client::{
        AsRepSession, Password,
        principal::Principal,
        stepwise::{ExchangeStep, InitCreds, Outbound, StepInput, TicketCreds},
    },
    error::{Client, Gss},
    gss::{InitStep, cred},
    krb_error,
};

/// `KRB_AP_ERR_IAKERB_KDC_NOT_FOUND`.
const KDC_NOT_FOUND: i32 = 85;
/// `KRB_AP_ERR_IAKERB_KDC_NO_RESPONSE`.
const KDC_NO_RESPONSE: i32 = 86;

/// Choose where to enter the exchanges once the client's realm is known.
///
/// A cached service ticket needs no relay, a cached TGT only the TGS exchange
/// (MIT `iakerb_get_initial_state`, `iakerb.c:713-772`). Without a password
/// or a client keytab, the responder is asked for the password.
///
/// # Errors
///
/// Returns [`Error::Gss`] without a ticket source, and the exchange errors.
pub(super) fn begin(state: &mut State, sources: &mut Sources<'_>) -> Result<InitStep, Error> {
    let credential = sources.credential;
    if let Some(ticket) = cred::service_ticket(credential, &state.target) {
        return ap_request(state, credential, ticket);
    }
    let client = state.client.clone().ok_or(Gss::NoCredential("no client"))?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(u64::MAX, |since| since.as_secs());
    let cached = credential.cache.as_ref().and_then(|cache| {
        let realm = &client.realm;
        cache
            .credentials()
            .iter()
            .find(|entry| {
                entry.server().components == ["krbtgt", realm.as_str()]
                    && entry.server().realm == *realm
                    && u64::from(entry.times().end_time) > now
            })
            .map(cred::session_of)
    });
    if let Some(tgt) = cached {
        return advance(
            state,
            sources,
            (
                Phase::Tgs(Box::new(ticket_creds(state, tgt)?)),
                StepInput::Start,
            ),
        );
    }
    let options = state.exchanges.0.clone();
    let exchange = if let Some(password) = &credential.password {
        InitCreds::with_password(client, Some(Password::from_vec(password.to_vec())), options)
    } else if let Some(keytab) = &credential.client_keytab {
        InitCreds::with_keytab(client, keytab.clone(), options)
    } else if sources.responder.is_some() {
        InitCreds::with_password(client, None, options)
    } else {
        return Err(Gss::NoCredential("no ticket source").into());
    };
    advance(
        state,
        sources,
        (Phase::As(Box::new(exchange)), StepInput::Start),
    )
}

/// The TGS exchange for the target with `tgt`.
///
/// # Errors
///
/// Returns the errors of [`TicketCreds::new`] and of reading the target.
fn ticket_creds(state: &State, tgt: AsRepSession) -> Result<TicketCreds, Error> {
    let components = cred::target_components(&state.target)?.to_vec();
    let service = Principal::new(
        state.target.principal().realm.clone(),
        state.target.principal().name_type,
        components,
    );
    Ok(TicketCreds::new(tgt, service, state.exchanges.1.clone())?)
}

/// Run the current exchange on `input` until it needs a KDC or finishes; a
/// prompt goes to the responder and its answer back into the exchange.
///
/// # Errors
///
/// Returns the exchange errors, [`Error::UnsupportedPrompt`] without a
/// responder and the responder's refusal as [`Error::Client`].
fn advance(
    state: &mut State,
    sources: &mut Sources<'_>,
    (mut phase, mut input): (Phase, StepInput<'_>),
) -> Result<InitStep, Error> {
    loop {
        match phase {
            Phase::As(mut exchange) => match exchange.step(input)? {
                ExchangeStep::Outbound(outbound) => {
                    state.phase = Phase::As(exchange);
                    return send(state, &outbound);
                }
                ExchangeStep::Complete(tgt) => {
                    acquired::keep(state, &tgt);
                    phase = Phase::Tgs(Box::new(ticket_creds(state, *tgt)?));
                    input = StepInput::Start;
                }
                ExchangeStep::Prompt(prompt) => {
                    let responder = sources
                        .responder
                        .as_deref_mut()
                        .ok_or(Error::UnsupportedPrompt)?;
                    input =
                        StepInput::Answer(responder.respond(&prompt).map_err(Client::Responder)?);
                    phase = Phase::As(exchange);
                }
            },
            Phase::Tgs(mut exchange) => match exchange.step(input)? {
                ExchangeStep::Outbound(outbound) => {
                    state.phase = Phase::Tgs(exchange);
                    return send(state, &outbound);
                }
                ExchangeStep::Complete(ticket) => {
                    acquired::keep(state, &ticket);
                    return ap_request(state, sources.credential, *ticket);
                }
                ExchangeStep::Prompt(_) => return Err(Error::UnsupportedPrompt),
            },
            Phase::Start
            | Phase::Discovery
            | Phase::Reply(_)
            | Phase::Established(_)
            | Phase::Done => return Err(Error::UnexpectedStep("no exchange is running")),
        }
    }
}

/// Send `outbound` as a proxy token, echoing the proxy's cookie.
///
/// # Errors
///
/// Returns the token and round-bound errors.
fn send(state: &mut State, outbound: &Outbound) -> Result<InitStep, Error> {
    let token = Token::new(
        outbound.realm(),
        state.cookie.clone(),
        outbound.message().to_vec(),
    )
    .encode()?;
    Ok(InitStep::Continue(state.conversation.produce(token)?))
}

/// The KRB-ERROR code of a proxy token's message, if it is one.
fn error_code(message: &[u8]) -> Option<i32> {
    (message.first() == Some(&0x7e))
        .then(|| krb_error::decode(message).ok())
        .flatten()
        .map(|error| error.error_code)
}

/// A proxy token from the acceptor: record it, then feed the exchange.
///
/// # Errors
///
/// Returns the token errors, the acceptor's IAKERB errors and the exchange errors.
pub(super) fn proxied(
    state: &mut State,
    sources: &mut Sources<'_>,
    token: &[u8],
) -> Result<InitStep, Error> {
    state.conversation.check_size(token.len())?;
    let parsed = Token::decode(token)?;
    state.conversation.append(token)?;
    let phase = mem::replace(&mut state.phase, Phase::Done);
    state.cookie = parsed.cookie().map(<[u8]>::to_vec);
    match error_code(parsed.message()) {
        Some(KDC_NOT_FOUND) => return Err(Error::KdcNotFound),
        Some(KDC_NO_RESPONSE) => return Err(Error::KdcNoResponse),
        Some(_) | None => {}
    }
    if matches!(phase, Phase::Discovery) {
        if parsed.realm().is_empty() {
            return Err(Error::BadToken("the acceptor sent no realm"));
        }
        let client = state
            .client
            .as_mut()
            .ok_or(Gss::NoCredential("no client"))?;
        parsed.realm().clone_into(&mut client.realm);
        return begin(state, sources);
    }
    if parsed.message().is_empty() {
        return Err(Error::BadToken("the acceptor sent no KDC message"));
    }
    advance(state, sources, (phase, StepInput::Reply(parsed.message())))
}
