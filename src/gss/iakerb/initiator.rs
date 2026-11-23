//! The IAKERB initiator.
//!
//! The initiator of MIT 1.22.2 `iakerb_initiator_step` (`iakerb.c:571-706`):
//! optional realm discovery, the AS exchange, the TGS exchange (each request
//! sent as a proxy token and each reply read from one), then the AP exchange
//! with the `IAKERB-FINISHED` of the transcript in the authenticator checksum
//! (`init_sec_context.c:313-345`).

use core::mem;
use std::time::{SystemTime, UNIX_EPOCH};

use super::{Error, Token, conversation::Conversation};
use crate::{
    client::{
        AsRepSession, Password,
        principal::Principal,
        stepwise::{
            ExchangeStep, InitCreds, InitCredsOptions, Outbound, StepInput, TicketCreds,
            TicketOptions,
        },
    },
    error::Gss,
    gss::{
        Credential, CredentialUsage, EstablishedContext, InitStep, InitiatorOptions, Name, cred,
    },
    krb_error,
};

mod ap;

use ap::{Pending, ap, reply};

/// `KRB_AP_ERR_IAKERB_KDC_NOT_FOUND`.
const KDC_NOT_FOUND: i32 = 85;
/// `KRB_AP_ERR_IAKERB_KDC_NO_RESPONSE`.
const KDC_NO_RESPONSE: i32 = 86;

/// Where the initiator is.
enum Phase {
    /// Nothing sent.
    Start,
    /// The acceptor's realm is awaited.
    Discovery,
    /// The AS exchange.
    As(Box<InitCreds<'static>>),
    /// The TGS exchange.
    Tgs(Box<TicketCreds>),
    /// The AP-REQ is sent; the AP-REP is awaited.
    Reply(Box<Pending>),
    /// Established.
    Established(Box<EstablishedContext>),
    /// A step failed or the context was taken.
    Done,
}

/// The initiator's state.
pub(super) struct State {
    /// The target.
    target: Name,
    /// The context options.
    options: InitiatorOptions,
    /// The AS and TGS options, from the profile.
    exchanges: (InitCredsOptions, TicketOptions),
    /// The client, its realm filled in by discovery.
    client: Option<Principal>,
    /// The proxy's newest cookie.
    cookie: Option<Vec<u8>>,
    /// The phase.
    phase: Phase,
    /// The tokens exchanged and their bounds.
    conversation: Conversation,
}

/// A new initiator state.
pub(super) const fn new(
    target: Name,
    options: InitiatorOptions,
    exchanges: (InitCredsOptions, TicketOptions),
) -> State {
    State {
        target,
        options,
        exchanges,
        client: None,
        cookie: None,
        phase: Phase::Start,
        conversation: Conversation::with_defaults(),
    }
}

impl State {
    /// Whether the context is established.
    pub(super) const fn is_established(&self) -> bool {
        matches!(self.phase, Phase::Established(_))
    }

    /// The established context.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnexpectedStep`] before the context is established.
    pub(super) fn into_established(self) -> Result<EstablishedContext, Error> {
        match self.phase {
            Phase::Established(context) => Ok(*context),
            Phase::Start
            | Phase::Discovery
            | Phase::As(_)
            | Phase::Tgs(_)
            | Phase::Reply(_)
            | Phase::Done => Err(Error::UnexpectedStep("the context is not established")),
        }
    }
}

/// One initiator step.
///
/// # Errors
///
/// Returns the errors of [`super::Context::init_sec_context`].
pub(super) fn step(
    state: &mut State,
    credential: &Credential,
    input: Option<&[u8]>,
) -> Result<InitStep, Error> {
    match (mem::replace(&mut state.phase, Phase::Done), input) {
        (Phase::Start, None) => start(state, credential),
        (Phase::Reply(pending), Some(token)) => reply(state, *pending, token),
        (phase @ (Phase::Discovery | Phase::As(_) | Phase::Tgs(_)), Some(token)) => {
            state.phase = phase;
            proxied(state, credential, token)
        }
        (phase, _) => {
            state.phase = phase;
            Err(Error::UnexpectedStep(
                "the initiator does not expect this input",
            ))
        }
    }
}

/// The first step: a discovery token, or the first request.
///
/// # Errors
///
/// Returns the errors of [`step`].
fn start(state: &mut State, credential: &Credential) -> Result<InitStep, Error> {
    if credential.usage == CredentialUsage::Accept {
        return Err(Gss::WrongCredentialUsage("initiate").into());
    }
    let _components: &[String] = cred::target_components(&state.target)?;
    let client = credential
        .name
        .as_ref()
        .map(|name| name.principal().clone())
        .ok_or(Gss::NoCredential("the credential names no client"))?;
    let known = !client.realm.is_empty();
    state.client = Some(client);
    if known {
        return begin(state, credential);
    }
    let token = state
        .conversation
        .produce(Token::new("", None, Vec::new()).encode()?)?;
    state.phase = Phase::Discovery;
    Ok(InitStep::Continue(token))
}

/// Choose where to enter the exchanges once the client's realm is known.
///
/// A cached service ticket needs no relay, a cached TGT only the TGS exchange
/// (MIT `iakerb_get_initial_state`, `iakerb.c:713-772`).
///
/// # Errors
///
/// Returns [`Error::Gss`] without a ticket source, and the exchange errors.
fn begin(state: &mut State, credential: &Credential) -> Result<InitStep, Error> {
    if let Some(ticket) = cred::service_ticket(credential, &state.target) {
        return ap(state, &ticket);
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
    } else {
        return Err(Gss::NoCredential("no ticket source").into());
    };
    advance(state, (Phase::As(Box::new(exchange)), StepInput::Start))
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

/// Run the current exchange on `input` until it needs a KDC or finishes.
///
/// # Errors
///
/// Returns the exchange errors and [`Error::UnsupportedPrompt`].
fn advance(
    state: &mut State,
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
                    phase = Phase::Tgs(Box::new(ticket_creds(state, *tgt)?));
                    input = StepInput::Start;
                }
                ExchangeStep::Prompt(_) => return Err(Error::UnsupportedPrompt),
            },
            Phase::Tgs(mut exchange) => match exchange.step(input)? {
                ExchangeStep::Outbound(outbound) => {
                    state.phase = Phase::Tgs(exchange);
                    return send(state, &outbound);
                }
                ExchangeStep::Complete(ticket) => return ap(state, &ticket),
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
fn proxied(state: &mut State, credential: &Credential, token: &[u8]) -> Result<InitStep, Error> {
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
        return begin(state, credential);
    }
    if parsed.message().is_empty() {
        return Err(Error::BadToken("the acceptor sent no KDC message"));
    }
    advance(state, (phase, StepInput::Reply(parsed.message())))
}
