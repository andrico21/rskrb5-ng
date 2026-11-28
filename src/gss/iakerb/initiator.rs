//! The IAKERB initiator.
//!
//! The initiator of MIT 1.22.2 `iakerb_initiator_step` (`iakerb.c:571-706`):
//! optional realm discovery, the AS exchange, the TGS exchange (each request
//! sent as a proxy token and each reply read from one), then the AP exchange
//! with the `IAKERB-FINISHED` of the transcript in the authenticator checksum
//! (`init_sec_context.c:313-345`).

use core::mem;

use super::{Error, Token, conversation::Conversation};
use crate::{
    ccache::CCache,
    client::{
        principal::Principal,
        stepwise::{InitCreds, InitCredsOptions, Responder, TicketCreds, TicketOptions},
    },
    error::Gss,
    gss::{
        Credential, CredentialUsage, EstablishedContext, InitStep, InitiatorOptions, Name, cred,
        initiator::Pending,
    },
};

pub(super) mod acquired;
mod ap;
mod exchange;

use ap::reply;
use exchange::{begin, proxied};

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
    /// The tickets the AS and TGS exchanges acquired.
    acquired: Option<CCache>,
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
        acquired: None,
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

/// What a step draws on: the caller's credential and responder.
pub(super) struct Sources<'step> {
    /// The credential.
    credential: &'step Credential,
    /// The responder that answers the KDC's prompts, if any.
    responder: Option<&'step mut dyn Responder>,
}

impl<'step> Sources<'step> {
    /// The credential and, if given, the responder.
    pub(super) fn new(
        credential: &'step Credential,
        responder: Option<&'step mut dyn Responder>,
    ) -> Self {
        Self {
            credential,
            responder,
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
    sources: &mut Sources<'_>,
    input: Option<&[u8]>,
) -> Result<InitStep, Error> {
    match (mem::replace(&mut state.phase, Phase::Done), input) {
        (Phase::Start, None) => start(state, sources),
        (Phase::Reply(pending), Some(token)) => reply(state, *pending, token),
        (phase @ (Phase::Discovery | Phase::As(_) | Phase::Tgs(_)), Some(token)) => {
            state.phase = phase;
            proxied(state, sources, token)
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
fn start(state: &mut State, sources: &mut Sources<'_>) -> Result<InitStep, Error> {
    let credential = sources.credential;
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
        return begin(state, sources);
    }
    let token = state
        .conversation
        .produce(Token::new("", None, Vec::new()).encode()?)?;
    state.phase = Phase::Discovery;
    Ok(InitStep::Continue(token))
}
