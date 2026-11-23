//! `NegoEx` under SPNEGO (RFC 4178, MS-NEGOEX).
//!
//! The SPNEGO mechanism list is the `NegoEx` OID, the first mechanism token is
//! the `NegoEx` message run (`INITIATOR_NEGO`, meta-data, an optimistic
//! `AP_REQUEST` and `VERIFY`), and each later token carries the next messages;
//! the acceptor answers `accept-incomplete` until the `NegoEx` exchange and its
//! `VERIFY` messages complete, then `accept-completed` (MIT 1.22.2
//! `spnego_mech.c`, `negoex_init` and `negoex_accept`).
//!
//! A SPNEGO negotiation of Kerberos and `NegoEx` together, with fallback from
//! one to the other, is not implemented: use [`crate::spnego::Initiator`] and
//! [`crate::spnego::Acceptor`] for Kerberos, or these for `NegoEx`.
//!
//! # Security
//!
//! - A mechanism whose context offers integrity needs a `mechListMIC` exchange
//!   when the acceptor selects `NegoEx` after another mechanism or the peer sends
//!   one; this module does not implement that exchange and fails the context
//!   ([`Negoex::MechListMicUnsupported`]) rather than skip it.
//! - The final `accept-completed` is required before the initiator completes.

use core::fmt;

use zeroize::Zeroizing;

use super::{NegState, NegTokenInit, NegTokenResp, ObjectIdentifier, Token};
use crate::{
    error::{Gss, Negoex, Spnego},
    gss::{
        ContextFlags, InitStep,
        negoex::{Context, MechanismMetadata, Session},
    },
};

/// Fail closed when a mechanism that offers integrity needs the `mechListMIC` exchange.
///
/// # Errors
///
/// Returns [`Negoex::MechListMicUnsupported`] when `required` and the selected
/// mechanism offers integrity.
fn check_mic(context: &Context, required: bool) -> Result<(), Negoex> {
    if required && context.selected_flags().contains(ContextFlags::INTEG) {
        return Err(Negoex::MechListMicUnsupported);
    }
    Ok(())
}

/// Encode a `NegTokenResp`.
///
/// # Errors
///
/// Returns the encoding errors of [`NegTokenResp::encode`].
fn response(
    state: NegState,
    mechanism: bool,
    token: Option<Vec<u8>>,
) -> Result<Vec<u8>, Gss> {
    let mut resp = NegTokenResp::reject();
    resp.set_neg_state(Some(state));
    resp.set_supported_mech(mechanism.then(ObjectIdentifier::negoex));
    resp.set_response_token(token.map(Zeroizing::new));
    Ok(resp.encode()?)
}

/// A SPNEGO initiator that negotiates `NegoEx` only: its mechanism list is the
/// `NegoEx` OID (what MIT offers when no other mechanism is usable).
#[non_exhaustive]
pub struct Initiator {
    /// The `NegoEx` negotiation.
    context: Context,
    /// Whether the `NegTokenInit` was sent.
    sent: bool,
    /// Whether the acceptor's first answer was handled.
    answered: bool,
}

impl fmt::Debug for Initiator {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Initiator")
            .field("context", &self.context)
            .field("sent", &self.sent)
            .finish_non_exhaustive()
    }
}

impl Initiator {
    /// An initiator over `context`, which must be an initiator context.
    #[inline]
    #[must_use]
    pub const fn new(context: Context) -> Self {
        Self {
            context,
            sent: false,
            answered: false,
        }
    }

    /// One step: the first call (no token) returns the `NegTokenInit`; each later
    /// call takes the acceptor's `NegTokenResp`.
    ///
    /// The result is [`InitStep::Continue`] while a token is sent and the
    /// acceptor's answer is awaited, and [`InitStep::Complete`] with no token
    /// once the acceptor's `accept-completed` arrived.
    ///
    /// # Errors
    ///
    /// Returns the SPNEGO token errors, [`Spnego::UnsupportedMechanism`] for a
    /// rejection or a mechanism that was not offered, [`Spnego::MissingMechToken`]
    /// for an answer without the token the exchange needs,
    /// [`Spnego::NegotiationRequiresState`] for a completion that is not
    /// `accept-completed`, [`Gss::DefectiveToken`] for a spurious token, and
    /// the errors of [`Context::step`], including [`Negoex::InvalidChecksum`]
    /// for a `VERIFY` message that does not verify.
    #[inline]
    pub fn init_sec_context(&mut self, input_token: Option<&[u8]>) -> Result<InitStep, Gss> {
        let Some(bytes) = input_token else {
            return self.first();
        };
        if !self.sent {
            return Err(Gss::UnexpectedStep("no NegTokenInit was sent"));
        }
        let Token::Resp(answer) = Token::decode(bytes)? else {
            return Err(Spnego::WrongNegotiationToken {
                expected: "NegTokenResp",
                actual: "NegTokenInit",
            }
            .into());
        };
        let negoex = ObjectIdentifier::negoex();
        if answer.neg_state == Some(NegState::Reject) {
            return Err(Spnego::UnsupportedMechanism(negoex).into());
        }
        if !self.answered
            && let Some(mechanism) = &answer.supported_mech
            && *mechanism != negoex
        {
            return Err(Spnego::UnsupportedMechanism(mechanism.clone()).into());
        }
        self.answered = true;
        let mic_required =
            answer.mech_list_mic.is_some() || answer.neg_state == Some(NegState::RequestMic);
        let token = answer
            .response_token
            .as_ref()
            .map(|value| value.as_slice())
            .filter(|value| !value.is_empty());
        if self.context.is_complete() {
            if token.is_some() {
                return Err(Gss::DefectiveToken("a spurious mechanism token"));
            }
            return self.complete(&answer, mic_required);
        }
        let step = self
            .context
            .step(Some(token.ok_or(Spnego::MissingMechToken)?))?;
        match step.into_token() {
            Some(output) => Ok(InitStep::Continue(response(
                NegState::AcceptIncomplete,
                false,
                Some(output),
            )?)),
            None if self.context.is_complete() => self.complete(&answer, mic_required),
            None => Err(Gss::UnexpectedStep("the mechanism sent no token")),
        }
    }

    /// The first token.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Context::step`] and [`NegTokenInit::encode`].
    fn first(&mut self) -> Result<InitStep, Gss> {
        let token = self
            .context
            .step(None)?
            .into_token()
            .ok_or(Gss::UnexpectedStep("the mechanism sent no first token"))?;
        let mut init = NegTokenInit::krb5(Vec::new());
        init.set_mech_types(vec![ObjectIdentifier::negoex()]);
        init.set_mech_token(Some(Zeroizing::new(token)));
        let encoded = Token::Init(init).encode()?;
        self.sent = true;
        Ok(InitStep::Continue(encoded))
    }

    /// The negotiation ends on `answer`.
    ///
    /// # Errors
    ///
    /// Returns [`Spnego::NegotiationRequiresState`] unless the answer is
    /// `accept-completed`, and [`Negoex::MechListMicUnsupported`].
    fn complete(&self, answer: &NegTokenResp, mic_required: bool) -> Result<InitStep, Gss> {
        if answer.neg_state != Some(NegState::AcceptCompleted) {
            return Err(Spnego::NegotiationRequiresState.into());
        }
        check_mic(&self.context, mic_required)?;
        Ok(InitStep::Complete(None))
    }

    /// The selected mechanism, once the negotiation is complete.
    #[inline]
    #[must_use]
    pub fn selected(&self) -> Option<MechanismMetadata> {
        self.context.selected()
    }

    /// The selected mechanism's session.
    ///
    /// # Errors
    ///
    /// Returns [`Negoex::UnexpectedStep`] before the negotiation is complete.
    #[inline]
    pub fn into_session(self) -> Result<Box<dyn Session>, Gss> {
        Ok(self.context.into_session()?)
    }
}

/// Where an [`Acceptor`] is.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum State {
    /// Nothing received.
    Start,
    /// The `NegoEx` selection was announced; the initiator's token is awaited.
    Selected,
    /// The exchange runs.
    Running,
}

/// A SPNEGO acceptor that negotiates `NegoEx` only.
#[non_exhaustive]
pub struct Acceptor {
    /// The `NegoEx` negotiation.
    context: Option<Context>,
    /// Where the negotiation is.
    state: State,
    /// Whether the `NegoEx` OID was named in an answer already.
    announced: bool,
    /// Whether the initiator's list put another mechanism first, which asks for a `mechListMIC`.
    mic_required: bool,
}

impl fmt::Debug for Acceptor {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Acceptor")
            .field("context", &self.context)
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

/// Where a `NegoEx` [`Acceptor`] stands after a token.
#[non_exhaustive]
pub enum AcceptStep {
    /// Send this `NegTokenResp` (`accept-incomplete` or `request-mic`) and
    /// pass the initiator's next token to the next step.
    Continue(Vec<u8>),
    /// The negotiation is complete; send its output token.
    Complete(Box<Accepted>),
}

impl fmt::Debug for AcceptStep {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Continue(token) => f
                .debug_struct("Continue")
                .field("token_len", &token.len())
                .finish(),
            Self::Complete(accepted) => f.debug_tuple("Complete").field(accepted).finish(),
        }
    }
}

/// A completed `NegoEx` acceptance.
#[non_exhaustive]
pub struct Accepted {
    /// The `NegTokenResp` to send.
    output: Vec<u8>,
    /// The selected mechanism.
    mechanism: MechanismMetadata,
    /// The mechanism's session.
    session: Box<dyn Session>,
}

impl fmt::Debug for Accepted {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Accepted")
            .field("output_len", &self.output.len())
            .field("mechanism", &self.mechanism)
            .finish_non_exhaustive()
    }
}

impl Accepted {
    /// The `NegTokenResp` to send to the initiator.
    #[inline]
    #[must_use]
    pub fn output_token(&self) -> &[u8] {
        &self.output
    }

    /// The selected mechanism.
    #[inline]
    #[must_use]
    pub const fn mechanism(&self) -> &MechanismMetadata {
        &self.mechanism
    }

    /// The selected mechanism's session.
    #[inline]
    #[must_use]
    pub fn into_session(self) -> Box<dyn Session> {
        self.session
    }
}

impl Acceptor {
    /// An acceptor over `context`, which must be an acceptor context.
    #[inline]
    #[must_use]
    pub const fn new(context: Context) -> Self {
        Self {
            context: Some(context),
            state: State::Start,
            announced: false,
            mic_required: false,
        }
    }

    /// Take one initiator token: the `NegTokenInit`, then each `NegTokenResp`.
    ///
    /// # Errors
    ///
    /// Returns the SPNEGO token errors, [`Spnego::UnsupportedMechanism`] for an
    /// offer without the `NegoEx` OID, [`Spnego::WrongNegotiationToken`],
    /// [`Spnego::MissingMechToken`] for a continuation without a token,
    /// [`Gss::UnexpectedStep`] after completion, and the errors of
    /// [`Context::step`].
    #[inline]
    pub fn accept_sec_context(&mut self, input_token: &[u8]) -> Result<AcceptStep, Gss> {
        match (self.state, Token::decode(input_token)?) {
            (State::Start, Token::Init(init)) => {
                let negoex = ObjectIdentifier::negoex();
                let position = init
                    .mech_types
                    .iter()
                    .position(|oid| *oid == negoex)
                    .ok_or_else(|| {
                        init.mech_types
                            .first()
                            .cloned()
                            .map_or(Spnego::MissingMechTypes, Spnego::UnsupportedMechanism)
                    })?;
                let first = position == 0;
                self.mic_required = !first;
                let token = init
                    .mech_token
                    .as_ref()
                    .map(|bytes| bytes.to_vec())
                    .filter(|_bytes| first);
                if let Some(bytes) = token {
                    return self.process(&bytes);
                }
                self.state = State::Selected;
                self.announced = true;
                let state = if first {
                    NegState::AcceptIncomplete
                } else {
                    NegState::RequestMic
                };
                Ok(AcceptStep::Continue(response(state, true, None)?))
            }
            (State::Selected | State::Running, Token::Resp(answer)) => {
                if answer.supported_mech.is_some() {
                    return Err(Gss::DefectiveToken("a continuation names a mechanism"));
                }
                if answer.mech_list_mic.is_some() {
                    self.mic_required = true;
                }
                let token = answer
                    .response_token
                    .as_ref()
                    .map(|bytes| bytes.to_vec())
                    .filter(|bytes| !bytes.is_empty())
                    .ok_or(Spnego::MissingMechToken)?;
                self.process(&token)
            }
            (State::Start, Token::Resp(_)) => Err(Spnego::NegotiationRequiresState.into()),
            (State::Selected | State::Running, Token::Init(_)) => Err(Spnego::WrongNegotiationToken {
                expected: "NegTokenResp",
                actual: "NegTokenInit",
            }
            .into()),
        }
    }

    /// Run the `NegoEx` step on `token` and answer.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Context::step`] and [`Negoex::MechListMicUnsupported`].
    fn process(&mut self, token: &[u8]) -> Result<AcceptStep, Gss> {
        let context = self
            .context
            .as_mut()
            .ok_or(Gss::UnexpectedStep("the negotiation is complete"))?;
        let step = context.step(Some(token))?;
        self.state = State::Running;
        let name_mechanism = !self.announced;
        self.announced = true;
        let complete = step.is_complete();
        let state = if complete {
            NegState::AcceptCompleted
        } else {
            NegState::AcceptIncomplete
        };
        let output = response(state, name_mechanism, step.into_token())?;
        if !complete {
            return Ok(AcceptStep::Continue(output));
        }
        check_mic(context, self.mic_required)?;
        let mechanism = context
            .selected()
            .ok_or(Gss::UnexpectedStep("no mechanism was selected"))?;
        let session = self
            .context
            .take()
            .ok_or(Gss::UnexpectedStep("the negotiation is complete"))?
            .into_session()?;
        Ok(AcceptStep::Complete(Box::new(Accepted {
            output,
            mechanism,
            session,
        })))
    }
}
