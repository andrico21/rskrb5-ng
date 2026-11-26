//! IAKERB: Kerberos through an application-mediated KDC relay.
//!
//! IAKERB is the GSS-API mechanism `1.3.6.1.5.2.5` of MIT krb5 1.22.2
//! (`iakerb.c`), which implements `draft-ietf-krb-wg-iakerb-02` (MIT
//! `doc/mitK5features.rst:99`). The initiator has no route to a KDC: its AS and
//! TGS requests travel inside GSS context tokens to the acceptor, which sends
//! them to a KDC of the named realm and returns the replies, before the normal
//! AP exchange. It is not anonymous Kerberos (RFC 6112).
//!
//! # Security
//!
//! - The acceptor relays only through a caller-supplied [`KdcRelay`], never
//!   through a socket of its own, and only for the realms, rounds and bytes
//!   its [`RelayPolicy`] allows; a request for another realm, or one that is
//!   not a well-formed AS-REQ or TGS-REQ for the realm in its header, is refused.
//! - Every IAKERB token of the exchange is appended to a transcript; the
//!   AP-REQ carries an `IAKERB-FINISHED` checksum of that transcript under
//!   the initiator's subkey, which the acceptor verifies (MIT `iakerb.c:125-181`).
//! - Tokens are bounded before they are parsed; a malformed or reordered token
//!   is an error, never a panic.
//! - The AP exchange is the krb5 mechanism's ([`super::Initiator`],
//!   [`super::Acceptor`]) with the transcript in its extension record: the
//!   finished checksum and the channel bindings are checked before the replay
//!   cache commits the authenticator. A credential is delegated only when the
//!   initiator's options request [`super::ContextFlags::DELEG`], under the same
//!   `enforce_ok_as_delegate` policy as krb5.

use core::fmt;
use std::time::SystemTime;

use super::{Accepted, Acceptor, Config, CredStore, Credential, EstablishedContext, InitStep};
use crate::{
    client::{
        options::TgsReq,
        stepwise::{InitCredsOptions, Responder, TicketOptions},
    },
    error::Iakerb as Error,
    spnego::oid::ObjectIdentifier,
};

mod acceptor;
mod conversation;
mod convert;
pub(super) mod finished;
mod initiator;
pub mod token;

use token::{AP_REP_TOKEN_ID, AP_REQ_TOKEN_ID, MAX_REALM_BYTES, Token, unframe};

/// Why a [`KdcRelay`] could not deliver a request.
///
/// The first two answer the initiator with the IAKERB error codes of MIT
/// (`iakerb.c:437-445`); [`Self::Other`] ends the context.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RelayFailure {
    /// No KDC of the realm answered (`KRB5_KDC_UNREACH`,
    /// `KRB_AP_ERR_IAKERB_KDC_NO_RESPONSE`).
    KdcUnreachable,
    /// The application knows no KDC for the realm (`KRB5_REALM_UNKNOWN`,
    /// `KRB_AP_ERR_IAKERB_KDC_NOT_FOUND`).
    RealmUnknown,
    /// Any other failure; the text is for the application's log.
    Other(String),
}

/// The application's channel to the KDCs: the acceptor hands it a request and
/// the realm it is for, and returns what it answers.
///
/// The library never opens a socket to a KDC here. The implementation decides
/// which servers a realm maps to, the transport and the retries (MIT retries a
/// `KRB_ERR_RESPONSE_TOO_BIG` over TCP, `iakerb.c:416-435`); it is called only
/// for requests the [`RelayPolicy`] already admitted.
///
/// # Security
///
/// The reply is not authenticated by the acceptor: the initiator binds every
/// reply to its own request, as it does over a direct transport.
pub trait KdcRelay {
    /// Send `request`, a DER AS-REQ or TGS-REQ for `realm`, to a KDC of `realm`
    /// and return its DER reply (an AS-REP, a TGS-REP or a KRB-ERROR).
    ///
    /// # Errors
    ///
    /// Returns [`RelayFailure`] when the realm has no KDC or none answers.
    fn relay(&mut self, realm: &str, request: &[u8]) -> Result<Vec<u8>, RelayFailure>;
}

/// What an IAKERB acceptor may relay: the realms, the rounds and the bytes.
///
/// A policy names its realms explicitly; there is no way to relay for "any
/// realm" (the acceptor is never an open proxy).
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct RelayPolicy {
    /// The acceptor's own realm, which realm discovery answers.
    local_realm: String,
    /// The realms a request may name.
    realms: Vec<String>,
    /// The most tokens the acceptor produces.
    max_rounds: usize,
    /// The longest token or relayed message.
    max_message_bytes: usize,
    /// The longest transcript.
    max_transcript_bytes: usize,
}

impl RelayPolicy {
    /// The default bound on rounds: 16 AS rounds and 10 referral hops (MIT
    /// `IAKERB_MAX_HOPS`, `iakerb.c:55`).
    pub const DEFAULT_MAX_ROUNDS: usize = 26;
    /// The default bound on one token or relayed message, in bytes.
    pub const DEFAULT_MAX_MESSAGE_BYTES: usize = 0x4_0000;
    /// The default bound on the transcript, in bytes.
    pub const DEFAULT_MAX_TRANSCRIPT_BYTES: usize = 0x10_0000;
    /// The most realms a policy may name.
    pub const MAX_REALMS: usize = 16;

    /// A policy that relays for `local_realm` only, which realm discovery
    /// answers.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidPolicy`] for an empty realm or one above 255 bytes.
    #[inline]
    pub fn new(local_realm: &str) -> Result<Self, Error> {
        check_realm(local_realm)?;
        Ok(Self {
            local_realm: local_realm.to_owned(),
            realms: vec![local_realm.to_owned()],
            max_rounds: Self::DEFAULT_MAX_ROUNDS,
            max_message_bytes: Self::DEFAULT_MAX_MESSAGE_BYTES,
            max_transcript_bytes: Self::DEFAULT_MAX_TRANSCRIPT_BYTES,
        })
    }

    /// Also relay for `realm`, for example a realm a referral may reach.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidPolicy`] for an empty realm, one above 255
    /// bytes, or more than [`Self::MAX_REALMS`] realms.
    #[inline]
    pub fn with_realm(mut self, realm: &str) -> Result<Self, Error> {
        check_realm(realm)?;
        if !self.permits(realm) {
            if self.realms.len() >= Self::MAX_REALMS {
                return Err(Error::InvalidPolicy("more than 16 realms"));
            }
            self.realms.push(realm.to_owned());
        }
        Ok(self)
    }

    /// Allow at most `rounds` tokens from the acceptor.
    #[inline]
    #[must_use]
    pub const fn with_max_rounds(mut self, rounds: usize) -> Self {
        self.max_rounds = rounds;
        self
    }

    /// Allow tokens and relayed messages of at most `bytes`.
    #[inline]
    #[must_use]
    pub const fn with_max_message_bytes(mut self, bytes: usize) -> Self {
        self.max_message_bytes = bytes;
        self
    }

    /// Allow a transcript of at most `bytes`.
    #[inline]
    #[must_use]
    pub const fn with_max_transcript_bytes(mut self, bytes: usize) -> Self {
        self.max_transcript_bytes = bytes;
        self
    }

    /// The realm realm discovery answers.
    #[inline]
    #[must_use]
    pub const fn local_realm(&self) -> &str {
        self.local_realm.as_str()
    }

    /// Whether a request for `realm` may be relayed.
    #[inline]
    #[must_use]
    pub fn permits(&self, realm: &str) -> bool {
        self.realms.iter().any(|allowed| allowed == realm)
    }
}

/// A realm a policy may name.
///
/// # Errors
///
/// Returns [`Error::InvalidPolicy`] for an empty realm or one above 255 bytes.
const fn check_realm(realm: &str) -> Result<(), Error> {
    if realm.is_empty() || realm.len() > MAX_REALM_BYTES {
        return Err(Error::InvalidPolicy("a realm is 1 to 255 bytes"));
    }
    Ok(())
}

/// What [`Context::accept_sec_context`] needs the application to do next.
#[non_exhaustive]
pub enum AcceptStep {
    /// Send this token to the initiator and pass its answer to the next step
    /// (`GSS_S_CONTINUE_NEEDED`).
    Continue(Vec<u8>),
    /// The context is established (`GSS_S_COMPLETE`).
    Complete(Box<Accepted>),
}

impl fmt::Debug for AcceptStep {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Continue(token) => write!(f, "Continue({} bytes)", token.len()),
            Self::Complete(accepted) => f.debug_tuple("Complete").field(accepted).finish(),
        }
    }
}

/// An IAKERB security context: the initiator that relays its Kerberos
/// exchanges through the acceptor, or the acceptor that relays them.
///
/// The initiator takes the credential at every step, as [`super::Initiator`]
/// does; the acceptor takes the keytab-backed [`Acceptor`] and the application's
/// [`KdcRelay`]. A failed step ends the initiator; the acceptor refuses the
/// token and stays as it was.
#[non_exhaustive]
pub struct Context {
    /// This end.
    role: Role,
}

/// Which end a context is.
enum Role {
    /// The initiator.
    Initiator(Box<initiator::State>),
    /// The acceptor.
    Acceptor(acceptor::State),
}

impl fmt::Debug for Context {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let role = match &self.role {
            Role::Initiator(_) => "initiator",
            Role::Acceptor(_) => "acceptor",
        };
        f.debug_struct("Context")
            .field("role", &role)
            .field("established", &self.is_established())
            .finish_non_exhaustive()
    }
}

impl Context {
    /// The IAKERB mechanism, `1.3.6.1.5.2.5`.
    #[inline]
    #[must_use]
    pub fn mechanism() -> ObjectIdentifier {
        ObjectIdentifier::from_static(&[1, 3, 6, 1, 5, 2, 5])
    }

    /// An initiator context for `target`; the AS and TGS requests take their
    /// lifetimes, flags, enctypes and policy from `config`'s `[libdefaults]`.
    ///
    /// # Errors
    ///
    /// Returns the errors of reading the request defaults of `config`
    /// ([`Error::Client`]) and of the random source.
    #[inline]
    pub fn initiator(
        config: &Config,
        target: super::Name,
        options: super::InitiatorOptions,
    ) -> Result<Self, Error> {
        let now = SystemTime::now();
        let mut random = [0_u8; 4];
        getrandom::fill(&mut random)?;
        let nonce = u32::from_be_bytes(random) & 0x7fff_ffff;
        let exchanges = (
            InitCredsOptions::from_config(config, now, nonce)?,
            TicketOptions::new(TgsReq::from_libdefaults(now, nonce, &config.libdefaults)?),
        );
        Ok(Self {
            role: Role::Initiator(Box::new(initiator::new(target, options, exchanges))),
        })
    }

    /// An acceptor context that relays under `policy`.
    #[inline]
    #[must_use]
    pub const fn acceptor(policy: RelayPolicy) -> Self {
        Self {
            role: Role::Acceptor(acceptor::new(policy)),
        }
    }

    /// One initiator step: the first call (no input) sends the first token.
    ///
    /// Each later call takes the acceptor's answer. The AS and TGS requests go
    /// out as proxy tokens; when the service ticket is in hand the AP-REQ goes
    /// out, and with mutual authentication the AP-REP completes the context.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnexpectedStep`] out of order or on an acceptor
    /// context, the token errors, [`Error::KdcNotFound`] and
    /// [`Error::KdcNoResponse`] when the acceptor reports them, the exchange
    /// errors ([`Error::Client`]), [`Error::UnsupportedPrompt`], and the
    /// bound errors ([`Error::RoundLimit`], [`Error::TranscriptTooLarge`]).
    #[inline]
    pub fn init_sec_context(
        &mut self,
        credential: &Credential,
        input_token: Option<&[u8]>,
    ) -> Result<InitStep, Error> {
        match &mut self.role {
            Role::Initiator(state) => initiator::step(
                state,
                &mut initiator::Sources::new(credential, None),
                input_token,
            ),
            Role::Acceptor(_) => Err(Error::UnexpectedStep("this is an acceptor context")),
        }
    }

    /// One initiator step that answers the KDC's prompts through `responder`.
    ///
    /// As [`Self::init_sec_context`], but a prompt of the AS exchange (the
    /// password of a credential that holds none, an OTP challenge) goes to
    /// `responder` (MIT's responder and prompter callbacks), whose answer
    /// continues the exchange.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Self::init_sec_context`], and
    /// [`Error::Client`] holding `Client::Responder` when `responder` does
    /// not answer.
    ///
    /// # Security
    ///
    /// Prompts carry no secret; an answer moves into the exchange, which
    /// erases it when the context is dropped, a cancelled exchange included.
    #[inline]
    pub fn init_sec_context_with_responder(
        &mut self,
        credential: &Credential,
        responder: &mut dyn Responder,
        input_token: Option<&[u8]>,
    ) -> Result<InitStep, Error> {
        match &mut self.role {
            Role::Initiator(state) => initiator::step(
                state,
                &mut initiator::Sources::new(credential, Some(responder)),
                input_token,
            ),
            Role::Acceptor(_) => Err(Error::UnexpectedStep("this is an acceptor context")),
        }
    }

    /// One acceptor step.
    ///
    /// A proxy token is answered with a proxy token: the acceptor's realm for a
    /// discovery request, the KDC's reply for a request it relays through
    /// `relay`. The AP-REQ completes the context.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnexpectedStep`] out of order or on an initiator
    /// context, the token errors, [`Error::RealmNotPermitted`] and
    /// [`Error::RequestRefused`] for a request the policy refuses,
    /// [`Error::RoundLimit`], [`Error::TokenTooLarge`] and
    /// [`Error::TranscriptTooLarge`] at the bounds, [`Error::RelayFailed`] and
    /// [`Error::BadRelayReply`] for the relay, and for the AP-REQ the
    /// validation errors, [`Error::MissingFinished`], [`Error::BadFinished`]
    /// and [`Error::UnexpectedFinished`].
    ///
    /// # Security
    ///
    /// The relay is called only after the realm and the request passed the
    /// policy. The context accepts at most one AP-REQ.
    #[inline]
    pub fn accept_sec_context(
        &mut self,
        acceptor: &mut Acceptor<'_>,
        relay: &mut dyn KdcRelay,
        input_token: &[u8],
    ) -> Result<AcceptStep, Error> {
        match &mut self.role {
            Role::Acceptor(state) => acceptor::step(state, (acceptor, relay), input_token),
            Role::Initiator(_) => Err(Error::UnexpectedStep("this is an initiator context")),
        }
    }

    /// Whether the context is established.
    #[inline]
    #[must_use]
    pub const fn is_established(&self) -> bool {
        match &self.role {
            Role::Initiator(state) => state.is_established(),
            Role::Acceptor(state) => state.is_established(),
        }
    }

    /// Store the tickets the initiator's AS and TGS exchanges acquired into
    /// the `ccache` of `store` (MIT's `out_ccache`, `iakerb.c:484-487`).
    ///
    /// The tickets go only to the cache the caller names here, never to a
    /// default cache. Without `overwrite`, a cache that already holds tickets
    /// is not replaced (MIT `GSS_S_DUPLICATE_ELEMENT`), as
    /// [`Credential::store_cred_into`] does.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnexpectedStep`] on an acceptor context, the
    /// [`Error::Gss`] of [`Credential::store_cred_into`] when no ticket was
    /// acquired, the store names no `ccache` or the cache holds tickets, and
    /// the errors of writing the cache. A failed write leaves the context as
    /// it was: an established context stays established.
    ///
    /// # Security
    ///
    /// The cache receives the session keys of the acquired tickets.
    #[inline]
    pub fn store_acquired_into(&self, store: &CredStore, overwrite: bool) -> Result<(), Error> {
        match &self.role {
            Role::Initiator(state) => {
                initiator::acquired::store_acquired_into(state, store, overwrite)
            }
            Role::Acceptor(_) => Err(Error::UnexpectedStep(
                "an acceptor context acquires no tickets",
            )),
        }
    }

    /// The established context of an initiator; the acceptor's comes with
    /// [`AcceptStep::Complete`]. Both report the IAKERB mechanism in
    /// [`EstablishedContext::inquire`] and keep it across a context transfer
    /// (MIT `iakerb.c:1183-1226`).
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnexpectedStep`] before the context is established and
    /// on an acceptor context.
    #[inline]
    pub fn into_established(self) -> Result<EstablishedContext, Error> {
        match self.role {
            Role::Initiator(state) => state.into_established(),
            Role::Acceptor(_) => Err(Error::UnexpectedStep(
                "an acceptor context has no initiator part",
            )),
        }
    }
}
