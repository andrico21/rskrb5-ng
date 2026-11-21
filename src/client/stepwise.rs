//! Transport-neutral, stepwise AS and TGS exchanges.
//!
//! These are MIT's `krb5_init_creds_step` and `krb5_tkt_creds_step`.
//!
//! An exchange never performs I/O. [`InitCreds::step`] and [`TicketCreds::step`]
//! take the previous [`StepInput`] and return one [`ExchangeStep`]: a request to
//! send to a realm's KDC ([`ExchangeStep::Outbound`]), a question for the caller
//! ([`ExchangeStep::Prompt`]) or the finished credential
//! ([`ExchangeStep::Complete`]). [`drive`] runs an exchange over a blocking
//! [`KdcTransport`]; with the `tokio` feature, [`drive_tokio`] runs it over the
//! Tokio transport.
//!
//! # Security
//!
//! Every reply is bound to its request: the AS-REP to the request's client,
//! service, nonce and offered enctypes ([`super::process_as_rep`]), the TGS-REP
//! to the TGT session key, nonce and service ([`super::process_tgs_rep`]). The
//! number of KDC round trips is bounded by [`MAX_EXCHANGE_ROUNDS`] (MIT
//! `MAX_IN_TKT_LOOPS`, `get_in_tkt.c:398`) and the referral chain by the
//! caller's [`TicketOptions::with_max_referrals`]. Prompt answers are owned by
//! [`Answer`], whose secrets are erased when dropped, including when an exchange
//! is abandoned between steps. No unauthenticated reply changes the client or
//! service identity: canonicalization stays suppressed for unarmored AS
//! requests.

use core::{fmt, net::IpAddr, time::Duration};
use std::time::SystemTime;

use zeroize::Zeroizing;

#[cfg(feature = "tokio")]
use super::transport::{KdcProtocol, Tokio as TokioTransport};
use super::{
    AsRepSession, KdcTransport, Password, TgsRepSession,
    options::{AsReq, TgsReq},
    principal::Principal,
};
use crate::{
    config::Config,
    error::Client as Error,
    extensions::{PreauthSession, ProviderError},
    keytab::{EncryptionKey, Keytab},
    preauth::spake::Policy as SpakePolicy,
    trace::{ExchangeKind, Guard},
};

/// The AS state machine.
#[path = "stepwise/init.rs"]
mod init;
/// Request options and their profile defaults.
#[path = "stepwise/options.rs"]
pub(super) mod options;
/// MIT's `preferred_preauth_types` ordering.
#[path = "stepwise/order.rs"]
mod order;
/// Deterministic fake-KDC exchanges.
#[cfg(test)]
#[path = "stepwise/tests.rs"]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests;
/// The TGS state machine with referral chasing.
#[path = "stepwise/ticket.rs"]
mod ticket;
/// Redacted trace events of the exchanges.
#[path = "stepwise/trace.rs"]
pub(super) mod trace;

/// The most KDC round trips one exchange may take (MIT `MAX_IN_TKT_LOOPS`).
pub const MAX_EXCHANGE_ROUNDS: usize = 16;
/// The default bound on cross-realm referral hops (MIT `KRB5_REFERRAL_MAXHOPS`).
pub const DEFAULT_MAX_REFERRALS: usize = 10;

/// What the caller hands to the next [`InitCreds::step`] or [`TicketCreds::step`].
#[non_exhaustive]
pub enum StepInput<'input> {
    /// Begin the exchange.
    Start,
    /// The KDC's reply to the last [`Outbound`] request.
    Reply(&'input [u8]),
    /// The caller's answer to the last [`Prompt`].
    Answer(Answer),
}

impl fmt::Debug for StepInput<'_> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Start => f.write_str("Start"),
            Self::Reply(reply) => write!(f, "Reply({} bytes)", reply.len()),
            Self::Answer(answer) => f.debug_tuple("Answer").field(answer).finish(),
        }
    }
}

/// What the exchange needs next. Its `Debug` output is redacted.
#[non_exhaustive]
pub enum ExchangeStep {
    /// Send this request to a KDC of its realm and pass the reply back.
    Outbound(Outbound),
    /// Answer this question and pass the [`Answer`] back.
    Prompt(Prompt),
    /// The exchange finished with this credential.
    Complete(Box<AsRepSession>),
}

impl fmt::Debug for ExchangeStep {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Outbound(outbound) => f.debug_tuple("Outbound").field(outbound).finish(),
            Self::Prompt(prompt) => f.debug_tuple("Prompt").field(prompt).finish(),
            Self::Complete(session) => f.debug_tuple("Complete").field(session).finish(),
        }
    }
}

/// One encoded KDC request and the realm whose KDC must receive it.
pub struct Outbound {
    /// The target realm.
    realm: String,
    /// The DER-encoded request.
    message: Zeroizing<Vec<u8>>,
    /// Whether this request continues the previous one at the same KDC.
    follow_up: bool,
}

impl Outbound {
    /// The realm whose KDC must receive the request.
    #[inline]
    #[must_use]
    pub fn realm(&self) -> &str {
        &self.realm
    }

    /// The DER-encoded request.
    #[inline]
    #[must_use]
    pub fn message(&self) -> &[u8] {
        &self.message
    }

    /// Whether the request continues the previous request of this exchange, so a
    /// transport that kept the earlier connection open should reuse it.
    #[inline]
    #[must_use]
    pub const fn follow_up(&self) -> bool {
        self.follow_up
    }
}

impl fmt::Debug for Outbound {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Outbound")
            .field("realm", &self.realm)
            .field("message_bytes", &self.message.len())
            .field("follow_up", &self.follow_up)
            .finish()
    }
}

/// A question the exchange cannot answer itself. Prompts carry no secret.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Prompt {
    /// The long-term password of `client` is needed (answer with [`Answer::Password`]).
    Password {
        /// The client whose password is needed.
        client: Principal,
    },
}

/// The caller's answer to a [`Prompt`]. Its `Debug` output is redacted and its
/// secret is erased when the answer, or the exchange holding it, is dropped.
#[non_exhaustive]
pub enum Answer {
    /// A password, for [`Prompt::Password`].
    Password(Password),
}

impl fmt::Debug for Answer {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Password(_) => f.write_str("Answer::Password([REDACTED])"),
        }
    }
}

/// Answers prompts and receives notices on the caller's behalf (MIT responder
/// and prompter callbacks).
pub trait Responder {
    /// Answer `prompt`.
    ///
    /// # Errors
    ///
    /// Returns the caller's failure; the driver reports it as
    /// [`Error::Responder`] and abandons the exchange.
    fn respond(&mut self, prompt: &Prompt) -> Result<Answer, ProviderError>;

    /// The KDC reported that the client's password or key expires at `expires`
    /// (MIT `krb5_get_init_creds_opt_set_expire_callback`). The default does nothing.
    #[inline]
    fn password_expiry(&mut self, expires: SystemTime) {
        let _: SystemTime = expires;
    }
}

/// A [`Responder`] that answers nothing: for keytab exchanges and TGS exchanges.
#[derive(Clone, Copy, Debug, Default)]
#[non_exhaustive]
pub struct NoResponder;

impl Responder for NoResponder {
    #[inline]
    fn respond(&mut self, prompt: &Prompt) -> Result<Answer, ProviderError> {
        Err(format!("no responder for {prompt:?}").into())
    }
}

/// A stepwise exchange, driven by [`drive`] or [`drive_tokio`].
pub trait Exchange {
    /// Advance the exchange by one step.
    ///
    /// # Errors
    ///
    /// Returns the exchange's typed failure; the exchange cannot continue after one.
    fn advance(&mut self, input: StepInput<'_>) -> Result<ExchangeStep, Error>;

    /// The key expiration the finished exchange reported, if any.
    fn key_expiration(&self) -> Option<SystemTime>;

    /// Adopt the profile's per-exchange settings before the first step;
    /// [`drive_tokio`] calls it with its configuration. The default does nothing.
    #[inline]
    fn configure(&mut self, config: &Config) {
        let _: &Config = config;
    }
}

/// Options of one AS exchange, from the profile or per request.
#[derive(Clone)]
pub struct InitCredsOptions {
    /// The request template: lifetimes, flags, enctypes, nonce and clock.
    request: AsReq,
    /// The service to request instead of the client realm's TGS.
    service: Option<Principal>,
    /// MIT `kdc_timesync`: adopt the KDC's clock for this exchange.
    kdc_timesync: bool,
    /// MIT `preferred_preauth_types`, most preferred first.
    preferred_preauth_types: Vec<i32>,
    /// `spake_preauth_groups`; `None` until set or adopted from a profile.
    spake: Option<SpakePolicy>,
    /// Realms whose `disable_encrypted_timestamp` is set (MIT `encts_disabled`).
    timestamp_disabled: Vec<String>,
}

impl fmt::Debug for InitCredsOptions {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InitCredsOptions")
            .field("request", &self.request)
            .field("service", &self.service)
            .field("kdc_timesync", &self.kdc_timesync)
            .field("preferred_preauth_types", &self.preferred_preauth_types)
            .field("spake", &self.spake)
            .field("timestamp_disabled", &self.timestamp_disabled)
            .finish()
    }
}

impl InitCredsOptions {
    /// Options with the request template's values, no addresses, the MIT
    /// preferred order and no clock adoption: the behaviour of the
    /// [`AsReq`]-taking login functions.
    #[inline]
    #[must_use]
    pub fn new(request: AsReq) -> Self {
        options::from_request(request)
    }

    /// Options from the parsed `[libdefaults]`: request lifetimes and flags
    /// (`ticket_lifetime`, `renew_lifetime`, `forwardable`, `proxiable`,
    /// `kdc_default_options`), request addresses (`noaddresses`,
    /// `extra_addresses`), `kdc_timesync`, `preferred_preauth_types`,
    /// `spake_preauth_groups` and the realms whose `disable_encrypted_timestamp`
    /// is set.
    ///
    /// # Errors
    ///
    /// Returns the configuration errors of [`AsReq::from_libdefaults`],
    /// including [`Error::NoRequestAddresses`] for `noaddresses = false` without
    /// `extra_addresses`.
    #[inline]
    pub fn from_config(config: &Config, now: SystemTime, nonce: u32) -> Result<Self, Error> {
        options::from_config(config, now, nonce)
    }

    /// Request `service` instead of the client realm's ticket-granting service.
    #[inline]
    #[must_use]
    pub fn with_service(self, service: Principal) -> Self {
        options::with_service(self, service)
    }

    /// Request a forwardable ticket, or clear the forwardable bit.
    #[inline]
    #[must_use]
    pub fn with_forwardable(self, forwardable: bool) -> Self {
        options::with_flag(self, options::FORWARDABLE, forwardable)
    }

    /// Request a proxiable ticket, or clear the proxiable bit.
    #[inline]
    #[must_use]
    pub fn with_proxiable(self, proxiable: bool) -> Self {
        options::with_flag(self, options::PROXIABLE, proxiable)
    }

    /// Request this ticket lifetime.
    #[inline]
    #[must_use]
    pub fn with_ticket_lifetime(self, lifetime: Duration) -> Self {
        options::with_ticket_lifetime(self, lifetime)
    }

    /// Request a renewable ticket for this long, or no renewal with `None`.
    #[inline]
    #[must_use]
    pub fn with_renew_lifetime(self, lifetime: Option<Duration>) -> Self {
        options::with_renew_lifetime(self, lifetime)
    }

    /// Bind the ticket to these client addresses, or to none with an empty list
    /// (MIT `krb5_get_init_creds_opt_set_address_list`).
    #[inline]
    #[must_use]
    pub fn with_addresses(self, addresses: Vec<IpAddr>) -> Self {
        options::with_addresses(self, addresses)
    }

    /// Adopt the KDC's clock for this exchange (MIT `kdc_timesync`).
    #[inline]
    #[must_use]
    pub const fn with_kdc_timesync(mut self, kdc_timesync: bool) -> Self {
        self.kdc_timesync = kdc_timesync;
        self
    }

    /// Prefer these PA types, in this order, among the KDC's offers.
    #[inline]
    #[must_use]
    pub fn with_preferred_preauth_types(self, types: Vec<i32>) -> Self {
        options::with_preferred(self, types)
    }

    /// The request template.
    #[inline]
    #[must_use]
    pub const fn request(&self) -> &AsReq {
        &self.request
    }

    /// Whether the exchange adopts the KDC's clock (MIT `kdc_timesync`).
    #[inline]
    #[must_use]
    pub const fn kdc_timesync(&self) -> bool {
        self.kdc_timesync
    }

    /// The preferred PA types, most preferred first.
    #[inline]
    #[must_use]
    pub fn preferred_preauth_types(&self) -> &[i32] {
        &self.preferred_preauth_types
    }

    /// Run SPAKE (RFC 9588) with `policy`'s groups when the KDC offers it; an
    /// empty policy disables SPAKE. Without this call the exchange uses the
    /// profile's `spake_preauth_groups` under [`drive_tokio`] and MIT's client
    /// default, edwards25519, otherwise.
    #[inline]
    #[must_use]
    pub fn with_spake_policy(self, policy: SpakePolicy) -> Self {
        options::with_spake(self, policy)
    }

    /// The SPAKE policy, when set or adopted from a profile.
    #[inline]
    #[must_use]
    pub const fn spake_policy(&self) -> Option<&SpakePolicy> {
        self.spake.as_ref()
    }
}

/// Options of one TGS exchange.
#[derive(Clone)]
pub struct TicketOptions {
    /// The request template.
    request: TgsReq,
    /// The most cross-realm referrals to follow.
    max_referrals: usize,
    /// The ticket of the user-to-user target, encrypted in its session key.
    second_ticket: Option<rasn_kerberos::Ticket>,
}

impl fmt::Debug for TicketOptions {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TicketOptions")
            .field("request", &self.request)
            .field("max_referrals", &self.max_referrals)
            .field("user_to_user", &self.second_ticket.is_some())
            .finish()
    }
}

impl TicketOptions {
    /// Options with the request template's values and [`DEFAULT_MAX_REFERRALS`].
    #[inline]
    #[must_use]
    pub const fn new(request: TgsReq) -> Self {
        Self {
            request,
            max_referrals: DEFAULT_MAX_REFERRALS,
            second_ticket: None,
        }
    }

    /// Follow at most `max` referrals.
    #[inline]
    #[must_use]
    pub const fn with_max_referrals(mut self, max: usize) -> Self {
        self.max_referrals = max;
        self
    }

    /// Request a user-to-user ticket encrypted in the session key of
    /// `second_ticket`, the target's TGT (RFC 4120 section 3.7,
    /// `ENC-TKT-IN-SKEY`). This is not S4U.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Decode`] when `second_ticket` is not a DER Ticket.
    #[inline]
    pub fn with_user_to_user(self, second_ticket: &[u8]) -> Result<Self, Error> {
        ticket::with_user_to_user(self, second_ticket)
    }

    /// Request a forwardable ticket, or clear the forwardable bit.
    #[inline]
    #[must_use]
    pub fn with_forwardable(self, forwardable: bool) -> Self {
        ticket::with_flag(self, options::FORWARDABLE, forwardable)
    }

    /// Request a proxiable ticket, or clear the proxiable bit.
    #[inline]
    #[must_use]
    pub fn with_proxiable(self, proxiable: bool) -> Self {
        ticket::with_flag(self, options::PROXIABLE, proxiable)
    }

    /// The request template.
    #[inline]
    #[must_use]
    pub const fn request(&self) -> &TgsReq {
        &self.request
    }
}

/// A stepwise AS exchange (MIT `krb5_init_creds_context`).
pub struct InitCreds<'registry> {
    /// The requesting client.
    client: Principal,
    /// The password of a password exchange, `None` until given or prompted for.
    password: Option<Password>,
    /// The keytab of a keytab exchange.
    keytab: Option<Keytab>,
    /// A KDC reply held while the exchange waits for the password to process it.
    held_reply: Option<Zeroizing<Vec<u8>>>,
    /// The reply key of the preauthenticated request that is out.
    reply_key: Option<EncryptionKey>,
    /// Request options.
    options: InitCredsOptions,
    /// Where the exchange stands.
    state: init::State,
    /// Requests sent so far.
    rounds: usize,
    /// The KDC clock offset adopted under `kdc_timesync`, in seconds.
    time_offset: Option<i64>,
    /// Registered preauthentication mechanisms, consulted before the built-in ones.
    preauth: Option<PreauthSession<'registry>>,
    /// The FAST seam, when an armor is installed.
    armor: Option<Box<dyn ArmoredExchange + 'registry>>,
    /// The finished credential's key expiration.
    key_expiration: Option<SystemTime>,
    /// The KDC's newest cookie from an armored reply.
    cookie: Option<Vec<u8>>,
    /// The strengthen key of the newest armored reply.
    strengthen_key: Option<EncryptionKey>,
    /// The trace of the exchange, when a guard is attached.
    trace: Option<trace::Tracer>,
    /// The client the armor authenticated in the newest reply.
    authenticated_client: Option<Principal>,
}

impl fmt::Debug for InitCreds<'_> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        init::debug(self, f)
    }
}

impl<'registry> InitCreds<'registry> {
    /// A password exchange for `client`. With `password` `None`, the exchange
    /// asks for it with [`Prompt::Password`] when it first needs it.
    #[inline]
    #[must_use]
    pub fn with_password(
        client: Principal,
        password: Option<Password>,
        options: InitCredsOptions,
    ) -> Self {
        init::new(client, (password, None), options)
    }

    /// A keytab exchange for `client`.
    #[inline]
    #[must_use]
    pub fn with_keytab(client: Principal, keytab: Keytab, options: InitCredsOptions) -> Self {
        init::new(client, (None, Some(keytab)), options)
    }

    /// Consult `session`'s registered mechanisms for the PA types the KDC offers,
    /// in `preferred_preauth_types` order, before the built-in encrypted timestamp.
    #[inline]
    #[must_use]
    pub fn with_preauth(mut self, session: PreauthSession<'registry>) -> Self {
        self.preauth = Some(session);
        self
    }

    /// Trace this exchange to `guard`: its start, each request and reply, a
    /// prompt, and its completion or failure, as redacted [`crate::trace::Event`]s.
    /// A failing sink never changes the exchange.
    #[inline]
    #[must_use]
    pub fn with_trace(mut self, guard: Guard) -> Self {
        self.trace = Some(trace::Tracer::new(guard, ExchangeKind::Initial));
        self
    }

    /// Wrap every request through `armor` (the FAST seam of RFC 6113).
    #[inline]
    #[must_use]
    pub fn with_armor<A>(mut self, armor: A) -> Self
    where
        A: ArmoredExchange + 'registry,
    {
        self.armor = Some(Box::new(armor));
        self
    }

    /// Advance the exchange.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnexpectedStepInput`] for an input the exchange does
    /// not expect now, [`Error::ExchangeLoop`] after [`MAX_EXCHANGE_ROUNDS`]
    /// requests, [`Error::Preauth`] for a registered mechanism's failure, the
    /// KDC error, and the request-building and reply-validation errors of the
    /// login functions, including [`Error::NonceMismatch`] for a reply to
    /// another request.
    #[inline]
    pub fn step(&mut self, input: StepInput<'_>) -> Result<ExchangeStep, Error> {
        init::step(self, input)
    }

    /// The KDC clock offset in seconds adopted under `kdc_timesync`.
    #[inline]
    #[must_use]
    pub const fn kdc_time_offset(&self) -> Option<i64> {
        self.time_offset
    }
}

impl Exchange for InitCreds<'_> {
    #[inline]
    fn advance(&mut self, input: StepInput<'_>) -> Result<ExchangeStep, Error> {
        init::step(self, input)
    }

    #[inline]
    fn key_expiration(&self) -> Option<SystemTime> {
        self.key_expiration
    }

    #[inline]
    fn configure(&mut self, config: &Config) {
        init::configure(self, config);
    }
}

/// A stepwise TGS exchange with referral chasing (MIT `krb5_tkt_creds_context`).
pub struct TicketCreds {
    /// The TGT of the current hop.
    tgt: AsRepSession,
    /// The requested service.
    service: Principal,
    /// Request options.
    options: TicketOptions,
    /// Where the exchange stands.
    state: ticket::State,
    /// Cross-realm TGTs obtained on the way, in hop order.
    referral_tgts: Vec<TgsRepSession>,
    /// The trace of the exchange, when a guard is attached.
    trace: Option<trace::Tracer>,
}

impl fmt::Debug for TicketCreds {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        ticket::debug(self, f)
    }
}

impl TicketCreds {
    /// A TGS exchange for `service` with `tgt`. A service without a realm is
    /// requested in the TGT's realm.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidReferralTicket`] when `tgt` is not a TGT.
    #[inline]
    pub fn new(
        tgt: AsRepSession,
        service: Principal,
        options: TicketOptions,
    ) -> Result<Self, Error> {
        ticket::new(tgt, service, options)
    }

    /// Trace this exchange to `guard` (see [`InitCreds::with_trace`]).
    #[inline]
    #[must_use]
    pub fn with_trace(mut self, guard: Guard) -> Self {
        self.trace = Some(trace::Tracer::new(guard, ExchangeKind::Ticket));
        self
    }

    /// Advance the exchange.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnexpectedStepInput`] for an input the exchange does
    /// not expect now, [`Error::MaxReferralDepth`] when the referral chain
    /// exceeds its bound, [`Error::InvalidReferralTicket`] for a referral back
    /// to the same realm, and the request-building and reply-validation errors
    /// of [`super::exchange_tgs_req`].
    #[inline]
    pub fn step(&mut self, input: StepInput<'_>) -> Result<ExchangeStep, Error> {
        ticket::step(self, input)
    }

    /// The cross-realm TGTs obtained on the way, in hop order (explicit
    /// per-realm TGT sessions for the caller's cache).
    #[inline]
    #[must_use]
    pub fn referral_tgts(&self) -> &[TgsRepSession] {
        &self.referral_tgts
    }
}

impl Exchange for TicketCreds {
    #[inline]
    fn advance(&mut self, input: StepInput<'_>) -> Result<ExchangeStep, Error> {
        ticket::step(self, input)
    }

    #[inline]
    fn key_expiration(&self) -> Option<SystemTime> {
        None
    }
}

/// The FAST seam (RFC 6113): an armor wraps each AS request and unwraps each
/// reply. The engine threads the KDC's cookie and applies the strengthen key.
pub trait ArmoredExchange: Send {
    /// Wrap `request` and return the armored AS-REQ to send in its place.
    ///
    /// # Errors
    ///
    /// Returns the armor's failure; the exchange stops with [`Error::Armor`].
    fn armor_request(
        &mut self,
        request: &ArmorRequest<'_>,
    ) -> Result<Zeroizing<Vec<u8>>, ProviderError>;

    /// Unwrap the KDC's reply to an armored request.
    ///
    /// # Errors
    ///
    /// Returns the armor's failure, for example a reply that is not armored or
    /// fails its integrity check; the exchange stops with [`Error::Armor`].
    fn unwrap_reply(&mut self, reply: &[u8]) -> Result<ArmoredReply, ProviderError>;

    /// The armor key of an armored conversation, which the encrypted-challenge
    /// factor combines with the reply key (RFC 6113 section 5.4.6). The
    /// default has none, so the engine never answers an encrypted challenge.
    #[inline]
    fn armor_key(&self) -> Option<&EncryptionKey> {
        None
    }
}

/// What an [`ArmoredExchange`] wraps: the unarmored request and its parts.
#[derive(Clone, Copy)]
#[non_exhaustive]
pub struct ArmorRequest<'request> {
    /// The DER-encoded unarmored AS-REQ.
    pub request: &'request [u8],
    /// The DER-encoded KDC-REQ-BODY the armor's checksum covers.
    pub body: &'request [u8],
    /// The KDC's last cookie (PA-FX-COOKIE value), echoed in the armored request.
    pub cookie: Option<&'request [u8]>,
    /// Whether the caller asked for client canonicalization, which the engine
    /// strips from unarmored requests and only an armor may request.
    pub canonicalize: bool,
}

impl fmt::Debug for ArmorRequest<'_> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ArmorRequest")
            .field("request_bytes", &self.request.len())
            .field("body_bytes", &self.body.len())
            .field("cookie", &self.cookie.is_some())
            .field("canonicalize", &self.canonicalize)
            .finish()
    }
}

/// An unwrapped reply to an armored request.
#[non_exhaustive]
pub struct ArmoredReply {
    /// The inner reply: an AS-REP or a KRB-ERROR.
    reply: Zeroizing<Vec<u8>>,
    /// The strengthen key the KDC sent, combined into the reply key.
    strengthen_key: Option<EncryptionKey>,
    /// The KDC's new cookie, echoed in the next request.
    cookie: Option<Vec<u8>>,
    /// The client the armor authenticated (`KrbFastFinished`), which may differ
    /// from the requested one under canonicalization.
    authenticated_client: Option<Principal>,
}

impl ArmoredReply {
    /// An unwrapped reply with its optional strengthen key and cookie.
    #[inline]
    #[must_use]
    pub const fn new(
        reply: Zeroizing<Vec<u8>>,
        strengthen_key: Option<EncryptionKey>,
        cookie: Option<Vec<u8>>,
    ) -> Self {
        Self {
            reply,
            strengthen_key,
            cookie,
            authenticated_client: None,
        }
    }

    /// The same reply, with the client the armor authenticated.
    #[inline]
    #[must_use]
    pub fn with_authenticated_client(mut self, client: Principal) -> Self {
        self.authenticated_client = Some(client);
        self
    }
}

impl fmt::Debug for ArmoredReply {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ArmoredReply")
            .field("reply_bytes", &self.reply.len())
            .field("strengthen_key", &self.strengthen_key.is_some())
            .field("cookie", &self.cookie.is_some())
            .field("authenticated_client", &self.authenticated_client)
            .finish()
    }
}

/// One step of [`drive`]: answer prompts through `responder`, send outbound
/// requests through `transport`, until the exchange completes.
///
/// # Errors
///
/// Returns the exchange's errors, the transport's errors and
/// [`Error::Responder`] when the responder fails.
#[inline]
pub fn drive<T, E, R>(
    transport: &mut T,
    exchange: &mut E,
    responder: &mut R,
) -> Result<AsRepSession, Error>
where
    T: KdcTransport + ?Sized,
    E: Exchange + ?Sized,
    R: Responder + ?Sized,
{
    init::drive(transport, exchange, responder)
}

/// Run `exchange` over the Tokio transport, reusing the open connection for a
/// follow-up request as the AS login functions do.
///
/// # Errors
///
/// Returns the exchange's errors, the transport's errors and
/// [`Error::Responder`] when the responder fails.
///
/// # Cancel safety
///
/// Cancel-safe in the sense that no client or cache state changes: dropping
/// the future drops `responder`'s pending answer; the exchange keeps whatever
/// it received so far and erases its secrets when it is dropped. Repeat the
/// exchange from the start after a cancellation.
#[cfg(feature = "tokio")]
#[inline]
pub async fn drive_tokio<E, R>(
    transport: &TokioTransport,
    target: (&Config, KdcProtocol),
    exchange: &mut E,
    responder: &mut R,
) -> Result<AsRepSession, Error>
where
    E: Exchange + ?Sized,
    R: Responder + ?Sized,
{
    init::drive_tokio(transport, target, exchange, responder).await
}
