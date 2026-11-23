//! The IAKERB initiator.
//!
//! The initiator of MIT 1.22.2 `iakerb_initiator_step` (`iakerb.c:571-706`):
//! optional realm discovery, the AS exchange, the TGS exchange (each request
//! sent as a proxy token and each reply read from one), then the AP exchange
//! with the `IAKERB-FINISHED` of the transcript in the authenticator checksum
//! (`init_sec_context.c:313-345`).

use core::mem;
use std::time::{SystemTime, UNIX_EPOCH};

use zeroize::Zeroizing;

use super::{
    AP_REP_TOKEN_ID, AP_REQ_TOKEN_ID, Error, Token, conversation::Conversation, finished, frame,
    unframe,
};
use crate::{
    ap_rep,
    client::{
        AsRepSession, Password, TgsRepSession,
        options::ApReq,
        principal::Principal,
        stepwise::{
            ExchangeStep, InitCreds, InitCredsOptions, Outbound, StepInput, TicketCreds,
            TicketOptions,
        },
    },
    crypto::{KerberosEtype, Use},
    error::Gss,
    gss::{
        ChannelBindings, ContextFlags, Credential, CredentialUsage, EncryptionKey,
        EstablishedContext, InitStep, InitiatorOptions, Name, cred, checksum,
        initiator::{random_key, random_sequence},
        seq,
    },
    krb_error,
};

/// The AP option `mutual-required` (RFC 4120 section 5.5.1, bit 2).
const MUTUAL_REQUIRED: u32 = 0x2000_0000;
/// The flags an initiator may put in its checksum (MIT `init_sec_context.c:546-550`).
const SENT_FLAGS: ContextFlags = ContextFlags::from_bits(
    ContextFlags::CONF.bits()
        | ContextFlags::INTEG.bits()
        | ContextFlags::MUTUAL.bits()
        | ContextFlags::REPLAY.bits()
        | ContextFlags::SEQUENCE.bits()
        | ContextFlags::IDENTIFY.bits()
        | ContextFlags::EXTENDED_ERROR.bits(),
);
/// `KRB_AP_ERR_IAKERB_KDC_NOT_FOUND`.
const KDC_NOT_FOUND: i32 = 85;
/// `KRB_AP_ERR_IAKERB_KDC_NO_RESPONSE`.
const KDC_NO_RESPONSE: i32 = 86;

/// What the initiator keeps between the AP-REQ and the AP-REP.
pub(super) struct Pending {
    /// The context, its acceptor's part not yet known.
    context: EstablishedContext,
    /// The authenticator's whole-second time.
    ctime: SystemTime,
    /// The authenticator's microseconds.
    cusec: u32,
}

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
/// Returns the errors of [`super::IakerbContext::init_sec_context`].
pub(super) fn step(
    state: &mut State,
    conversation: &mut Conversation,
    credential: &Credential,
    input: Option<&[u8]>,
) -> Result<InitStep, Error> {
    match (mem::replace(&mut state.phase, Phase::Done), input) {
        (Phase::Start, None) => start(state, conversation, credential),
        (Phase::Reply(pending), Some(token)) => reply(state, *pending, token),
        (phase @ (Phase::Discovery | Phase::As(_) | Phase::Tgs(_)), Some(token)) => {
            proxied(state, conversation, credential, phase, token)
        }
        (phase, _) => {
            state.phase = phase;
            Err(Error::UnexpectedStep("the initiator does not expect this input"))
        }
    }
}

/// The first step: a discovery token, or the first request.
///
/// # Errors
///
/// Returns the errors of [`step`].
fn start(
    state: &mut State,
    conversation: &mut Conversation,
    credential: &Credential,
) -> Result<InitStep, Error> {
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
        return begin(state, conversation, credential);
    }
    let token = conversation.produce(Token::new("", None, Vec::new()).encode()?)?;
    state.phase = Phase::Discovery;
    Ok(InitStep::Continue(token))
}

/// Choose where to enter the exchanges once the client's realm is known: a
/// cached service ticket needs no relay, a cached TGT only the TGS exchange
/// (MIT `iakerb_get_initial_state`, `iakerb.c:713-772`).
///
/// # Errors
///
/// Returns [`Error::Gss`] without a ticket source, and the exchange errors.
fn begin(
    state: &mut State,
    conversation: &mut Conversation,
    credential: &Credential,
) -> Result<InitStep, Error> {
    if let Some(ticket) = cred::service_ticket(credential, &state.target) {
        return ap(state, conversation, ticket);
    }
    let client = state.client.clone().ok_or(Gss::NoCredential("no client"))?;
    let tgt = credential.cache.as_ref().and_then(|cache| {
        let realm = &client.realm;
        cache
            .credentials()
            .iter()
            .find(|entry| {
                entry.server().components == ["krbtgt", realm.as_str()]
                    && entry.server().realm == *realm
                    && entry.times().end_time != 0
            })
            .map(cred::session_of)
    });
    if let Some(tgt) = tgt {
        return advance(state, conversation, credential, Phase::Tgs(Box::new(ticket_creds(state, tgt)?)), StepInput::Start);
    }
    let options = state.exchanges.0.clone();
    let exchange = if let Some(password) = &credential.password {
        InitCreds::with_password(client, Some(Password::from_vec(password.to_vec())), options)
    } else if let Some(keytab) = &credential.client_keytab {
        InitCreds::with_keytab(client, keytab.clone(), options)
    } else {
        return Err(Gss::NoCredential("no ticket source").into());
    };
    advance(state, conversation, credential, Phase::As(Box::new(exchange)), StepInput::Start)
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
    conversation: &mut Conversation,
    credential: &Credential,
    mut phase: Phase,
    mut input: StepInput<'_>,
) -> Result<InitStep, Error> {
    loop {
        match phase {
            Phase::As(mut exchange) => match exchange.step(input)? {
                ExchangeStep::Outbound(outbound) => {
                    state.phase = Phase::As(exchange);
                    return send(state, conversation, &outbound);
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
                    return send(state, conversation, &outbound);
                }
                ExchangeStep::Complete(ticket) => return ap(state, conversation, *ticket),
                ExchangeStep::Prompt(_) => return Err(Error::UnsupportedPrompt),
            },
            Phase::Start
            | Phase::Discovery
            | Phase::Reply(_)
            | Phase::Established(_)
            | Phase::Done => {
                let _unused = credential;
                return Err(Error::UnexpectedStep("no exchange is running"));
            }
        }
    }
}

/// Send `outbound` as a proxy token, echoing the proxy's cookie.
///
/// # Errors
///
/// Returns the token and round-bound errors.
fn send(
    state: &State,
    conversation: &mut Conversation,
    outbound: &Outbound,
) -> Result<InitStep, Error> {
    let token = Token::new(
        outbound.realm(),
        state.cookie.clone(),
        outbound.message().to_vec(),
    )
    .encode()?;
    Ok(InitStep::Continue(conversation.produce(token)?))
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
fn proxied(
    state: &mut State,
    conversation: &mut Conversation,
    credential: &Credential,
    phase: Phase,
    token: &[u8],
) -> Result<InitStep, Error> {
    conversation.check_size(token.len())?;
    let parsed = Token::decode(token)?;
    conversation.append(token)?;
    state.cookie = parsed.cookie().map(<[u8]>::to_vec);
    match error_code(parsed.message()) {
        Some(KDC_NOT_FOUND) => return Err(Error::KdcNotFound),
        Some(KDC_NO_RESPONSE) => return Err(Error::KdcNoResponse),
        Some(_) | None => {}
    }
    if let Phase::Discovery = phase {
        if parsed.realm().is_empty() {
            return Err(Error::BadToken("the acceptor sent no realm"));
        }
        let client = state.client.as_mut().ok_or(Gss::NoCredential("no client"))?;
        parsed.realm().clone_into(&mut client.realm);
        return begin(state, conversation, credential);
    }
    if parsed.message().is_empty() {
        return Err(Error::BadToken("the acceptor sent no KDC message"));
    }
    advance(state, conversation, credential, phase, StepInput::Reply(parsed.message()))
}

/// The flags the initiator sends: its request, within what it may send.
fn flags(options: &InitiatorOptions) -> ContextFlags {
    options.flags.intersection(SENT_FLAGS)
        | ContextFlags::TRANS
        | ContextFlags::CONF
        | ContextFlags::INTEG
}

/// The current time as whole seconds and microseconds.
///
/// # Errors
///
/// Returns [`Gss::ContextExpired`] for a clock before the epoch.
fn now() -> Result<(SystemTime, u32), Error> {
    let since = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_before| Gss::ContextExpired)?;
    let whole = UNIX_EPOCH
        .checked_add(core::time::Duration::from_secs(since.as_secs()))
        .ok_or(Gss::ContextExpired)?;
    Ok((whole, since.subsec_micros()))
}

/// The AP-REQ with `ticket`, carrying the finished checksum of the transcript.
///
/// # Errors
///
/// Returns the policy, checksum and AP-REQ errors.
fn ap(
    state: &mut State,
    conversation: &Conversation,
    ticket: TgsRepSession,
) -> Result<InitStep, Error> {
    let options = &state.options;
    if options.flags.contains(ContextFlags::DCE_STYLE) {
        return Err(Gss::NotNegotiated("DCE-style establishment").into());
    }
    options
        .crypto_policy
        .check_use(ticket.session_key().etype(), Use::SessionKey)
        .map_err(Gss::from)?;
    let flags = flags(options);
    let digest = options
        .bindings
        .as_ref()
        .map_or([0; 16], ChannelBindings::digest);
    let subkey = random_key(ticket.session_key().etype())?;
    let sequence = random_sequence()?;
    let mut value = checksum::encode(&digest, flags, None)?;
    if !conversation.transcript().is_empty() {
        let proof = finished::make(&subkey, conversation.transcript())?;
        value.extend_from_slice(&finished::extension(&proof)?);
    }
    let cbt = options.flags.contains(ContextFlags::CHANNEL_BOUND)
        || options.client_aware_channel_bindings;
    let mut request = ApReq::new()
        .with_ap_option_bits(if flags.contains(ContextFlags::MUTUAL) {
            MUTUAL_REQUIRED
        } else {
            0
        })
        .with_checksum(Some(rasn_kerberos::Checksum {
            r#type: checksum::CHECKSUM_TYPE,
            checksum: value.into(),
        }))
        .with_subkey(Some(subkey.clone()))
        .with_sequence_number(Some(sequence))
        .with_authorization_data(cbt.then(checksum::cbt_authorization_data).transpose()?);
    request.set_crypto_policy(Some(options.crypto_policy.clone()));
    let kind = KerberosEtype::from_etype_id(ticket.session_key().etype())
        .ok_or(Gss::LegacyTokenFormat(ticket.session_key().etype()))?;
    let mut confounder = Zeroizing::new(vec![0; kind.confounder_len()]);
    getrandom::fill(&mut confounder)?;
    let (ctime, cusec) = now()?;
    let built =
        crate::client::build_ap_req_with_confounder(&ticket, request, ctime, cusec, &confounder)?;
    let token = frame(AP_REQ_TOKEN_ID, built.der())?;
    let context = established(&ticket, subkey, sequence, flags, options);
    if flags.contains(ContextFlags::MUTUAL) {
        state.phase = Phase::Reply(Box::new(Pending {
            context,
            ctime,
            cusec,
        }));
        return Ok(InitStep::Continue(token));
    }
    state.phase = Phase::Established(Box::new(context));
    Ok(InitStep::Complete(Some(token)))
}

/// The initiator's context, with no acceptor part yet.
fn established(
    ticket: &TgsRepSession,
    subkey: EncryptionKey,
    sequence: u32,
    flags: ContextFlags,
    options: &InitiatorOptions,
) -> EstablishedContext {
    let flags = flags | ContextFlags::PROT_READY;
    let first = u64::from(sequence);
    EstablishedContext {
        initiated: true,
        source: Name::from_principal(ticket.client()),
        target: Name::from_principal(ticket.service()),
        flags,
        session_key: ticket.session_key().clone(),
        initiator_subkey: Some(subkey),
        acceptor_subkey: None,
        send_sequence: first,
        window: seq::Window::new(
            first,
            flags.contains(ContextFlags::REPLAY),
            flags.contains(ContextFlags::SEQUENCE),
        ),
        expires: ticket.end_time(),
        crypto_policy: options.crypto_policy.clone(),
        delegated: None,
        pac: None,
    }
}

/// The acceptor's AP-REP: verify it and complete the context.
///
/// # Errors
///
/// Returns the AP-REP decryption, policy and echo errors.
fn reply(state: &mut State, pending: Pending, token: &[u8]) -> Result<InitStep, Error> {
    let Pending {
        mut context,
        ctime,
        cusec: sent,
    } = pending;
    let (id, body) = unframe(token)?;
    if id != AP_REP_TOKEN_ID {
        return Err(Error::UnexpectedStep("the acceptor did not answer with an AP-REP"));
    }
    let policy = context.crypto_policy.clone();
    let wire = ap_rep::decode(body)?;
    policy
        .check_use(wire.enc_part.etype, Use::SessionKey)
        .map_err(Gss::from)?;
    let part = ap_rep::decrypt_ap_rep_enc_part(&wire, &context.session_key)?;
    let echoed = crate::client::time::from_kerberos(&part.ctime);
    let cusec = part.cusec.to_string().parse::<u32>().ok();
    if echoed != Some(ctime) || cusec != Some(sent) {
        return Err(Gss::DefectiveToken("the AP-REP does not echo the authenticator").into());
    }
    context.acceptor_subkey = match &part.subkey {
        Some(key) => {
            policy
                .check_use(key.r#type, Use::AcceptorSubkey)
                .map_err(Gss::from)?;
            Some(EncryptionKey::new(key.r#type, key.value.to_vec()))
        }
        None => None,
    };
    context.window = seq::Window::new(
        part.seq_number.map_or(0, u64::from),
        context.flags.contains(ContextFlags::REPLAY),
        context.flags.contains(ContextFlags::SEQUENCE),
    );
    state.phase = Phase::Established(Box::new(context));
    Ok(InitStep::Complete(None))
}
