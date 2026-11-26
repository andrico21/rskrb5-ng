//! The TGS state machine.
//!
//! One request per hop, following cross-realm referrals up to the caller's
//! bound, as the Tokio referral functions do.

use core::{fmt, mem};

use super::{
    super::{
        AsRepSession, BuiltTgsReq, Error, KRB_NT_SRV_INST, Principal, TgsFastRequestParts,
        TgsRepSession, build_tgs_req_for_realm, build_tgs_req_for_realm_with_subkey, crypto_policy,
        options::TgsReq, principal_matches, process_tgs_rep_with_referral, tgt_realm, ticket_error,
    },
    ExchangeStep, FastOutcome, FastPolicy, Outbound, StepInput, TicketCreds, TicketOptions,
};
use crate::{
    error::Fast as FastError,
    extensions::ProviderError,
    keytab::EncryptionKey,
    preauth::fast::tgs::{self, Armor},
    ticket::decode as decode_ticket,
};

/// The `ENC-TKT-IN-SKEY` KDC option bit (RFC 4120 section 5.4.1, bit 28).
const ENC_TKT_IN_SKEY: u32 = 0x0000_0008;

/// The FAST state of a TGS exchange.
pub(super) struct Fast {
    /// How the requests are armored.
    policy: FastPolicy,
    /// What the replies so far showed.
    outcome: Option<FastOutcome>,
}

impl Fast {
    /// FAST under `policy`, with nothing seen yet.
    pub(super) const fn new(policy: FastPolicy) -> Self {
        Self {
            policy,
            outcome: None,
        }
    }

    /// What the replies so far showed.
    pub(super) const fn outcome(&self) -> Option<FastOutcome> {
        self.outcome
    }

    /// Fold what one authenticated reply showed into the outcome: the exchange
    /// is armored only while every reply was.
    fn record(&mut self, seen: FastOutcome) {
        self.outcome = Some(
            if seen == FastOutcome::Unarmored || self.outcome == Some(FastOutcome::Unarmored) {
                FastOutcome::Unarmored
            } else {
                FastOutcome::Armored
            },
        );
    }
}

/// Where a TGS exchange stands.
pub(super) enum State {
    /// Nothing sent yet.
    Start,
    /// A request is out.
    Await(Box<BuiltTgsReq>),
    /// Finished or failed.
    Done,
}

/// A new exchange.
///
/// # Errors
/// Returns [`Error::InvalidReferralTicket`] when `tgt` is not a TGT.
pub(super) fn new(
    tgt: AsRepSession,
    mut service: Principal,
    options: TicketOptions,
) -> Result<TicketCreds, Error> {
    let realm = tgt_realm(&tgt).ok_or_else(|| Error::InvalidReferralTicket {
        service: tgt.service.name(),
    })?;
    if service.realm.is_empty() {
        service.realm.clone_from(&realm);
    }
    let walk = options
        .realm_path
        .as_ref()
        .map(|path| path.realms().to_vec())
        .filter(|realms| realms.first() == Some(&realm) && realms.last() == Some(&service.realm))
        .map(|realms| Walk {
            next: realms.len().saturating_sub(1),
            current: 0,
            realms,
        });
    Ok(TicketCreds {
        tgt,
        service,
        options,
        state: State::Start,
        referral_tgts: Vec::new(),
        seen_realms: vec![realm],
        walk,
        trace: None,
        fast: Fast::new(FastPolicy::Off),
        armor: None,
    })
}

/// The position on a configured client path (MIT 1.22.2 `get_creds.c:225-229`).
pub(super) struct Walk {
    /// The realms of the path, the client realm first.
    realms: Vec<String>,
    /// The index of the realm of the current TGT.
    current: usize,
    /// The index of the realm whose TGT is requested next.
    next: usize,
}

/// Redacted `Debug`.
///
/// # Errors
/// Returns the typed failure of the step; the exchange cannot continue after it.
pub(super) fn debug(engine: &TicketCreds, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
        .debug_struct("TicketCreds")
        .field("service", &engine.service)
        .field("tgt_service", &engine.tgt.service)
        .field("referrals", &engine.referral_tgts.len())
        .field("user_to_user", &engine.options.second_ticket.is_some())
        .field("fast", &engine.fast.policy)
        .finish_non_exhaustive()
}

/// Request a user-to-user ticket.
///
/// # Errors
/// Returns [`Error::Decode`] for bytes that are not a DER Ticket.
pub(super) fn with_user_to_user(
    mut options: TicketOptions,
    second_ticket: &[u8],
) -> Result<TicketOptions, Error> {
    let ticket = decode_ticket(second_ticket).map_err(ticket_error)?;
    options.second_ticket = Some(ticket);
    Ok(options)
}

/// Set or clear one KDC option bit.
pub(super) fn with_flag(mut options: TicketOptions, bit: u32, set: bool) -> TicketOptions {
    let bits = options.request.kdc_option_bits();
    options.request =
        options
            .request
            .with_kdc_option_bits(if set { bits | bit } else { bits & !bit });
    options
}

/// Advance the exchange; any error leaves it finished.
///
/// # Errors
/// Returns the typed failure of the step; the exchange cannot continue after it.
pub(super) fn step(engine: &mut TicketCreds, input: StepInput<'_>) -> Result<ExchangeStep, Error> {
    if let Some(tracer) = &engine.trace {
        tracer.input(&input, (&engine.tgt.client, &engine.service));
    }
    let result = advance(engine, input);
    if let Some(tracer) = &mut engine.trace {
        tracer.output(&result);
    }
    result
}

/// Advance the exchange without tracing.
///
/// # Errors
/// Returns the typed failure of the step; the exchange cannot continue after it.
fn advance(engine: &mut TicketCreds, input: StepInput<'_>) -> Result<ExchangeStep, Error> {
    match (mem::replace(&mut engine.state, State::Done), input) {
        (State::Start, StepInput::Start) => request(engine),
        (State::Await(pending), StepInput::Reply(reply)) => {
            let for_service = principal_matches(&pending.service, &engine.service);
            let armor = engine.armor.take();
            let required = engine.fast.policy == FastPolicy::Required;
            let (ticket, seen) = match process(
                (&pending, reply),
                armor.as_ref().map(|armored| (armored, required)),
                engine.tgt.session_key(),
            ) {
                Ok(processed) => processed,
                Err(Error::Kdc(_)) if !for_service && back_off(engine) => {
                    return request(engine);
                }
                Err(error) => return Err(error),
            };
            if let Some(outcome) = seen {
                engine.fast.record(outcome);
            }
            if principal_matches(&ticket.service, &engine.service) {
                return Ok(ExchangeStep::Complete(Box::new(ticket)));
            }
            let current = tgt_realm(&engine.tgt).unwrap_or_default();
            let referred = tgt_realm(&ticket).ok_or_else(|| Error::ServicePrincipalMismatch {
                expected: engine.service.name(),
                actual: ticket.service.name(),
            })?;
            if referred == current {
                return Err(Error::InvalidReferralTicket {
                    service: ticket.service.name(),
                });
            }
            if engine.referral_tgts.len() >= engine.options.max_referrals {
                return Err(Error::MaxReferralDepth {
                    max: engine.options.max_referrals,
                });
            }
            if engine.seen_realms.contains(&referred) {
                return Err(Error::ReferralLoop { realm: referred });
            }
            engine.seen_realms.push(referred.clone());
            if for_service {
                // FU-IOP-P12: a referral answering the service request names the
                // service's realm (MIT 1.22.2 `get_creds.c:625-633`).
                engine.service.realm.clone_from(&referred);
            } else {
                advance_walk(engine, &referred);
            }
            engine.referral_tgts.push(ticket.clone());
            engine.tgt = ticket;
            request(engine)
        }
        (state, _) => {
            let expected = match state {
                State::Start => "start",
                State::Await(_) => "a KDC reply",
                State::Done => "nothing (the exchange is finished)",
            };
            engine.state = state;
            Err(Error::UnexpectedStepInput { expected })
        }
    }
}

/// Authenticate and validate the reply to the request, and report whether it
/// was armored.
///
/// `armor` is the armor of an armored request and whether the exchange
/// requires FAST. A reply to an armored request that fails FAST
/// authentication is the error of the exchange: it is never read as a plain
/// reply. `tgt_key` decrypts the reply to an unarmored request.
///
/// # Errors
/// Returns [`Error::Armor`] for the FAST failure of a reply and the errors of
/// [`process_tgs_rep_with_referral`].
fn process(
    (request, reply): (&BuiltTgsReq, &[u8]),
    armored: Option<(&Armor, bool)>,
    tgt_key: &EncryptionKey,
) -> Result<(TgsRepSession, Option<FastOutcome>), Error> {
    let Some((armor, required)) = armored else {
        return Ok((
            process_tgs_rep_with_referral(request, reply, tgt_key)?,
            None,
        ));
    };
    let (_armor_key, subkey, _nonce) = armor;
    match tgs::unwrap(armor, reply, required).map_err(armor_error)? {
        tgs::Reply::Unarmored => Ok((
            process_tgs_rep_with_referral(request, reply, subkey)?,
            Some(FastOutcome::Unarmored),
        )),
        tgs::Reply::Error(inner) => Ok((
            process_tgs_rep_with_referral(request, &inner, subkey)?,
            None,
        )),
        tgs::Reply::Success { reply: inner, key } => Ok((
            process_tgs_rep_with_referral(request, &inner, &key)?,
            Some(FastOutcome::Armored),
        )),
    }
}

/// The exchange error of a FAST failure.
fn armor_error(error: FastError) -> Error {
    Error::Armor(ProviderError::from(error))
}

/// After a KDC refused a TGT on the configured path, ask for the next closer
/// realm (MIT 1.22.2 `get_creds.c:923-932`); `false` when none is left.
const fn back_off(engine: &mut TicketCreds) -> bool {
    let Some(walk) = engine.walk.as_mut() else {
        return false;
    };
    let closer = walk.next.saturating_sub(1);
    if closer <= walk.current {
        return false;
    }
    walk.next = closer;
    true
}

/// Move along the configured path to the realm of a new TGT, or leave the path
/// for an off-path referral (MIT 1.22.2 `get_creds.c:949-972`).
fn advance_walk(engine: &mut TicketCreds, referred: &str) {
    if let Some(walk) = engine.walk.as_mut() {
        let ahead = walk
            .realms
            .iter()
            .enumerate()
            .skip(walk.current.saturating_add(1))
            .find(|&(_, realm)| realm == referred)
            .map(|(index, _)| index);
        if let Some(index) = ahead {
            walk.current = index;
            walk.next = walk.realms.len().saturating_sub(1);
        } else {
            engine.walk = None;
        }
    }
}

/// Build the request of the current hop: the service itself in its realm, else
/// the cross-realm TGS of the target realm.
///
/// # Errors
/// Returns the typed failure of the step; the exchange cannot continue after it.
fn request(engine: &mut TicketCreds) -> Result<ExchangeStep, Error> {
    let current = tgt_realm(&engine.tgt).ok_or_else(|| Error::InvalidReferralTicket {
        service: engine.tgt.service.name(),
    })?;
    let target = engine
        .walk
        .as_ref()
        .and_then(|walk| walk.realms.get(walk.next))
        .cloned()
        .unwrap_or_else(|| engine.service.realm.clone());
    let mut options = engine.options.request.clone();
    let requested = if current == engine.service.realm {
        if let Some(ticket) = &engine.options.second_ticket {
            let bits = options.kdc_option_bits() | ENC_TKT_IN_SKEY;
            options = options
                .with_kdc_option_bits(bits)
                .with_additional_tickets(vec![ticket.clone()]);
        }
        engine.service.clone()
    } else {
        Principal::new(
            current.clone(),
            KRB_NT_SRV_INST,
            ["krbtgt".to_owned(), target],
        )
    };
    let (request, armor) = match engine.fast.policy {
        FastPolicy::Off => (
            build_tgs_req_for_realm(&engine.tgt, current, requested, options)?,
            None,
        ),
        FastPolicy::Opportunistic | FastPolicy::Required => {
            let (request, armor) = armored(&engine.tgt, (current, requested), options)?;
            (request, Some(armor))
        }
    };
    engine.armor = armor;
    let outbound = Outbound {
        realm: request.kdc_realm.clone(),
        message: request.der.clone(),
        follow_up: false,
    };
    engine.state = State::Await(Box::new(request));
    Ok(ExchangeStep::Outbound(outbound))
}

/// Build the request with a fresh authenticator subkey and armor it with the
/// TGT (MIT `k5_make_tgs_req`, `send_tgs.c:172-179,279-281`).
///
/// # Errors
/// Returns the request-building errors, [`Error::Armor`] for the armor's
/// failure and the policy refusal of the padata it adds.
fn armored(
    tgt: &AsRepSession,
    (realm, service): (String, Principal),
    options: TgsReq,
) -> Result<(BuiltTgsReq, Armor), Error> {
    let TgsFastRequestParts {
        mut request,
        ap_req_der,
        authenticator_subkey,
    } = build_tgs_req_for_realm_with_subkey(tgt, realm, service, options)?;
    let (message, der, armor) = tgs::wrap(
        (&request.message, &ap_req_der),
        (&authenticator_subkey, tgt.session_key()),
        &request.crypto_policy,
    )
    .map_err(armor_error)?;
    crypto_policy::padata(
        &request.crypto_policy,
        message.0.padata.as_deref().unwrap_or_default(),
    )?;
    request.message = message;
    request.der = der;
    Ok((request, armor))
}
