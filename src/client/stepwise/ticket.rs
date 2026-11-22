//! The TGS state machine.
//!
//! One request per hop, following cross-realm referrals up to the caller's
//! bound, as the Tokio referral functions do.

use core::{fmt, mem};

use super::{
    super::{
        AsRepSession, BuiltTgsReq, Error, KRB_NT_SRV_INST, Principal, build_tgs_req_for_realm,
        principal_matches, process_tgs_rep_with_referral, tgt_realm, ticket_error,
    },
    ExchangeStep, Outbound, StepInput, TicketCreds, TicketOptions,
};
use crate::ticket::decode as decode_ticket;

/// The `ENC-TKT-IN-SKEY` KDC option bit (RFC 4120 section 5.4.1, bit 28).
const ENC_TKT_IN_SKEY: u32 = 0x0000_0008;

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
            let ticket =
                match process_tgs_rep_with_referral(&pending, reply, engine.tgt.session_key()) {
                    Ok(ticket) => ticket,
                    Err(Error::Kdc(_)) if !for_service && back_off(engine) => {
                        return request(engine);
                    }
                    Err(error) => return Err(error),
                };
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
    let request = build_tgs_req_for_realm(&engine.tgt, current, requested, options)?;
    let outbound = Outbound {
        realm: request.kdc_realm.clone(),
        message: request.der.clone(),
        follow_up: false,
    };
    engine.state = State::Await(Box::new(request));
    Ok(ExchangeStep::Outbound(outbound))
}
