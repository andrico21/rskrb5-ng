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
        service.realm = realm;
    }
    Ok(TicketCreds {
        tgt,
        service,
        options,
        state: State::Start,
        referral_tgts: Vec::new(),
        trace: None,
    })
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
            let ticket = process_tgs_rep_with_referral(&pending, reply, engine.tgt.session_key())?;
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

/// Build the request of the current hop: the service itself in its realm, else
/// the cross-realm TGS of the target realm.
///
/// # Errors
/// Returns the typed failure of the step; the exchange cannot continue after it.
fn request(engine: &mut TicketCreds) -> Result<ExchangeStep, Error> {
    let current = tgt_realm(&engine.tgt).ok_or_else(|| Error::InvalidReferralTicket {
        service: engine.tgt.service.name(),
    })?;
    let target = engine.service.realm.clone();
    let mut options = engine.options.request.clone();
    let requested = if current == target {
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
