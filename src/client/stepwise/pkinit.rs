//! The engine side of PKINIT (RFC 4556) and anonymous PKINIT (RFC 6112):
//! MIT 1.22.2 `get_in_tkt.c` with `pkinit_clnt.c`.
//!
//! The first request carries an empty `PA-AS-FRESHNESS` (MIT
//! `get_in_tkt.c:1364-1371`), so the KDC can hand out a freshness token with
//! its `PREAUTH_REQUIRED`. The PA-PK-AS-REQ then answers that error; its
//! checksums bind the request body, which is checked to be the one sent. The
//! reply key comes from the KDC's PA-PK-AS-REP, strengthened under FAST, and a
//! fully anonymous reply must prove its session key with `PA-PKINIT-KX`
//! (`get_in_tkt.c:139-203`). After PKINIT has started, nothing else is tried
//! (MIT `disable_fallback`, `pkinit_clnt.c:160`).

use std::time::SystemTime;

use rasn_kerberos::PaData;

use super::{
    BuiltAsReq, Error, ExchangeStep, InitCreds, KDC_ERR_PREAUTH_REQUIRED, State, build_as_req,
    decode, encode, padata_contains, preauth_retry_options, process_as_rep, process_kdc_error,
};
use crate::{
    crypto::Use,
    error::Pkinit,
    preauth::pkinit::{
        AnonymousOptions, Exchange as PkinitExchange, PA_AS_FRESHNESS, PA_PK_AS_REP, PA_PK_AS_REQ,
        PA_PKINIT_KX,
        exchange::{self, ReplyInput, RequestInput},
    },
};

/// The engine's PKINIT exchange.
///
/// # Errors
/// Returns [`Pkinit::Unexpected`] when the engine has none.
fn installed<'engine>(engine: &'engine InitCreds<'_>) -> Result<&'engine PkinitExchange, Error> {
    engine
        .pkinit
        .as_deref()
        .ok_or(Error::Pkinit(Pkinit::Unexpected {
            reason: "no PKINIT exchange is installed",
        }))
}

/// Send the first request with an empty `PA-AS-FRESHNESS`.
///
/// # Errors
/// Returns the request-building errors.
pub(super) fn start(engine: &mut InitCreds<'_>) -> Result<ExchangeStep, Error> {
    let mut options = engine.options.request.clone();
    if !padata_contains(options.padata(), PA_AS_FRESHNESS) {
        options.padata_mut().push(PaData {
            r#type: PA_AS_FRESHNESS,
            value: Vec::new().into(),
        });
    }
    let request = build_as_req(engine.client.clone(), super::service(engine), options)?;
    super::send(engine, request, false, State::Initial)
}

/// A PKINIT exchange never accepts a reply it cannot authenticate: an AS-REP
/// to the first request (no preauthentication) has no key it could decrypt.
///
/// # Errors
/// Returns [`Pkinit::Unexpected`] for a PKINIT exchange.
pub(super) const fn refuse_unauthenticated(engine: &InitCreds<'_>) -> Result<(), Error> {
    if engine.pkinit.is_some() {
        return Err(Error::Pkinit(Pkinit::Unexpected {
            reason: "the KDC issued a ticket without PKINIT",
        }));
    }
    Ok(())
}

/// Answer the KDC's `PREAUTH_REQUIRED` with a PA-PK-AS-REQ.
///
/// # Errors
/// Returns the KDC's error when it is not `PREAUTH_REQUIRED`,
/// [`Pkinit::NotOffered`] without a PA-PK-AS-REQ offer, and the PKINIT and
/// request-building errors.
pub(super) fn offer(
    engine: &mut InitCreds<'_>,
    reply: &[u8],
    at: Option<(SystemTime, u32)>,
) -> Result<ExchangeStep, Error> {
    let error = process_kdc_error(reply)?;
    if error.error_code() != KDC_ERR_PREAUTH_REQUIRED {
        return Err(Error::Kdc(Box::new(error)));
    }
    let offers = error.method_data();
    if !padata_contains(offers, PA_PK_AS_REQ) {
        return Err(Pkinit::NotOffered.into());
    }
    let freshness = offers
        .iter()
        .find(|entry| entry.r#type == PA_AS_FRESHNESS && !entry.value.is_empty())
        .map(|entry| entry.value.to_vec());
    let options = preauth_retry_options(engine.options.request.clone(), offers);
    let client = engine.client.clone();
    let unanswered = build_as_req(client.clone(), super::service(engine), options.clone())?;
    let body = encode("KDC-REQ-BODY", &unanswered.message.0.req_body)?;
    let time = match at {
        Some(kdc_time) => kdc_time,
        None => super::now()?,
    };
    let (value, pending) = exchange::request(
        installed(engine)?,
        &RequestInput {
            client: &client,
            body: &body,
            nonce: unanswered.nonce,
            time,
            freshness: freshness.as_deref(),
        },
    )?;
    engine.pkinit_pending = Some(pending);
    let mut answered = options;
    answered.padata_mut().push(PaData {
        r#type: PA_PK_AS_REQ,
        value: value.into(),
    });
    let request = build_as_req(client, super::service(engine), answered)?;
    if encode("KDC-REQ-BODY", &request.message.0.req_body)? != body {
        return Err(Error::Pkinit(Pkinit::Unexpected {
            reason: "the request body differs from the checksummed one",
        }));
    }
    super::send(engine, request, true, State::Pkinit)
}

/// The AS-REP to a PA-PK-AS-REQ: derive the reply key, decrypt, and check an
/// anonymous reply.
///
/// # Errors
/// Returns the KDC's error, [`Pkinit::Malformed`] without a PA-PK-AS-REP,
/// the PKINIT errors and the AS-REP validation errors.
pub(super) fn reply(
    engine: &mut InitCreds<'_>,
    request: &BuiltAsReq,
    reply: &[u8],
) -> Result<ExchangeStep, Error> {
    if let Ok(error) = process_kdc_error(reply) {
        return Err(Error::Kdc(Box::new(error)));
    }
    let rasn_kerberos::AsRep(as_rep) = decode("AS-REP", reply)?;
    let padata = as_rep.padata.as_deref().unwrap_or_default();
    let found = |kind: i32| {
        padata
            .iter()
            .find(|entry| entry.r#type == kind)
            .map(|entry| entry.value.to_vec())
    };
    let pk_as_rep = found(PA_PK_AS_REP).ok_or(Error::Pkinit(Pkinit::Malformed {
        structure: "AS-REP",
        reason: "no PA-PK-AS-REP answers the PA-PK-AS-REQ",
    }))?;
    let etype = as_rep.enc_part.etype;
    request.crypto_policy.check_use(etype, Use::ReplyKey)?;
    let pending = engine
        .pkinit_pending
        .take()
        .ok_or(Error::Pkinit(Pkinit::Unexpected {
            reason: "a PA-PK-AS-REP before any PA-PK-AS-REQ",
        }))?;
    let reply_key = exchange::reply_key(
        installed(engine)?,
        pending,
        &ReplyInput {
            pk_as_rep: &pk_as_rep,
            request: &request.der,
            client: &request.client,
            server: &request.service,
            etype,
            now: SystemTime::now(),
        },
    )?;
    let canonical = super::canonical_request(engine, request);
    let session = process_as_rep(
        canonical.as_ref().unwrap_or(request),
        reply,
        &super::strengthened(engine, reply_key.clone())?,
    )?;
    if engine.options.anonymous == Some(AnonymousOptions::Full) {
        exchange::verify_anonymous(
            found(PA_PKINIT_KX).as_deref(),
            &reply_key,
            session.session_key(),
        )?;
    }
    Ok(super::finish(engine, request, session))
}

/// The request with the client name an anonymous reply must carry.
pub(super) fn anonymous_request(anonymous: AnonymousOptions, request: &BuiltAsReq) -> BuiltAsReq {
    let mut expected = request.clone();
    expected.client = anonymous.expected_client(&request.client.realm);
    expected
}
