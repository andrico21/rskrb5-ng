//! The engine side of SPAKE preauthentication (RFC 9588; MIT 1.22.2
//! `get_in_tkt.c` with `spake_client.c`) and of `disable_encrypted_timestamp`.
//!
//! SPAKE starts when the KDC's PREAUTH_REQUIRED offers PA-SPAKE before an
//! encrypted timestamp the exchange may send, in `preferred_preauth_types`
//! order, and the policy has a usable group. The support message goes out with
//! the KDC's cookie; the challenge arrives in a MORE_PREAUTH_DATA_REQUIRED
//! error; the response request is sent with `K'[0]` as its reply key. After
//! SPAKE has started the exchange never tries another mechanism (MIT
//! `disable_fallback`, `get_in_tkt.c:1335`; stricter than MIT for a failure
//! before the response, see `preauth::spake`).

use rasn_kerberos::PaData;

use super::{
    Error, ExchangeStep, InitCreds, InitCredsOptions, KDC_ERR_PREAUTH_REQUIRED, KdcError,
    PA_ENC_TIMESTAMP, Principal, State, build_as_req, challenge_key, encode, order,
    preauth_retry_options, process_kdc_error, send, service,
};
use crate::{
    error::Spake as SpakeError,
    krb_error,
    preauth::spake::{self, KDC_ERR_MORE_PREAUTH_DATA_REQUIRED, PA_SPAKE},
};

/// A SPAKE exchange in progress.
pub(in super::super) struct Round {
    /// The client half.
    client: spake::Client,
    /// The `PREAUTH_REQUIRED` error whose etype information names the initial reply key.
    first: KdcError,
}

/// Whether the exchange may send an encrypted timestamp for its client realm
/// (MIT `encts_disabled`, `get_in_tkt.c:758-772,815-818`).
pub(super) fn timestamp_allowed(engine: &InitCreds<'_>) -> bool {
    !engine
        .options
        .timestamp_disabled
        .contains(&engine.client.realm)
}

/// Refuse the encrypted-timestamp answer when it is disabled for the client
/// realm (MIT `preauth_encts.c:68-73`).
///
/// # Errors
/// Returns [`Error::EncryptedTimestampDisabled`].
pub(super) fn check_timestamp(engine: &InitCreds<'_>) -> Result<(), Error> {
    if timestamp_allowed(engine) {
        Ok(())
    } else {
        Err(Error::EncryptedTimestampDisabled {
            realm: engine.client.realm.clone(),
        })
    }
}

/// Never send an optimistic encrypted timestamp for a realm that disables it.
pub(super) fn strip_timestamp(client: &Principal, options: &mut InitCredsOptions) {
    if options.timestamp_disabled.contains(&client.realm) {
        options.request = options.request.clone().with_assume_preauthentication(false);
    }
}

/// Start SPAKE when the KDC's first usable offer is PA-SPAKE.
///
/// # Errors
/// Returns the SPAKE, key-derivation and request-building errors.
pub(super) fn offer(
    engine: &mut InitCreds<'_>,
    reply: &[u8],
) -> Result<Option<ExchangeStep>, Error> {
    let policy = engine.options.spake.clone().unwrap_or_default();
    if !policy.is_usable() {
        return Ok(None);
    }
    let Ok(error) = process_kdc_error(reply) else {
        return Ok(None);
    };
    if error.error_code() != KDC_ERR_PREAUTH_REQUIRED {
        return Ok(None);
    }
    let allowed = timestamp_allowed(engine);
    let chosen = order::sorted(error.method_data(), &engine.options.preferred_preauth_types)
        .into_iter()
        .find(|offer| offer.r#type == PA_SPAKE || (offer.r#type == PA_ENC_TIMESTAMP && allowed))
        .filter(|offer| offer.r#type == PA_SPAKE)
        .map(|offer| offer.value.to_vec());
    let Some(value) = chosen else {
        return Ok(None);
    };
    let offers = error.method_data().to_vec();
    let round = Round {
        client: spake::Client::new(policy),
        first: error,
    };
    advance(engine, round, &offers, &value).map(Some)
}

/// Continue SPAKE with the KDC's answer to the support message.
///
/// # Errors
/// Returns the KDC error when it is not `MORE_PREAUTH_DATA_REQUIRED`, a SPAKE
/// error when it carries no PA-SPAKE, and the errors of [`offer`].
pub(super) fn reply(
    engine: &mut InitCreds<'_>,
    round: Round,
    reply: &[u8],
) -> Result<ExchangeStep, Error> {
    let error = process_kdc_error(reply)?;
    if error.error_code() != KDC_ERR_MORE_PREAUTH_DATA_REQUIRED {
        return Err(Error::Kdc(Box::new(error)));
    }
    let offers: Vec<PaData> = match error.e_data() {
        Some(bytes) => krb_error::decode_method_data(bytes).map_err(|_detail| {
            Error::Spake(SpakeError::Malformed {
                message: "METHOD-DATA of the KDC error".to_owned(),
            })
        })?,
        None => Vec::new(),
    };
    let value = offers
        .iter()
        .find(|offer| offer.r#type == PA_SPAKE)
        .map(|offer| offer.value.to_vec())
        .ok_or(Error::Spake(SpakeError::Unexpected {
            message: "a KDC error without PA-SPAKE",
        }))?;
    advance(engine, round, &offers, &value)
}

/// Answer one PA-SPAKE value with the KDC's cookies from `offers`.
///
/// # Errors
/// Returns the SPAKE, key-derivation and request-building errors.
fn advance(
    engine: &mut InitCreds<'_>,
    mut round: Round,
    offers: &[PaData],
    value: &[u8],
) -> Result<ExchangeStep, Error> {
    let mut options = preauth_retry_options(engine.options.request.clone(), offers);
    let unanswered = build_as_req(engine.client.clone(), service(engine), options.clone())?;
    let body = encode("KDC-REQ-BODY", &unanswered.message.0.req_body)?;
    let first = round.first.clone();
    let step = round
        .client
        .process(value, &body, || challenge_key(engine, &first))?;
    match step {
        spake::Step::Support(padata) => {
            options.padata_mut().push(padata);
            let request = build_as_req(engine.client.clone(), service(engine), options)?;
            send(engine, request, true, |_| State::Spake(Box::new(round)))
        }
        spake::Step::Response { padata, reply_key } => {
            options.padata_mut().push(padata);
            let request = build_as_req(engine.client.clone(), service(engine), options)?;
            engine.reply_key = Some(reply_key);
            send(engine, request, true, State::Final)
        }
    }
}
