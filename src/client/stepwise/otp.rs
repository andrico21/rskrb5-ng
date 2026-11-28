//! The engine side of OTP preauthentication (RFC 6560; MIT 1.22.2
//! `preauth_otp.c:982-1134`).
//!
//! With an OTP policy installed ([`InitCreds::with_otp`]), an armored
//! `PREAUTH_REQUIRED` that offers `PA-OTP-CHALLENGE` is decoded and put to the
//! caller as [`Prompt::Otp`]; the answer becomes a `PA-OTP-REQUEST` inside the
//! armored request and the reply key is the armor key. The caller's choice comes
//! first: an offered mechanism named in `preferred_preauth_types` ahead of
//! `PA-OTP-CHALLENGE` is answered instead. OTP needs no password, so the offer is
//! handled before the password prompt. After the OTP request the exchange never
//! tries another mechanism and never retries the value.

use super::{
    Answer, ENCRYPTED_CHALLENGE, Error, ExchangeStep, InitCreds, KDC_ERR_PREAUTH_REQUIRED,
    KdcError, PA_ENC_TIMESTAMP, Prompt, State, Use, build_as_req, crypto_policy, permits,
    preauth_retry_options, process_kdc_error,
};
use crate::{
    error::Otp,
    keytab::EncryptionKey,
    preauth::{
        fast::PA_ENCRYPTED_CHALLENGE,
        otp::{Challenge, PA_OTP_CHALLENGE},
        spake::PA_SPAKE,
    },
};

/// An OTP prompt in progress: the challenge asked about and the KDC error it
/// came in, whose cookies the request echoes.
pub(in super::super) struct Pending {
    /// The challenge the caller is answering.
    challenge: Challenge,
    /// The `PREAUTH_REQUIRED` error.
    error: KdcError,
}

/// With an OTP policy installed, the exchange must be armored: OTP is never sent
/// unarmored, and nothing is sent without armor.
///
/// # Errors
/// Returns [`Otp::ArmorRequired`].
pub(super) fn require_armor(engine: &InitCreds<'_>) -> Result<(), Error> {
    if engine.otp.is_some() && engine.armor.is_none() {
        return Err(Error::Otp(Otp::ArmorRequired));
    }
    Ok(())
}

/// The armor key of the conversation.
///
/// # Errors
/// Returns [`Otp::ArmorRequired`] when the exchange ran without armor.
fn armor_key(engine: &InitCreds<'_>) -> Result<EncryptionKey, Error> {
    engine
        .armor
        .as_ref()
        .and_then(|armor| armor.armor_key().cloned())
        .ok_or(Error::Otp(Otp::ArmorRequired))
}

/// Whether the caller's `preferred_preauth_types` leave OTP first among the offers.
fn preferred(engine: &InitCreds<'_>, error: &KdcError) -> bool {
    let offered = |pa_type: i32| {
        error
            .method_data()
            .iter()
            .any(|offer| offer.r#type == pa_type)
    };
    for &pa_type in &engine.options.preferred_preauth_types {
        let usable = match pa_type {
            PA_OTP_CHALLENGE => return true,
            PA_SPAKE => super::spake::usable(engine),
            PA_ENCRYPTED_CHALLENGE => {
                engine.armor.is_some() && permits(&engine.options, ENCRYPTED_CHALLENGE)
            }
            PA_ENC_TIMESTAMP => super::spake::timestamp_allowed(engine),
            _ => false,
        };
        if usable && offered(pa_type) {
            return false;
        }
    }
    true
}

/// Put the KDC's OTP challenge to the caller when OTP is installed and offered.
///
/// # Errors
/// Returns [`Otp::RepeatedChallenge`], [`Otp::ArmorRequired`] and the decoding
/// errors of [`Challenge::decode`].
pub(super) fn offer(
    engine: &mut InitCreds<'_>,
    reply: &[u8],
) -> Result<Option<ExchangeStep>, Error> {
    let Some(policy) = engine.otp else {
        return Ok(None);
    };
    let Ok(error) = process_kdc_error(reply) else {
        return Ok(None);
    };
    if error.error_code() != KDC_ERR_PREAUTH_REQUIRED {
        return Ok(None);
    }
    let mut offers = error
        .method_data()
        .iter()
        .filter(|offer| offer.r#type == PA_OTP_CHALLENGE);
    let (Some(offer), second) = (offers.next(), offers.next()) else {
        return Ok(None);
    };
    if !preferred(engine, &error) {
        return Ok(None);
    }
    if second.is_some() {
        return Err(Otp::RepeatedChallenge.into());
    }
    drop(armor_key(engine)?);
    let challenge = Challenge::decode(&offer.value, &policy)?;
    engine.state = State::Otp(Box::new(Pending {
        challenge: challenge.clone(),
        error,
    }));
    Ok(Some(ExchangeStep::Prompt(Prompt::Otp {
        client: engine.client.clone(),
        challenge,
    })))
}

/// Send the `PA-OTP-REQUEST` that answers `pending` with the caller's answer.
///
/// # Errors
/// Returns the answer's refusals ([`Challenge::request`]), the policy's refusal
/// of the armor key as a reply key and the request-building errors.
pub(super) fn answer(
    engine: &mut InitCreds<'_>,
    pending: &Pending,
    answer: Answer,
) -> Result<ExchangeStep, Error> {
    let Answer::Otp(response) = answer else {
        return Err(Error::UnexpectedStepInput {
            expected: "an OTP answer",
        });
    };
    let otp = engine.otp.ok_or(Error::UnexpectedStepInput {
        expected: "an OTP answer",
    })?;
    let key = armor_key(engine)?;
    crypto_policy::request(
        engine.options.request.crypto_policy(),
        engine.options.request.etypes(),
    )?
    .check_use(key.etype(), Use::ReplyKey)?;
    let padata = pending.challenge.request(&response, &key, &otp)?;
    drop(response);
    let mut options =
        preauth_retry_options(engine.options.request.clone(), pending.error.method_data());
    options.padata_mut().push(padata);
    let request = build_as_req(engine.client.clone(), super::service(engine), options)?;
    engine.reply_key = Some(key);
    super::send(engine, request, true, State::Final)
}
