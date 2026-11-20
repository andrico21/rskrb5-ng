//! The AS exchange state machine.
//!
//! It is the login functions' request sequence, one step at a time, with
//! prompts, registered mechanisms, clock adoption and the FAST seam.

use core::{fmt, mem, time::Duration};
use std::time::{SystemTime, UNIX_EPOCH};

use zeroize::Zeroizing;

#[cfg(feature = "tokio")]
use super::super::transport::{KdcProtocol, Tokio as TokioTransport};
use super::{
    super::{
        AsRepSession, BuiltAsReq, Error, KDC_ERR_PREAUTH_REQUIRED, KDC_OPTION_CANONICALIZE,
        KdcError, KdcTransport, PA_ENC_TIMESTAMP, Password, PreauthKeyInfo, Principal,
        as_rep_reply_key_info, build_as_req, crypto_policy, decode, encode,
        enforce_requested_enctypes, keytab_initial_as_rep_session, keytab_initial_as_req,
        padata_contains, password_derivation, password_initial_as_rep_session,
        password_initial_as_req, preauth, preauth_key_info_from_method_data, preauth_retry_options,
        process_as_rep, process_kdc_error, select_keytab_reply_key_for_etype,
        select_preauth_key_info,
    },
    Answer, ArmorRequest, ArmoredReply, Exchange, ExchangeStep, InitCreds, InitCredsOptions,
    MAX_EXCHANGE_ROUNDS, Outbound, Prompt, Responder, StepInput, order,
};
#[cfg(feature = "tokio")]
use crate::config::Config;
use crate::{
    crypto::{KerberosEtype, Use, prf},
    error::Fast,
    keytab::{EncryptionKey, Keytab},
    preauth::{encrypted_challenge::EncryptedChallenge, fast::PA_ENCRYPTED_CHALLENGE},
};

/// Where an AS exchange stands.
pub(super) enum State {
    /// Nothing sent yet.
    Start,
    /// The first request needs the password (assumed preauthentication).
    PasswordForInitial,
    /// The first request is out.
    Initial(Box<BuiltAsReq>),
    /// An AS-REP (held in `held_reply`) answered the first request; decrypting
    /// it needs the password.
    PasswordForReply(Box<BuiltAsReq>),
    /// The cookie-only discovery request is out.
    Discovery,
    /// The KDC asked for preauthentication (the error held in `held_reply`);
    /// answering needs the password.
    PasswordForChallenge,
    /// The preauthenticated request is out; its key is in `reply_key`.
    Final(Box<BuiltAsReq>),
    /// Finished or failed; no further step is possible.
    Done,
}

/// A new exchange in its start state.
pub(super) fn new(
    client: Principal,
    (password, keytab): (Option<Password>, Option<Keytab>),
    options: InitCredsOptions,
) -> InitCreds<'static> {
    InitCreds {
        client,
        password,
        keytab,
        held_reply: None,
        reply_key: None,
        options,
        state: State::Start,
        rounds: 0,
        time_offset: None,
        preauth: None,
        armor: None,
        key_expiration: None,
        cookie: None,
        strengthen_key: None,
        authenticated_client: None,
    }
}

/// Redacted `Debug`: identities, state and counters, never secrets.
///
/// # Errors
/// Returns the typed failure of the step; the exchange cannot continue after it.
pub(super) fn debug(engine: &InitCreds<'_>, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
        .debug_struct("InitCreds")
        .field("client", &engine.client)
        .field("state", &state_name(&engine.state))
        .field("rounds", &engine.rounds)
        .field("kdc_time_offset", &engine.time_offset)
        .field("preauth", &engine.preauth)
        .field("armor", &engine.armor.is_some())
        .finish_non_exhaustive()
}

/// The name of a state, for diagnostics and the unexpected-input error.
const fn state_name(state: &State) -> &'static str {
    match state {
        State::Start => "start",
        State::PasswordForInitial | State::PasswordForReply(_) | State::PasswordForChallenge => {
            "a password answer"
        }
        State::Initial(_) | State::Discovery | State::Final(..) => "a KDC reply",
        State::Done => "nothing (the exchange is finished)",
    }
}

/// Advance the exchange; any error leaves it finished.
///
/// # Errors
/// Returns the typed failure of the step; the exchange cannot continue after it.
pub(super) fn step(
    engine: &mut InitCreds<'_>,
    input: StepInput<'_>,
) -> Result<ExchangeStep, Error> {
    let state = mem::replace(&mut engine.state, State::Done);
    let expected = state_name(&state);
    let unwrapped = match (&input, engine.armor.as_mut()) {
        (StepInput::Reply(reply), Some(armor)) => Some(unwrap(armor.as_mut(), reply)?),
        _ => None,
    };
    if let Some(reply) = &unwrapped {
        remember_cookie(engine, reply);
    }
    let effective = unwrapped
        .as_ref()
        .map_or(input, |reply| StepInput::Reply(&reply.reply));
    match (state, effective) {
        (State::Start, StepInput::Start) => start(engine),
        (State::PasswordForInitial, StepInput::Answer(answer)) => {
            accept(engine, answer)?;
            start(engine)
        }
        (State::Initial(request), StepInput::Reply(reply)) => initial_reply(engine, request, reply),
        (State::PasswordForReply(request), StepInput::Answer(answer)) => {
            accept(engine, answer)?;
            let reply = held(engine.held_reply.take())?;
            initial_as_rep(engine, &request, &reply)
        }
        (State::Discovery, StepInput::Reply(reply)) => {
            preauth::validate_discovery(reply, &engine.options.request)?;
            challenge(engine, reply)
        }
        (State::PasswordForChallenge, StepInput::Answer(answer)) => {
            accept(engine, answer)?;
            let reply = held(engine.held_reply.take())?;
            challenge(engine, &reply)
        }
        (State::Final(request), StepInput::Reply(reply)) => {
            let reply_key = held(engine.reply_key.take())?;
            verify_kdc_challenge(engine, &request, reply, &reply_key)?;
            let canonical = canonical_request(engine, &request);
            let session = process_as_rep(
                canonical.as_ref().unwrap_or(&request),
                reply,
                &strengthened(engine, reply_key)?,
            )?;
            Ok(finish(engine, &request, session))
        }
        (unexpected, _) => {
            engine.state = unexpected;
            Err(Error::UnexpectedStepInput { expected })
        }
    }
}

/// Send the first request, or ask for the password it needs.
///
/// # Errors
/// Returns the typed failure of the step; the exchange cannot continue after it.
fn start(engine: &mut InitCreds<'_>) -> Result<ExchangeStep, Error> {
    let service = service(engine);
    if awaiting_password(engine) && engine.options.request.assume_preauthentication() {
        return Ok(prompt(engine, State::PasswordForInitial));
    }
    let request = match &engine.keytab {
        Some(keytab) => keytab_initial_as_req(
            engine.client.clone(),
            service,
            keytab,
            engine.options.request.clone(),
        )?,
        None => password_initial_as_req(
            engine.client.clone(),
            service,
            password_bytes(engine),
            engine.options.request.clone(),
        )?,
    };
    send(engine, request, false, State::Initial)
}

/// The first reply: an AS-REP without preauthentication, or a KRB-ERROR.
///
/// # Errors
/// Returns the typed failure of the step; the exchange cannot continue after it.
fn initial_reply(
    engine: &mut InitCreds<'_>,
    request: Box<BuiltAsReq>,
    reply: &[u8],
) -> Result<ExchangeStep, Error> {
    if as_rep_reply_key_info(reply).is_some() {
        if awaiting_password(engine) {
            engine.held_reply = Some(Zeroizing::new(reply.to_vec()));
            return Ok(prompt(engine, State::PasswordForReply(request)));
        }
        return initial_as_rep(engine, &request, reply);
    }
    note_kdc_time(engine, reply);
    if let Some(probe) = preauth::discovery_request(&request, &engine.options.request, reply)? {
        return send(engine, probe, true, |_| State::Discovery);
    }
    challenge(engine, reply)
}

/// Decrypt an AS-REP that needed no preauthentication.
///
/// # Errors
/// Returns the typed failure of the step; the exchange cannot continue after it.
fn initial_as_rep(
    engine: &mut InitCreds<'_>,
    request: &BuiltAsReq,
    reply: &[u8],
) -> Result<ExchangeStep, Error> {
    let canonical = canonical_request(engine, request);
    let checked = canonical.as_ref().unwrap_or(request);
    if engine.strengthen_key.is_some() {
        let key = initial_reply_key(engine, checked, reply)?;
        let session = process_as_rep(checked, reply, &strengthened(engine, key)?)?;
        return Ok(finish(engine, request, session));
    }
    let session = match &engine.keytab {
        Some(keytab) => keytab_initial_as_rep_session(checked, reply, &engine.client, keytab)?,
        None => {
            password_initial_as_rep_session(checked, reply, &engine.client, password_bytes(engine))?
        }
    };
    let completed = session.ok_or_else(|| Error::UnexpectedStepInput {
        expected: "an AS-REP",
    })?;
    Ok(finish(engine, request, completed))
}

/// The unstrengthened reply key of an armored AS-REP that needed no
/// preauthentication: the keytab key, or the password key from the reply's
/// ETYPE-INFO2 (MIT `fast.c:569-592` strengthens it).
///
/// # Errors
/// Returns the enctype, policy, keytab and derivation errors.
fn initial_reply_key(
    engine: &InitCreds<'_>,
    request: &BuiltAsReq,
    reply: &[u8],
) -> Result<EncryptionKey, Error> {
    let (etype, kvno) = as_rep_reply_key_info(reply).ok_or(Error::UnexpectedStepInput {
        expected: "an AS-REP",
    })?;
    request.crypto_policy.check_use(etype, Use::ReplyKey)?;
    enforce_requested_enctypes(&request.message.0.req_body.etype, etype)?;
    if let Some(keytab) = &engine.keytab {
        return select_keytab_reply_key_for_etype(
            keytab,
            &engine.client,
            kvno.unwrap_or_default(),
            etype,
        )
        .map(|(key, _)| key);
    }
    let rasn_kerberos::AsRep(as_rep) = decode("AS-REP", reply)?;
    let info = preauth_key_info_from_method_data(as_rep.padata.as_deref().unwrap_or_default())?
        .into_iter()
        .find(|info| info.etype == etype)
        .unwrap_or_else(|| PreauthKeyInfo::new(etype));
    password_derivation::derive(
        &request.crypto_policy,
        &engine.client,
        password_bytes(engine),
        &info,
    )
}

/// Answer the KDC's preauthentication challenge.
///
/// A registered mechanism answers when it handles an offered type that the
/// preferred order puts ahead of encrypted timestamp; else encrypted timestamp does.
///
/// # Errors
/// Returns the typed failure of the step; the exchange cannot continue after it.
fn challenge(engine: &mut InitCreds<'_>, reply: &[u8]) -> Result<ExchangeStep, Error> {
    if awaiting_password(engine) {
        engine.held_reply = Some(Zeroizing::new(reply.to_vec()));
        return Ok(prompt(engine, State::PasswordForChallenge));
    }
    let at = preauth_time(engine)?;
    if let Some(error) = registered_challenge(engine, reply)? {
        let key = challenge_key(engine, &error)?;
        let options = preauth_retry_options(engine.options.request.clone(), error.method_data());
        let request = build_as_req(engine.client.clone(), service(engine), options)?;
        engine.reply_key = Some(key);
        return send(engine, request, true, State::Final);
    }
    if let Some(step) = encrypted_challenge(engine, reply, at)? {
        return Ok(step);
    }
    let (request, reply_key) = match &engine.keytab {
        Some(keytab) => preauth::keytab_preauth_request_at(
            (engine.client.clone(), service(engine)),
            keytab,
            engine.options.request.clone(),
            reply,
            at,
        )?,
        None => preauth::password_preauth_request_at(
            (engine.client.clone(), service(engine)),
            password_bytes(engine),
            engine.options.request.clone(),
            reply,
            at,
        )?,
    };
    engine.reply_key = Some(reply_key);
    send(engine, request, true, State::Final)
}

/// When a registered mechanism answers an offered PA type that the preferred
/// order puts ahead of encrypted timestamp, add its PA-DATA to the request
/// template and return the challenge it answered.
///
/// # Errors
/// Returns the typed failure of the step; the exchange cannot continue after it.
fn registered_challenge(
    engine: &mut InitCreds<'_>,
    reply: &[u8],
) -> Result<Option<KdcError>, Error> {
    if engine.preauth.is_none() {
        return Ok(None);
    }
    let error = process_kdc_error(reply)?;
    if error.error_code() != KDC_ERR_PREAUTH_REQUIRED {
        return Ok(None);
    }
    let unanswered = build_as_req(
        engine.client.clone(),
        service(engine),
        engine.options.request.clone(),
    )?;
    let body = encode("KDC-REQ-BODY", &unanswered.message.0.req_body)?;
    let offered: Vec<i32> =
        order::sorted(error.method_data(), &engine.options.preferred_preauth_types)
            .iter()
            .map(|offer| offer.r#type)
            .collect();
    let Some(session) = engine.preauth.as_mut() else {
        return Ok(None);
    };
    for pa_type in offered {
        if pa_type == PA_ENC_TIMESTAMP {
            return Ok(None);
        }
        if let Some(padata) = session
            .respond(pa_type, error.method_data(), &body)
            .map_err(Error::Preauth)?
        {
            engine.options.request.padata_mut().extend(padata);
            return Ok(Some(error));
        }
    }
    Ok(None)
}

/// Emit a prompt for the client's password and wait in `pending`.
fn prompt(engine: &mut InitCreds<'_>, pending: State) -> ExchangeStep {
    engine.state = pending;
    ExchangeStep::Prompt(Prompt::Password {
        client: engine.client.clone(),
    })
}

/// Store a prompted password.
///
/// # Errors
/// Returns the typed failure of the step; the exchange cannot continue after it.
fn accept(engine: &mut InitCreds<'_>, answer: Answer) -> Result<(), Error> {
    match answer {
        Answer::Password(password) if awaiting_password(engine) => {
            engine.password = Some(password);
            Ok(())
        }
        Answer::Password(_) => Err(Error::UnexpectedStepInput {
            expected: "a KDC reply",
        }),
    }
}

/// Whether this is a password exchange still without its password.
const fn awaiting_password(engine: &InitCreds<'_>) -> bool {
    engine.keytab.is_none() && engine.password.is_none()
}

/// The password bytes of a password exchange (empty before it is known).
fn password_bytes<'engine>(engine: &'engine InitCreds<'_>) -> &'engine [u8] {
    engine
        .password
        .as_ref()
        .map_or(&[][..], |secret| secret.as_bytes())
}

/// A value the current state guarantees, taken from its slot.
///
/// # Errors
/// Returns [`Error::UnexpectedStepInput`] when the slot is empty, which the
/// state machine never allows.
fn held<T>(slot: Option<T>) -> Result<T, Error> {
    slot.ok_or(Error::UnexpectedStepInput {
        expected: "a KDC reply",
    })
}

/// Count, armor and emit one request; the next state keeps the request.
///
/// # Errors
/// Returns the typed failure of the step; the exchange cannot continue after it.
fn send<F>(
    engine: &mut InitCreds<'_>,
    mut request: BuiltAsReq,
    follow_up: bool,
    next: F,
) -> Result<ExchangeStep, Error>
where
    F: FnOnce(Box<BuiltAsReq>) -> State,
{
    if engine.rounds >= MAX_EXCHANGE_ROUNDS {
        return Err(Error::ExchangeLoop {
            limit: MAX_EXCHANGE_ROUNDS,
        });
    }
    engine.rounds = engine.rounds.saturating_add(1);
    if engine.options.kdc_timesync {
        let (now, _) = request.reply_clock();
        request.set_reply_clock((now, Duration::MAX));
    }
    let canonicalize = canonicalize_requested(engine);
    let message = match engine.armor.as_mut() {
        Some(armor) => {
            let body = encode("KDC-REQ-BODY", &request.message.0.req_body)?;
            let armored = armor
                .armor_request(&ArmorRequest {
                    request: &request.der,
                    body: &body,
                    cookie: engine.cookie.as_deref(),
                    canonicalize,
                })
                .map_err(Error::Armor)?;
            crypto_policy::armored(&request.crypto_policy, &armored)?;
            // RFC 6806 section 11 checksums the request as sent (MIT
            // `fast.c:634-675` over `encoded_previous_request`): the armored one.
            request.der.clone_from(&armored);
            armored
        }
        None => request.der.clone(),
    };
    let realm = request.client.realm.clone();
    engine.state = next(Box::new(request));
    Ok(ExchangeStep::Outbound(Outbound {
        realm,
        message,
        follow_up,
    }))
}

/// Record the result, the adopted clock offset and the key expiration.
fn finish(engine: &mut InitCreds<'_>, request: &BuiltAsReq, session: AsRepSession) -> ExchangeStep {
    if engine.options.kdc_timesync {
        engine.time_offset = Some(offset(session.auth_time, request.reply_clock().0));
    }
    engine.key_expiration = session.key_expiration;
    engine.state = State::Done;
    ExchangeStep::Complete(Box::new(session))
}

/// MIT `note_req_timestamp` (`get_in_tkt.c:1425-1439`): remember the KDC time of a
/// preauthentication error for the encrypted timestamp under `kdc_timesync`.
fn note_kdc_time(engine: &mut InitCreds<'_>, reply: &[u8]) {
    if engine.options.kdc_timesync
        && let Ok(error) = process_kdc_error(reply)
    {
        engine.time_offset = Some(offset(error.stime(), SystemTime::now()));
    }
}

/// The encrypted-timestamp time: now, shifted by the KDC's offset under `kdc_timesync`.
///
/// # Errors
/// Returns [`Error::TimeOverflow`] when the shifted time is before the Unix epoch.
fn preauth_time(engine: &InitCreds<'_>) -> Result<Option<(SystemTime, u32)>, Error> {
    let Some(seconds) = engine.time_offset else {
        return Ok(None);
    };
    let now = SystemTime::now();
    let shifted = if seconds >= 0 {
        now.checked_add(Duration::from_secs(seconds.unsigned_abs()))
    } else {
        now.checked_sub(Duration::from_secs(seconds.unsigned_abs()))
    }
    .ok_or(Error::TimeOverflow)?;
    let elapsed = shifted
        .duration_since(UNIX_EPOCH)
        .map_err(|_before| Error::TimeOverflow)?;
    let whole = UNIX_EPOCH
        .checked_add(Duration::from_secs(elapsed.as_secs()))
        .ok_or(Error::TimeOverflow)?;
    Ok(Some((whole, elapsed.subsec_micros())))
}

/// `kdc - local` in whole seconds, saturating.
fn offset(kdc: SystemTime, local: SystemTime) -> i64 {
    match kdc.duration_since(local) {
        Ok(ahead) => i64::try_from(ahead.as_secs()).unwrap_or(i64::MAX),
        Err(behind) => i64::try_from(behind.duration().as_secs())
            .map_or(i64::MIN, |value| 0_i64.saturating_sub(value)),
    }
}

/// The requested service: the caller's, or the client realm's TGS.
fn service(engine: &InitCreds<'_>) -> Principal {
    engine
        .options
        .service
        .clone()
        .unwrap_or_else(|| Principal::tgt_service(engine.client.realm.clone()))
}

/// Unwrap an armored reply.
///
/// # Errors
/// Returns [`Error::Armor`] for the armor's failure.
fn unwrap(
    armor: &mut (dyn super::ArmoredExchange + '_),
    reply: &[u8],
) -> Result<ArmoredReply, Error> {
    armor.unwrap_reply(reply).map_err(Error::Armor)
}

/// Keep the newest cookie, strengthen key and authenticated client of an armored reply.
fn remember_cookie(engine: &mut InitCreds<'_>, reply: &ArmoredReply) {
    engine
        .authenticated_client
        .clone_from(&reply.authenticated_client);
    if let Some(cookie) = &reply.cookie {
        engine.cookie = Some(cookie.clone());
    }
    if let Some(key) = &reply.strengthen_key {
        engine.strengthen_key = Some(key.clone());
    }
}

/// The reply key, combined with the KDC's strengthen key when the armor
/// reported one (RFC 6113 section 5.4.3, `KRB-FX-CF2(strengthen, reply,
/// "strengthenkey", "replykey")`).
///
/// # Errors
/// Returns the combination's crypto errors.
fn strengthened(engine: &InitCreds<'_>, reply_key: EncryptionKey) -> Result<EncryptionKey, Error> {
    match &engine.strengthen_key {
        Some(strengthen) => strengthen_key(strengthen, &reply_key),
        None => Ok(reply_key),
    }
}

/// Whether the caller asked for client canonicalization (`canonicalize`).
const fn canonicalize_requested(engine: &InitCreds<'_>) -> bool {
    engine.options.request.kdc_option_bits() & KDC_OPTION_CANONICALIZE != 0
}

/// The request with the client FAST authenticated.
///
/// Only when it differs and the caller asked for canonicalization: only a
/// protected reply may change the client name (RFC 6806 section 7; RFC 6113
/// section 5.4.3 `cname`).
fn canonical_request(engine: &InitCreds<'_>, request: &BuiltAsReq) -> Option<BuiltAsReq> {
    let client = engine.authenticated_client.as_ref()?;
    (canonicalize_requested(engine) && *client != request.client).then(|| {
        let mut canonical = request.clone();
        canonical.client = client.clone();
        canonical
    })
}

/// Answer an armored KDC's encrypted-challenge offer (RFC 6113 section 5.4.6,
/// MIT `preauth_ec.c:96-142`), in the KDC's time under `kdc_timesync`.
///
/// # Errors
/// Returns the key selection, challenge and request-building errors.
fn encrypted_challenge(
    engine: &mut InitCreds<'_>,
    reply: &[u8],
    at: Option<(SystemTime, u32)>,
) -> Result<Option<ExchangeStep>, Error> {
    let Some(armor_key) = engine
        .armor
        .as_ref()
        .and_then(|armor| armor.armor_key().cloned())
    else {
        return Ok(None);
    };
    let error = process_kdc_error(reply)?;
    if error.error_code() != KDC_ERR_PREAUTH_REQUIRED
        || !padata_contains(error.method_data(), PA_ENCRYPTED_CHALLENGE)
    {
        return Ok(None);
    }
    let key = challenge_key(engine, &error)?;
    let time = match at {
        Some(kdc_time) => kdc_time,
        None => now()?,
    };
    let padata = EncryptedChallenge::new(&armor_key, &key)
        .and_then(|challenge| challenge.padata(time))
        .map_err(armor_failure)?;
    let mut options = preauth_retry_options(engine.options.request.clone(), error.method_data());
    options.padata_mut().push(padata);
    let request = build_as_req(engine.client.clone(), service(engine), options)?;
    engine.reply_key = Some(key);
    send(engine, request, true, State::Final).map(Some)
}

/// After an encrypted challenge, the KDC's challenge must decrypt and the
/// reply key must have been strengthened (RFC 6113 section 5.4.6).
///
/// # Errors
/// Returns [`Error::Armor`] with [`Fast::ChallengeReply`] otherwise.
fn verify_kdc_challenge(
    engine: &InitCreds<'_>,
    request: &BuiltAsReq,
    reply: &[u8],
    reply_key: &EncryptionKey,
) -> Result<(), Error> {
    let answered = request
        .message
        .0
        .padata
        .as_deref()
        .is_some_and(|data| padata_contains(data, PA_ENCRYPTED_CHALLENGE));
    let armor_key = engine.armor.as_ref().and_then(|armor| armor.armor_key());
    let (true, Some(key)) = (answered, armor_key) else {
        return Ok(());
    };
    let Ok(rasn_kerberos::AsRep(as_rep)) = decode::<rasn_kerberos::AsRep>("AS-REP", reply) else {
        return Ok(());
    };
    EncryptedChallenge::new(key, reply_key)
        .and_then(|challenge| challenge.verify_reply(as_rep.padata.as_deref().unwrap_or_default()))
        .map_err(armor_failure)?;
    if engine.strengthen_key.is_none() {
        return Err(armor_failure(Fast::ChallengeReply {
            what: "a strengthen key",
        }));
    }
    Ok(())
}

/// A FAST failure as the exchange's armor error.
fn armor_failure(error: Fast) -> Error {
    Error::Armor(Box::new(error))
}

/// The current time in whole seconds and microseconds.
///
/// # Errors
/// Returns [`Error::TimeOverflow`] before the Unix epoch.
fn now() -> Result<(SystemTime, u32), Error> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_before| Error::TimeOverflow)?;
    let whole = UNIX_EPOCH
        .checked_add(Duration::from_secs(elapsed.as_secs()))
        .ok_or(Error::TimeOverflow)?;
    Ok((whole, elapsed.subsec_micros()))
}

/// The reply key for a challenge a registered mechanism answered.
///
/// # Errors
/// Returns the key selection and derivation errors of the encrypted-timestamp path.
fn challenge_key(engine: &InitCreds<'_>, error: &KdcError) -> Result<EncryptionKey, Error> {
    let etypes = engine.options.request.etypes();
    if let Some(keytab) = &engine.keytab {
        return preauth::challenge_key(keytab, &engine.client, error, etypes).map(|(key, _)| key);
    }
    let policy = crypto_policy::request(engine.options.request.crypto_policy(), etypes)?;
    let info = select_preauth_key_info(error, etypes)?;
    policy.check_use(info.etype, Use::ReplyKey)?;
    password_derivation::derive(&policy, &engine.client, password_bytes(engine), &info)
}

/// `KRB-FX-CF2(strengthen, reply, "strengthenkey", "replykey")` (RFC 6113 section 5.4.3).
///
/// # Errors
/// Returns [`Error::UnsupportedEtype`] for an unimplemented enctype and the crypto errors.
fn strengthen_key(
    strengthen: &EncryptionKey,
    reply: &EncryptionKey,
) -> Result<EncryptionKey, Error> {
    let etype = |key: &EncryptionKey| {
        KerberosEtype::from_etype_id(key.etype()).ok_or(Error::UnsupportedEtype(key.etype()))
    };
    let combined = prf::krb_fx_cf2(
        &prf::CfInput::new(
            prf::Key::new(etype(strengthen)?, strengthen.value()),
            b"strengthenkey",
        ),
        &prf::CfInput::new(prf::Key::new(etype(reply)?, reply.value()), b"replykey"),
    )?;
    Ok(EncryptionKey::new(strengthen.etype(), combined.to_vec()))
}

/// The blocking driver.
///
/// # Errors
/// Returns the typed failure of the step; the exchange cannot continue after it.
pub(super) fn drive<T, E, R>(
    transport: &mut T,
    exchange: &mut E,
    responder: &mut R,
) -> Result<AsRepSession, Error>
where
    T: KdcTransport + ?Sized,
    E: Exchange + ?Sized,
    R: Responder + ?Sized,
{
    let mut reply: Option<Vec<u8>> = None;
    let mut answer = None;
    loop {
        let input = match (&reply, answer.take()) {
            (_, Some(pending)) => StepInput::Answer(pending),
            (Some(bytes), None) => StepInput::Reply(bytes),
            (None, None) => StepInput::Start,
        };
        match exchange.advance(input)? {
            ExchangeStep::Outbound(outbound) => {
                reply = Some(transport.send(outbound.realm(), outbound.message())?);
            }
            ExchangeStep::Prompt(prompt) => {
                answer = Some(responder.respond(&prompt).map_err(Error::Responder)?);
            }
            ExchangeStep::Complete(session) => {
                if let Some(expires) = exchange.key_expiration() {
                    responder.password_expiry(expires);
                }
                return Ok(*session);
            }
        }
    }
}

/// The Tokio driver: realm discovery for the first request, the open
/// connection for follow-up requests, as the AS login functions do.
///
/// # Errors
/// Returns the typed failure of the step; the exchange cannot continue after it.
///
/// # Cancel safety
/// Cancel-safe in the sense of [`super::drive_tokio`]: no client or cache state
/// changes, and the exchange erases its secrets when it is dropped.
#[cfg(feature = "tokio")]
pub(super) async fn drive_tokio<E, R>(
    transport: &TokioTransport,
    (config, protocol): (&Config, KdcProtocol),
    exchange: &mut E,
    responder: &mut R,
) -> Result<AsRepSession, Error>
where
    E: Exchange + ?Sized,
    R: Responder + ?Sized,
{
    let mut reply: Option<Vec<u8>> = None;
    let mut answer = None;
    let mut pinned = None;
    loop {
        let input = match (&reply, answer.take()) {
            (_, Some(pending)) => StepInput::Answer(pending),
            (Some(bytes), None) => StepInput::Reply(bytes),
            (None, None) => StepInput::Start,
        };
        match exchange.advance(input)? {
            ExchangeStep::Outbound(outbound) => {
                let reused = if outbound.follow_up() {
                    transport
                        .send_follow_up(pinned.as_mut(), outbound.message())
                        .await?
                } else {
                    None
                };
                reply = Some(if let Some(bytes) = reused {
                    bytes
                } else {
                    drop(pinned.take());
                    let (bytes, connection) = transport
                        .send_to_realm_pinned(
                            config,
                            protocol,
                            outbound.realm(),
                            outbound.message(),
                        )
                        .await?;
                    pinned = connection;
                    bytes
                });
            }
            ExchangeStep::Prompt(prompt) => {
                answer = Some(responder.respond(&prompt).map_err(Error::Responder)?);
            }
            ExchangeStep::Complete(session) => {
                if let Some(expires) = exchange.key_expiration() {
                    responder.password_expiry(expires);
                }
                return Ok(*session);
            }
        }
    }
}
