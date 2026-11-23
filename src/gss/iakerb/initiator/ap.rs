//! The AP exchange of the IAKERB initiator: the AP-REQ with the finished
//! checksum of the transcript, and the acceptor's AP-REP.

use core::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use zeroize::Zeroizing;

use super::{
    super::{AP_REP_TOKEN_ID, AP_REQ_TOKEN_ID, Error, finished, frame, unframe},
    Phase, State,
};
use crate::{
    ap_rep,
    client::{TgsRepSession, build_ap_req_with_confounder, options::ApReq, time::from_kerberos},
    crypto::{KerberosEtype, Use},
    error::Gss,
    gss::{
        ChannelBindings, ContextFlags, EncryptionKey, EstablishedContext, InitStep,
        InitiatorOptions, Name, checksum,
        initiator::{random_key, random_sequence},
        seq,
    },
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
/// What the initiator keeps between the AP-REQ and the AP-REP.
pub(super) struct Pending {
    /// The context, its acceptor's part not yet known.
    context: EstablishedContext,
    /// The authenticator's whole-second time.
    ctime: SystemTime,
    /// The authenticator's microseconds.
    cusec: u32,
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
        .checked_add(Duration::from_secs(since.as_secs()))
        .ok_or(Gss::ContextExpired)?;
    Ok((whole, since.subsec_micros()))
}

/// The AP-REQ with `ticket`, carrying the finished checksum of the transcript.
///
/// # Errors
///
/// Returns the policy, checksum and AP-REQ errors.
pub(super) fn ap(state: &mut State, ticket: &TgsRepSession) -> Result<InitStep, Error> {
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
    if !state.conversation.transcript().is_empty() {
        let proof = finished::make(&subkey, state.conversation.transcript())?;
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
    let built = build_ap_req_with_confounder(ticket, request, ctime, cusec, &confounder)?;
    let token = frame(AP_REQ_TOKEN_ID, built.der())?;
    let context = established(ticket, subkey, sequence, flags, options);
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
    let protected = flags | ContextFlags::PROT_READY;
    let first = u64::from(sequence);
    EstablishedContext {
        initiated: true,
        source: Name::from_principal(ticket.client()),
        target: Name::from_principal(ticket.service()),
        flags: protected,
        session_key: ticket.session_key().clone(),
        initiator_subkey: Some(subkey),
        acceptor_subkey: None,
        send_sequence: first,
        window: seq::Window::new(
            first,
            protected.contains(ContextFlags::REPLAY),
            protected.contains(ContextFlags::SEQUENCE),
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
pub(super) fn reply(state: &mut State, pending: Pending, token: &[u8]) -> Result<InitStep, Error> {
    let Pending {
        mut context,
        ctime,
        cusec: sent,
    } = pending;
    let (id, body) = unframe(token)?;
    if id != AP_REP_TOKEN_ID {
        return Err(Error::UnexpectedStep(
            "the acceptor did not answer with an AP-REP",
        ));
    }
    let policy = context.crypto_policy.clone();
    let wire = ap_rep::decode(body)?;
    policy
        .check_use(wire.enc_part.etype, Use::SessionKey)
        .map_err(Gss::from)?;
    let part = ap_rep::decrypt_ap_rep_enc_part(&wire, &context.session_key)?;
    let echoed = from_kerberos(&part.ctime);
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
