//! The krb5 mechanism's initiator.
//!
//! The krb5 mechanism's initiator (MIT 1.22.2 `init_sec_context.c:240-688`
//! and `mutual_auth`, `init_sec_context.c:691-870`).

use core::{mem, slice, time::Duration};
use std::time::{SystemTime, UNIX_EPOCH};

use rasn::types::Integer;
use rasn_kerberos::KerberosTime;
use zeroize::Zeroizing;

use super::{
    ChannelBindings, ContextFlags, Credential, CredentialUsage, CryptoPolicy, EncryptionKey, Error,
    EstablishedContext, InitState, InitStep, Initiator, Name, Principal, TgsRepSession, checksum,
    cred, dce, seq,
};
use crate::{
    ap_rep, ap_req,
    client::time::from_kerberos,
    crypto::{KerberosEtype, Use, prf},
    krb_cred,
    spnego::{Krb5MechToken, Krb5TokenId},
    ticket,
};

/// The AP option `mutual-required` (RFC 4120 section 5.5.1, bit 2).
const MUTUAL_REQUIRED: u32 = 0x2000_0000;
/// The flags an initiator may put in its checksum (`init_sec_context.c:546-550`).
const SENT_FLAGS: ContextFlags = ContextFlags::from_bits(
    ContextFlags::CONF.bits()
        | ContextFlags::INTEG.bits()
        | ContextFlags::MUTUAL.bits()
        | ContextFlags::REPLAY.bits()
        | ContextFlags::SEQUENCE.bits()
        | ContextFlags::DELEG.bits()
        | ContextFlags::DCE_STYLE.bits()
        | ContextFlags::IDENTIFY.bits()
        | ContextFlags::EXTENDED_ERROR.bits(),
);

/// What the initiator keeps between the AP-REQ and the AP-REP: the context
/// without the acceptor's part, and the authenticator time the AP-REP echoes.
pub(super) struct Pending {
    /// The context, its acceptor subkey and receive window not yet known.
    context: EstablishedContext,
    /// The authenticator's whole-second time.
    ctime: SystemTime,
    /// The authenticator's microseconds.
    cusec: u32,
}

/// The parts of a new initiator context.
struct Parts {
    /// The ticket the context is for.
    ticket: TgsRepSession,
    /// The initiator subkey.
    subkey: EncryptionKey,
    /// The initiator's sequence number.
    sequence: u32,
    /// The context flags.
    flags: ContextFlags,
    /// The runtime enctype policy.
    policy: CryptoPolicy,
}

/// One initiator step.
///
/// # Errors
///
/// Returns the errors of [`super::Initiator::init_sec_context`].
pub(super) fn step(
    initiator: &mut Initiator,
    credential: &Credential,
    input: Option<&[u8]>,
) -> Result<InitStep, Error> {
    match (
        mem::replace(&mut initiator.state, InitState::Finished),
        input,
    ) {
        (InitState::Start, None) => first(initiator, credential),
        (InitState::AwaitingReply(pending), Some(token)) => {
            let (context, step) = reply(*pending, token)?;
            initiator.state = InitState::Established(Box::new(context));
            Ok(step)
        }
        (state, _) => {
            initiator.state = state;
            Err(Error::UnexpectedStep(
                "the initiator does not expect this input",
            ))
        }
    }
}

/// A random key of `etype` (RFC 3961 `random-to-key`).
///
/// # Errors
///
/// Returns [`Error::LegacyTokenFormat`] for an unknown enctype and the random
/// source and key errors.
pub(super) fn random_key(etype: i32) -> Result<EncryptionKey, Error> {
    let kind = KerberosEtype::from_etype_id(etype).ok_or(Error::LegacyTokenFormat(etype))?;
    let mut seed = Zeroizing::new(vec![0; prf::seed_len(kind)]);
    getrandom::fill(&mut seed).map_err(Error::Random)?;
    let value = prf::random_to_key(kind, &seed).map_err(Error::Crypto)?;
    Ok(EncryptionKey::new(etype, value.to_vec()))
}

/// A random 30-bit sequence number, as MIT and gokrb5 choose.
///
/// # Errors
///
/// Returns the random source error.
pub(super) fn random_sequence() -> Result<u32, Error> {
    let mut bytes = [0; 4];
    getrandom::fill(&mut bytes).map_err(Error::Random)?;
    Ok(u32::from_be_bytes(bytes) & 0x3fff_ffff)
}

/// A Kerberos string.
///
/// # Errors
///
/// Returns [`Error::BadName`] for a string Kerberos cannot carry.
fn kerberos_string(value: &str) -> Result<rasn_kerberos::KerberosString, Error> {
    rasn_kerberos::KerberosString::from_bytes(value.as_bytes())
        .map_err(|_invalid| Error::BadName("not a Kerberos string"))
}

/// The ASN.1 name of `principal`.
///
/// # Errors
///
/// Returns [`Error::BadName`] for a component Kerberos cannot carry.
fn principal_name(principal: &Principal) -> Result<rasn_kerberos::PrincipalName, Error> {
    Ok(rasn_kerberos::PrincipalName {
        r#type: principal.name_type,
        string: principal
            .components
            .iter()
            .map(|component| kerberos_string(component))
            .collect::<Result<_, _>>()?,
    })
}

/// The current time as whole seconds, microseconds and the Kerberos time.
///
/// # Errors
///
/// Returns [`Error::ContextExpired`] for a clock outside the Kerberos range.
fn now() -> Result<(SystemTime, u32, KerberosTime), Error> {
    let since = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_before| Error::ContextExpired)?;
    let seconds = i64::try_from(since.as_secs()).map_err(|_range| Error::ContextExpired)?;
    let whole = UNIX_EPOCH
        .checked_add(Duration::from_secs(since.as_secs()))
        .ok_or(Error::ContextExpired)?;
    let kerberos = chrono::DateTime::from_timestamp(seconds, 0)
        .map(|utc| KerberosTime(utc.fixed_offset()))
        .ok_or(Error::ContextExpired)?;
    Ok((whole, since.subsec_micros(), kerberos))
}

/// The context flags of a request against a ticket's `OK-AS-DELEGATE`
/// (`init_sec_context.c:537-586`).
fn negotiate(requested: ContextFlags, enforce: bool, ok_as_delegate: bool) -> ContextFlags {
    let asked = if enforce && requested.contains(ContextFlags::DELEG) {
        requested.difference(ContextFlags::DELEG) | ContextFlags::DELEG_POLICY
    } else {
        requested
    };
    let mut flags = asked.intersection(SENT_FLAGS)
        | ContextFlags::TRANS
        | ContextFlags::CONF
        | ContextFlags::INTEG;
    if asked.contains(ContextFlags::DCE_STYLE) {
        // DCE style implies mutual authentication (`init_sec_context.c:554-555`).
        flags = flags | ContextFlags::MUTUAL;
    }
    if asked.contains(ContextFlags::DELEG_POLICY) && ok_as_delegate {
        flags = flags | ContextFlags::DELEG | ContextFlags::DELEG_POLICY;
    }
    flags
}

/// The KRB-CRED of the client's forwardable TGT, encrypted in the session key
/// (RFC 4121 section 4.1.1.1), or `None` when there is none to forward.
///
/// # Errors
///
/// Returns [`Error::DelegatedCredential`] when the KRB-CRED cannot be built.
fn delegation(
    credential: &Credential,
    session_key: &EncryptionKey,
) -> Result<Option<Zeroizing<Vec<u8>>>, Error> {
    let Some(tgt) = cred::forwardable_tgt(credential) else {
        return Ok(None);
    };
    let etype = KerberosEtype::from_etype_id(session_key.etype())
        .ok_or(Error::LegacyTokenFormat(session_key.etype()))?;
    let mut confounder = Zeroizing::new(vec![0; etype.confounder_len()]);
    getrandom::fill(&mut confounder).map_err(Error::Random)?;
    krb_cred::encode_encrypt_ccache_credentials_to_krb_cred_with_confounder(
        slice::from_ref(tgt),
        session_key,
        &confounder,
    )
    .map(|bytes| Some(Zeroizing::new(bytes)))
    .map_err(Error::DelegatedCredential)
}

/// The krb5 AP-REQ token of `authenticator` with the service ticket.
///
/// # Errors
///
/// Returns the ticket, AP-REQ and token encoding errors.
fn ap_req_token(
    ticket: &TgsRepSession,
    authenticator: &rasn_kerberos::Authenticator,
    flags: ContextFlags,
) -> Result<Vec<u8>, Error> {
    let mutual = flags.contains(ContextFlags::MUTUAL);
    let wire_ticket = ticket::decode(ticket.ticket()).map_err(Error::Ticket)?;
    let usage = ap_req::authenticator_usage_for_ticket(&wire_ticket);
    let kvno = wire_ticket.enc_part.kvno;
    let etype = KerberosEtype::from_etype_id(ticket.session_key().etype())
        .ok_or(Error::LegacyTokenFormat(ticket.session_key().etype()))?;
    let mut confounder = Zeroizing::new(vec![0; etype.confounder_len()]);
    getrandom::fill(&mut confounder).map_err(Error::Random)?;
    let bits = if mutual { MUTUAL_REQUIRED } else { 0 };
    let message = ap_req::build_ap_req_with_confounder(
        wire_ticket,
        ap_req::ap_options_from_bits(bits),
        authenticator,
        ticket.session_key(),
        usage,
        kvno,
        &confounder,
    )?;
    let der = Zeroizing::new(ap_req::encode(&message).map_err(Error::ApReq)?);
    if flags.contains(ContextFlags::DCE_STYLE) {
        // A raw AP-REQ, without the RFC 2743 framing (`init_sec_context.c:420-426`).
        return Ok(der.to_vec());
    }
    Ok(Krb5MechToken::ap_req(der.to_vec()).encode()?)
}

/// The first step: the AP-REQ token.
///
/// # Errors
///
/// Returns the errors of [`super::Initiator::init_sec_context`].
fn first(initiator: &mut Initiator, credential: &Credential) -> Result<InitStep, Error> {
    if credential.usage == CredentialUsage::Accept {
        return Err(Error::WrongCredentialUsage("initiate"));
    }
    let options = &initiator.options;
    let _components: &[String] = cred::target_components(&initiator.target)?;
    let ticket = cred::service_ticket(credential, &initiator.target)
        .ok_or(Error::NoCredential("no live service ticket for the target"))?;
    let policy = options.crypto_policy.clone();
    policy
        .check_use(ticket.session_key().etype(), Use::SessionKey)
        .map_err(Error::Policy)?;
    let ok_as_delegate = ticket
        .ticket_flags()
        .iter()
        .zip(cred::OK_AS_DELEGATE)
        .any(|(flags, bit)| flags & bit != 0);
    let mut flags = negotiate(
        options.flags,
        options.enforce_ok_as_delegate,
        ok_as_delegate,
    );
    let forwarded = if flags.contains(ContextFlags::DELEG) {
        delegation(credential, ticket.session_key())?
    } else {
        None
    };
    if forwarded.is_none() {
        flags = flags.difference(ContextFlags::DELEG | ContextFlags::DELEG_POLICY);
    }
    let digest = options
        .bindings
        .as_ref()
        .map_or([0; 16], ChannelBindings::digest);
    let cbt = options.flags.contains(ContextFlags::CHANNEL_BOUND)
        || options.client_aware_channel_bindings;
    let subkey = random_key(ticket.session_key().etype())?;
    let sequence = random_sequence()?;
    let (ctime, cusec, kerberos_time) = now()?;
    let authenticator = rasn_kerberos::Authenticator {
        authenticator_vno: Integer::from(5_i32),
        crealm: kerberos_string(&ticket.client().realm)?,
        cname: principal_name(ticket.client())?,
        cksum: Some(rasn_kerberos::Checksum {
            r#type: checksum::CHECKSUM_TYPE,
            checksum: checksum::encode(&digest, flags, forwarded.as_deref().map(Vec::as_slice))?
                .into(),
        }),
        cusec: Integer::from(cusec),
        ctime: kerberos_time,
        subkey: Some(rasn_kerberos::EncryptionKey {
            r#type: subkey.etype(),
            value: subkey.value().to_vec().into(),
        }),
        seq_number: Some(sequence),
        authorization_data: if cbt {
            Some(checksum::cbt_authorization_data()?)
        } else {
            None
        },
    };
    let token = ap_req_token(&ticket, &authenticator, flags)?;
    let context = established(Parts {
        ticket,
        subkey,
        sequence,
        flags,
        policy,
    });
    if flags.contains(ContextFlags::MUTUAL) {
        initiator.state = InitState::AwaitingReply(Box::new(Pending {
            context,
            ctime,
            cusec,
        }));
        return Ok(InitStep::Continue(token));
    }
    initiator.state = InitState::Established(Box::new(context));
    Ok(InitStep::Complete(Some(token)))
}

/// The initiator's context; without an AP-REP it receives from its own
/// sequence number (MIT `init_sec_context.c:632-641`).
fn established(parts: Parts) -> EstablishedContext {
    let flags = parts.flags | ContextFlags::PROT_READY;
    let sequence = u64::from(parts.sequence);
    EstablishedContext {
        initiated: true,
        source: Name::from_principal(parts.ticket.client()),
        target: Name::from_principal(parts.ticket.service()),
        flags,
        session_key: parts.ticket.session_key().clone(),
        initiator_subkey: Some(parts.subkey),
        acceptor_subkey: None,
        send_sequence: sequence,
        window: seq::Window::new(
            sequence,
            flags.contains(ContextFlags::REPLAY),
            flags.contains(ContextFlags::SEQUENCE),
        ),
        expires: parts.ticket.end_time(),
        crypto_policy: parts.policy,
        delegated: None,
        pac: None,
        open: true,
    }
}

/// The second step: verify the acceptor's AP-REP.
///
/// # Errors
///
/// Returns [`Error::DefectiveToken`] for a token that is not an AP-REP, and the
/// AP-REP decryption, policy and timestamp errors.
fn reply(pending: Pending, token: &[u8]) -> Result<(EstablishedContext, InitStep), Error> {
    let Pending {
        mut context,
        ctime,
        cusec: sent_cusec,
    } = pending;
    let dce = context.flags.contains(ContextFlags::DCE_STYLE);
    let wire = if dce {
        // A raw AP-REP (`init_sec_context.c:757-759`).
        ap_rep::decode(token).map_err(Error::ApRep)?
    } else {
        let mech = Krb5MechToken::decode(token)?;
        if mech.token_id() != Krb5TokenId::ApRep {
            return Err(Error::DefectiveToken(
                "the acceptor did not answer with an AP-REP",
            ));
        }
        ap_rep::decode(mech.message()).map_err(Error::ApRep)?
    };
    let policy = &context.crypto_policy;
    policy.check_use(wire.enc_part.etype, Use::SessionKey)?;
    let part = ap_rep::decrypt_ap_rep_enc_part(&wire, &context.session_key)?;
    let echoed = from_kerberos(&part.ctime);
    let cusec = part.cusec.to_string().parse::<u32>().ok();
    if echoed != Some(ctime) || cusec != Some(sent_cusec) {
        return Err(Error::DefectiveToken(
            "the AP-REP does not echo the authenticator",
        ));
    }
    let acceptor_subkey = match &part.subkey {
        Some(key) => {
            policy.check_use(key.r#type, Use::AcceptorSubkey)?;
            Some(EncryptionKey::new(key.r#type, key.value.to_vec()))
        }
        None => None,
    };
    context.acceptor_subkey = acceptor_subkey;
    let received = part.seq_number.unwrap_or(0);
    context.window = seq::Window::new(
        u64::from(received),
        context.flags.contains(ContextFlags::REPLAY),
        context.flags.contains(ContextFlags::SEQUENCE),
    );
    if dce {
        let third = dce::initiator_reply(&context.session_key, received)?;
        return Ok((context, InitStep::Complete(Some(third))));
    }
    Ok((context, InitStep::Complete(None)))
}
