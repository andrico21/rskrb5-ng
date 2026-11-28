//! The krb5 mechanism's initiator.
//!
//! The krb5 mechanism's initiator (MIT 1.22.2 `init_sec_context.c:240-688`
//! and `mutual_auth`, `init_sec_context.c:691-870`).

use core::mem;
use std::time::SystemTime;

use rasn::types::Integer;
use zeroize::Zeroizing;

use super::{
    ChannelBindings, ContextFlags, Credential, CredentialUsage, CryptoPolicy, EncryptionKey, Error,
    EstablishedContext, InitState, InitStep, Initiator, InitiatorOptions, Name, Principal,
    TgsRepSession,
    checksum::{self, Extensions},
    context::Mechanism,
    cred, dce,
    iakerb::finished,
    seq,
};
use crate::{
    crypto::{KerberosEtype, Use, prf},
    spnego::Krb5MechToken,
};

/// The authenticator and the AP-REQ.
mod authenticator;
/// The acceptor's AP-REP.
pub(in crate::gss) mod mutual;

use authenticator::{ap_req_der, delegation, kerberos_string, negotiate, now, principal_name};
use mutual::reply;

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
    /// The mechanism.
    mechanism: Mechanism,
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

/// The first step: the AP-REQ token.
///
/// # Errors
///
/// Returns the errors of [`super::Initiator::init_sec_context`].
fn first(initiator: &mut Initiator, credential: &Credential) -> Result<InitStep, Error> {
    if credential.usage == CredentialUsage::Accept {
        return Err(Error::WrongCredentialUsage("initiate"));
    }
    let _components: &[String] = cred::target_components(&initiator.target)?;
    let ticket = cred::service_ticket(credential, &initiator.target)
        .ok_or(Error::NoCredential("no live service ticket for the target"))?;
    let (token, pending) = request(&initiator.options, (credential, ticket), Extensions::KRB5)?;
    if pending.awaits_reply() {
        initiator.state = InitState::AwaitingReply(Box::new(pending));
        return Ok(InitStep::Continue(token));
    }
    initiator.state = InitState::Established(Box::new(pending.context));
    Ok(InitStep::Complete(Some(token)))
}

impl Pending {
    /// Whether the AP-REP is awaited (mutual authentication).
    pub(super) const fn awaits_reply(&self) -> bool {
        self.context.flags.contains(ContextFlags::MUTUAL)
    }

    /// The context, when no AP-REP is awaited.
    pub(super) fn into_context(self) -> EstablishedContext {
        self.context
    }
}

/// The AP-REQ token of a service ticket and the context it starts.
///
/// The token carries the record's extensions in the authenticator checksum
/// (MIT `krb5_gss_init_sec_context_ext` and `make_gss_checksum`,
/// `init_sec_context.c:240-345`); a delegation carries the forwardable TGT of
/// the credential.
///
/// # Errors
///
/// Returns the policy, delegation, checksum, AP-REQ and token errors.
pub(super) fn request(
    options: &InitiatorOptions,
    (credential, ticket): (&Credential, TgsRepSession),
    extensions: Extensions<'_>,
) -> Result<(Vec<u8>, Pending), Error> {
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
    let mut value = checksum::encode(&digest, flags, forwarded.as_deref().map(Vec::as_slice))?;
    if let Some(conversation) = extensions.conversation() {
        let proof = finished::make(&subkey, conversation)?;
        value.extend_from_slice(&checksum::extension(checksum::FINISHED_EXTENSION, &proof)?);
    }
    let authenticator = rasn_kerberos::Authenticator {
        authenticator_vno: Integer::from(5_i32),
        crealm: kerberos_string(&ticket.client().realm)?,
        cname: principal_name(ticket.client())?,
        cksum: Some(rasn_kerberos::Checksum {
            r#type: checksum::CHECKSUM_TYPE,
            checksum: value.into(),
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
    let der = ap_req_der(
        &ticket,
        &authenticator,
        flags.contains(ContextFlags::MUTUAL),
    )?;
    let token = if flags.contains(ContextFlags::DCE_STYLE) {
        // A raw AP-REQ, without the RFC 2743 framing (`init_sec_context.c:420-426`).
        der.to_vec()
    } else {
        let mut framed = Krb5MechToken::ap_req(der.to_vec());
        framed.set_oid(extensions.mechanism().oid());
        framed.encode()?
    };
    let context = established(Parts {
        ticket,
        subkey,
        sequence,
        flags,
        policy,
        mechanism: extensions.mechanism(),
    });
    Ok((
        token,
        Pending {
            context,
            ctime,
            cusec,
        },
    ))
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
        auth_indicators: Vec::new(),
        open: true,
        mechanism: parts.mechanism,
    }
}
