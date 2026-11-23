//! The AP exchange of the IAKERB acceptor: the checks of the authenticator,
//! among them the `IAKERB-FINISHED` checksum, and the context with its AP-REP.

use core::cell::RefCell;

use zeroize::Zeroizing;

use super::super::{
    AP_REP_TOKEN_ID, AP_REQ_TOKEN_ID, Error, conversation::Conversation, finished, frame, unframe,
};
use crate::{
    ap_req,
    client::principal::Principal,
    crypto::KerberosEtype,
    error::Gss,
    gss::{
        Accepted, Acceptor, AcceptorOptions, ChannelBindings, ContextFlags, EncryptionKey,
        EstablishedContext, Name, bindings, checksum,
        initiator::{random_key, random_sequence},
        seq,
    },
    service::{self, ApRepOptions, ValidatedApReq},
};

/// The flags the acceptor takes from the initiator's checksum
/// (MIT `accept_sec_context.c:413-416`).
const INITIATOR_FLAGS: ContextFlags = ContextFlags::from_bits(
    ContextFlags::INTEG.bits()
        | ContextFlags::CONF.bits()
        | ContextFlags::MUTUAL.bits()
        | ContextFlags::REPLAY.bits()
        | ContextFlags::SEQUENCE.bits()
        | ContextFlags::IDENTIFY.bits()
        | ContextFlags::EXTENDED_ERROR.bits(),
);
/// The AP option `mutual-required` (RFC 4120 section 5.5.1, bit 2).
const MUTUAL_REQUIRED_BIT: usize = 2;
/// What the authenticator told the acceptor.
struct Checked {
    /// The initiator's flags.
    flags: ContextFlags,
    /// Whether matching bindings were present.
    bound: bool,
}

/// Check the authenticator: the checksum, the channel bindings, the sequence
/// number and the `IAKERB-FINISHED` against the transcript.
///
/// # Errors
///
/// Returns [`Error::MissingFinished`], [`Error::BadFinished`] and
/// [`Error::UnexpectedFinished`] for the transcript checksum, and the GSS
/// checksum, bindings and delegation errors.
fn check(
    authenticator: &rasn_kerberos::Authenticator,
    options: &AcceptorOptions,
    transcript: &[u8],
) -> Result<Checked, Error> {
    let value = authenticator
        .cksum
        .as_ref()
        .ok_or(Gss::DefectiveChecksum("the authenticator has no checksum"))?;
    if value.r#type != checksum::CHECKSUM_TYPE {
        return Err(Gss::DefectiveChecksum("not a GSS checksum").into());
    }
    let mut decoded = checksum::decode(&value.checksum)?;
    if decoded.take_delegation().is_some() {
        return Err(Error::DelegationUnsupported);
    }
    let ours = options.bindings.as_ref().map(ChannelBindings::digest);
    let present = *decoded.bindings() != [0; 16];
    let bound = present && ours.is_some_and(|digest| bindings::same(decoded.bindings(), &digest));
    if (present && ours.is_some() && !bound)
        || (checksum::asserts_cbt(authenticator.authorization_data.as_ref())?
            && ours.is_some()
            && !bound)
    {
        return Err(Gss::BadBindings.into());
    }
    if options.require_bindings && !bound {
        return Err(Gss::MissingBindings.into());
    }
    if authenticator.seq_number.is_none() {
        return Err(Gss::DefectiveToken("the authenticator has no sequence number").into());
    }
    match (transcript.is_empty(), finished::find(&value.checksum)?) {
        (true, None) => {}
        (true, Some(_)) => return Err(Error::UnexpectedFinished),
        (false, None) => return Err(Error::MissingFinished),
        (false, Some(proof)) => {
            let subkey = authenticator.subkey.as_ref().ok_or(Error::BadFinished)?;
            let key = EncryptionKey::new(subkey.r#type, subkey.value.to_vec());
            finished::verify(&key, transcript, &proof)?;
        }
    }
    Ok(Checked {
        flags: decoded.flags(),
        bound,
    })
}

/// A client principal from the validator's form.
fn principal(value: &service::Principal) -> Principal {
    Principal::new(
        value.realm.clone(),
        value.name_type,
        value.components.clone(),
    )
}

/// A random acceptor subkey of `etype`, none for the legacy enctypes.
///
/// # Errors
///
/// Returns the random source and key errors.
fn acceptor_subkey(etype: i32) -> Result<Option<EncryptionKey>, Error> {
    match KerberosEtype::from_etype_id(etype) {
        Some(KerberosEtype::Sha1(_) | KerberosEtype::Sha2(_) | KerberosEtype::Camellia(_)) => {
            Ok(Some(random_key(etype)?))
        }
        Some(KerberosEtype::Des3CbcSha1Kd(_) | KerberosEtype::Rc4Hmac(_)) | None => Ok(None),
    }
}

/// The AP-REQ after the exchange: validate it, the finished checksum before the
/// replay state is committed, and answer with the AP-REP.
///
/// # Errors
///
/// Returns the AP-REQ validation errors and those of [`check`].
pub(super) fn ap(
    conversation: &Conversation,
    acceptor: &mut Acceptor<'_>,
    token: &[u8],
) -> Result<Accepted, Error> {
    let (id, request) = unframe(token)?;
    if id != AP_REQ_TOKEN_ID {
        return Err(Error::UnexpectedStep("the token is neither a proxy token nor an AP-REQ"));
    }
    let mutual_option = ap_req::decode(request)?
        .ap_options
        .0
        .get(MUTUAL_REQUIRED_BIT)
        .is_some_and(|bit| *bit);
    let outcome = RefCell::new(None);
    let options = &acceptor.options;
    let validated =
        acceptor
            .validator
            .validate_ap_req_with_check(request, |authenticator, _session_key| {
                *outcome.borrow_mut() =
                    Some(check(authenticator, options, conversation.transcript())?);
                Ok::<(), Error>(())
            })?;
    let checked = outcome
        .into_inner()
        .ok_or(Error::UnexpectedStep("the authenticator was not checked"))?;
    context(&validated, &checked, mutual_option)
}

/// The established context and the AP-REP of a validated AP-REQ.
///
/// # Errors
///
/// Returns the sequence, key and AP-REP errors.
fn context(
    validated: &ValidatedApReq,
    checked: &Checked,
    mutual_option: bool,
) -> Result<Accepted, Error> {
    let mut flags = checked.flags.intersection(INITIATOR_FLAGS)
        | ContextFlags::TRANS
        | ContextFlags::PROT_READY;
    if checked.bound {
        flags = flags | ContextFlags::CHANNEL_BOUND;
    }
    if mutual_option {
        flags = flags | ContextFlags::MUTUAL;
    }
    let received = validated
        .sequence_number()
        .ok_or(Gss::DefectiveToken("the authenticator has no sequence number"))?;
    let (send, subkey, output_token) = if flags.contains(ContextFlags::MUTUAL) {
        let current = validated
            .subkey()
            .unwrap_or_else(|| validated.session_key());
        let subkey = acceptor_subkey(current.etype())?;
        let send = random_sequence()?;
        let reply_options = ApRepOptions::default()
            .with_subkey(subkey.clone())
            .with_sequence_number(Some(send));
        let kind = KerberosEtype::from_etype_id(validated.session_key().etype())
            .ok_or(Gss::LegacyTokenFormat(validated.session_key().etype()))?;
        let mut confounder = Zeroizing::new(vec![0; kind.confounder_len()]);
        getrandom::fill(&mut confounder)?;
        let reply = validated.build_ap_rep_with_confounder(&confounder, &reply_options)?;
        (send, subkey, Some(frame(AP_REP_TOKEN_ID, &reply)?))
    } else {
        (received, None, None)
    };
    let context = EstablishedContext {
        initiated: false,
        source: Name::from_principal(&principal(validated.client())),
        target: Name::from_principal(&principal(validated.service())),
        flags,
        session_key: validated.session_key().clone(),
        initiator_subkey: validated.subkey().cloned(),
        acceptor_subkey: subkey,
        send_sequence: u64::from(send),
        window: seq::Window::new(
            u64::from(received),
            flags.contains(ContextFlags::REPLAY),
            flags.contains(ContextFlags::SEQUENCE),
        ),
        expires: validated.ticket_end(),
        crypto_policy: validated.crypto_policy().clone(),
        delegated: None,
        pac: validated.pac().cloned(),
    };
    Ok(Accepted {
        context,
        output_token,
    })
}
