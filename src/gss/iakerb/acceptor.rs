//! The IAKERB acceptor.
//!
//! The acceptor of MIT 1.22.2 `iakerb_acceptor_step` (`iakerb.c:380-457`) and
//! the AP exchange of `iakerb_gss_accept_sec_context` (`iakerb.c:847-930`)
//! over `krb5_gss_accept_sec_context_ext` (`accept_sec_context.c:665-1150`),
//! with the checks MIT lacks: the relay policy decides which realms, requests,
//! rounds and bytes pass, and a reply that is not a KDC message is not returned.

use core::cell::RefCell;
use std::time::SystemTime;

use chrono::Timelike as _;
use rasn::der;
use zeroize::Zeroizing;

use super::{
    AP_REP_TOKEN_ID, AP_REQ_TOKEN_ID, AcceptStep, Error, KdcRelay, RelayFailure, RelayPolicy,
    Token, conversation::Conversation, finished, frame, unframe,
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
    kdc_req,
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
/// `KRB_AP_ERR_IAKERB_KDC_NOT_FOUND`.
const KDC_NOT_FOUND: i32 = 85;
/// `KRB_AP_ERR_IAKERB_KDC_NO_RESPONSE`.
const KDC_NO_RESPONSE: i32 = 86;
/// The leading tag of an AS-REQ (`[APPLICATION 10]`).
const AS_REQ_TAG: u8 = 0x6a;
/// The leading tag of a TGS-REQ (`[APPLICATION 12]`).
const TGS_REQ_TAG: u8 = 0x6c;
/// The leading tags of a KDC reply: AS-REP, TGS-REP and KRB-ERROR.
const REPLY_TAGS: [u8; 3] = [0x6b, 0x6d, 0x7e];

/// The acceptor's state.
pub(super) struct State {
    /// What it may relay.
    policy: RelayPolicy,
    /// Whether the context is established.
    done: bool,
}

/// A new acceptor state.
pub(super) const fn new(policy: RelayPolicy) -> State {
    State {
        policy,
        done: false,
    }
}

impl State {
    /// Whether the context is established.
    pub(super) const fn is_established(&self) -> bool {
        self.done
    }
}

/// One acceptor step.
///
/// # Errors
///
/// Returns the errors of [`super::IakerbContext::accept_sec_context`].
pub(super) fn step(
    state: &mut State,
    conversation: &mut Conversation,
    (acceptor, relay): (&mut Acceptor<'_>, &mut dyn KdcRelay),
    token: &[u8],
) -> Result<AcceptStep, Error> {
    if state.done {
        return Err(Error::UnexpectedStep("the context is established"));
    }
    conversation.check_size(token.len())?;
    if Token::is_iakerb(token) {
        return proxy(state, conversation, relay, token);
    }
    let accepted = ap(conversation, acceptor, token)?;
    state.done = true;
    Ok(AcceptStep::Complete(Box::new(accepted)))
}

/// A proxy token: answer realm discovery or relay one request.
///
/// # Errors
///
/// Returns the policy, relay and token errors.
fn proxy(
    state: &State,
    conversation: &mut Conversation,
    relay: &mut dyn KdcRelay,
    token: &[u8],
) -> Result<AcceptStep, Error> {
    conversation.check_round()?;
    let request = Token::decode(token)?;
    conversation.append(token)?;
    let answer = match (request.realm().is_empty(), request.message().is_empty()) {
        (true, true) => Token::new(state.policy.local_realm(), None, Vec::new()),
        (false, false) => relayed(&state.policy, relay, &request)?,
        (true, false) | (false, true) => {
            return Err(Error::BadToken("the realm and the message are both set or both empty"));
        }
    };
    Ok(AcceptStep::Continue(conversation.produce(answer.encode()?)?))
}

/// The realm a KDC request is for, when it is a well-formed AS-REQ or TGS-REQ.
fn request_realm(request: &[u8]) -> Option<String> {
    let body = match request.first()? {
        &AS_REQ_TAG => kdc_req::decode_as_req(request).ok()?.0.req_body,
        &TGS_REQ_TAG => kdc_req::decode_tgs_req(request).ok()?.0.req_body,
        _ => return None,
    };
    String::from_utf8(body.realm.as_bytes().to_vec()).ok()
}

/// Relay `request` under the policy and wrap the answer.
///
/// # Errors
///
/// Returns [`Error::RealmNotPermitted`], [`Error::RequestRefused`],
/// [`Error::RelayFailed`] and [`Error::BadRelayReply`].
fn relayed(
    policy: &RelayPolicy,
    relay: &mut dyn KdcRelay,
    request: &Token,
) -> Result<Token, Error> {
    let realm = request.realm();
    if !policy.permits(realm) {
        return Err(Error::RealmNotPermitted(realm.to_owned()));
    }
    if request_realm(request.message()).as_deref() != Some(realm) {
        return Err(Error::RequestRefused(
            "not an AS-REQ or TGS-REQ for the realm of the token header",
        ));
    }
    let reply = match relay.relay(realm, request.message()) {
        Ok(reply) => {
            if reply.len() > policy.max_message_bytes
                || !reply.first().is_some_and(|tag| REPLY_TAGS.contains(tag))
            {
                return Err(Error::BadRelayReply("not an AS-REP, TGS-REP or KRB-ERROR"));
            }
            reply
        }
        Err(RelayFailure::KdcUnreachable) => error_message(KDC_NO_RESPONSE)?,
        Err(RelayFailure::RealmUnknown) => error_message(KDC_NOT_FOUND)?,
        Err(RelayFailure::Other(text)) => return Err(Error::RelayFailed(text)),
    };
    Ok(Token::new(realm, None, reply))
}

/// A KRB-ERROR of `code` for the anonymous server principal, as MIT sends when
/// it has no acceptor name (`iakerb.c:84-100`).
///
/// # Errors
///
/// Returns [`Error::BadToken`] when the error does not encode.
fn error_message(code: i32) -> Result<Vec<u8>, Error> {
    let failed = || Error::BadToken("the KRB-ERROR does not encode");
    let name = |text: &str| rasn_kerberos::KerberosString::from_bytes(text.as_bytes());
    let now = chrono::DateTime::<chrono::Utc>::from(SystemTime::now())
        .with_nanosecond(0)
        .ok_or_else(failed)?;
    der::encode(&rasn_kerberos::KrbError {
        pvno: 5_i32.into(),
        msg_type: 30_i32.into(),
        ctime: None,
        cusec: None,
        stime: rasn_kerberos::KerberosTime(now.fixed_offset()),
        susec: 0_i32.into(),
        error_code: code,
        crealm: None,
        cname: None,
        realm: name("WELLKNOWN:ANONYMOUS").map_err(|_invalid| failed())?,
        sname: rasn_kerberos::PrincipalName {
            r#type: 11,
            string: vec![
                name("WELLKNOWN").map_err(|_invalid| failed())?,
                name("ANONYMOUS").map_err(|_invalid| failed())?,
            ],
        },
        e_text: None,
        e_data: None,
    })
    .map_err(|_encode| failed())
}

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
fn ap(
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
