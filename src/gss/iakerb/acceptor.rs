//! The IAKERB acceptor.
//!
//! The acceptor of MIT 1.22.2 `iakerb_acceptor_step` (`iakerb.c:380-457`) and
//! the AP exchange of `iakerb_gss_accept_sec_context` (`iakerb.c:847-930`)
//! over `krb5_gss_accept_sec_context_ext` (`accept_sec_context.c:665-1150`),
//! with the checks MIT lacks: the relay policy decides which realms, requests,
//! rounds and bytes pass, and a reply that is not a KDC message is not returned.

use std::time::SystemTime;

use chrono::Timelike as _;
use rasn::der;

use super::{
    AcceptStep, Error, KdcRelay, RelayFailure, RelayPolicy, Token, conversation::Conversation,
};
use crate::{gss::Acceptor, kdc_req};

mod ap;

use ap::ap;

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
    /// The tokens exchanged and their bounds.
    conversation: Conversation,
}

/// A new acceptor state.
pub(super) const fn new(policy: RelayPolicy) -> State {
    State {
        conversation: Conversation::for_policy(&policy),
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
/// Returns the errors of [`super::Context::accept_sec_context`].
pub(super) fn step(
    state: &mut State,
    (acceptor, relay): (&mut Acceptor<'_>, &mut dyn KdcRelay),
    token: &[u8],
) -> Result<AcceptStep, Error> {
    if state.done {
        return Err(Error::UnexpectedStep("the context is established"));
    }
    state.conversation.check_size(token.len())?;
    if Token::is_iakerb(token) {
        return proxy(state, relay, token);
    }
    let accepted = ap(state.conversation.transcript(), acceptor, token)?;
    state.done = true;
    Ok(AcceptStep::Complete(Box::new(accepted)))
}

/// A proxy token: answer realm discovery or relay one request.
///
/// # Errors
///
/// Returns the policy, relay and token errors.
fn proxy(state: &mut State, relay: &mut dyn KdcRelay, token: &[u8]) -> Result<AcceptStep, Error> {
    state.conversation.check_round()?;
    let request = Token::decode(token)?;
    state.conversation.append(token)?;
    let answer = match (request.realm().is_empty(), request.message().is_empty()) {
        (true, true) => Token::new(state.policy.local_realm(), None, Vec::new()),
        (false, false) => relayed(&state.policy, relay, &request)?,
        (true, false) | (false, true) => {
            return Err(Error::BadToken(
                "the realm and the message are both set or both empty",
            ));
        }
    };
    Ok(AcceptStep::Continue(
        state.conversation.produce(answer.encode()?)?,
    ))
}

/// The realm a KDC request is for, when it is a well-formed AS-REQ or TGS-REQ.
fn request_realm(request: &[u8]) -> Option<String> {
    let body = match *request.first()? {
        AS_REQ_TAG => kdc_req::decode_as_req(request).ok()?.0.req_body,
        TGS_REQ_TAG => kdc_req::decode_tgs_req(request).ok()?.0.req_body,
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
