//! The krb5 mechanism's acceptor.
//!
//! The krb5 mechanism's acceptor (MIT 1.22.2 `accept_sec_context.c:406-621`
//! for the checksum and channel bindings, `:665-1150` for the context and the
//! AP-REP).

use alloc::sync::Arc;
use core::cell::RefCell;

use zeroize::Zeroizing;

use super::{
    Accepted, Acceptor, AcceptorOptions, ChannelBindings, ContextFlags, Credential,
    CredentialUsage, EncryptionKey, Error, EstablishedContext, Name, ObjectIdentifier, Principal,
    bindings,
    checksum::{self, Extensions},
    cred, dce,
    iakerb::finished::{self, Fault},
    impersonate, initiator, seq,
};
use crate::{
    ap_req,
    ccache::CCache,
    crypto::KerberosEtype,
    error::Service,
    krb_cred,
    service::{self, ApRepOptions, ValidatedApReq, Validator},
    spnego::Krb5MechToken,
};

/// The longest context token, in bytes.
const MAX_TOKEN_LEN: usize = 0x4_0000;
/// The flags the acceptor takes from the initiator's checksum
/// (`accept_sec_context.c:413-416`).
const INITIATOR_FLAGS: ContextFlags = ContextFlags::from_bits(
    ContextFlags::INTEG.bits()
        | ContextFlags::CONF.bits()
        | ContextFlags::MUTUAL.bits()
        | ContextFlags::REPLAY.bits()
        | ContextFlags::SEQUENCE.bits()
        | ContextFlags::DCE_STYLE.bits()
        | ContextFlags::IDENTIFY.bits()
        | ContextFlags::EXTENDED_ERROR.bits(),
);
/// The AP option `mutual-required` (RFC 4120 section 5.5.1, bit 2).
const MUTUAL_REQUIRED_BIT: usize = 2;

/// An acceptor of `credential`'s keys.
///
/// # Errors
///
/// Returns the errors of [`super::Acceptor::new`].
pub(super) fn new(
    credential: &Credential,
    options: AcceptorOptions,
) -> Result<Acceptor<'_>, Error> {
    if credential.usage == CredentialUsage::Initiate {
        return Err(Error::WrongCredentialUsage("accept"));
    }
    let keytab = credential
        .keytab
        .as_ref()
        .ok_or(Error::WrongCredentialUsage("accept"))?;
    let mut validator = Validator::new(keytab);
    if let Some(store) = &credential.replay {
        validator = validator.with_replay_store(Arc::clone(store))?;
    }
    if let Some(name) = &credential.name {
        validator.set_acceptor_name(cred::acceptor_name(name, options.ignore_acceptor_hostname));
    }
    Ok(Acceptor {
        validator,
        options,
        credential: Some(credential),
    })
}

/// What the checksum told the acceptor.
struct Checked {
    /// The initiator's flags.
    flags: ContextFlags,
    /// Whether matching bindings were present.
    bound: bool,
    /// The delegated KRB-CRED.
    delegation: Option<Zeroizing<Vec<u8>>>,
}

/// Interpret the authenticator checksum and the CBT assertion against the
/// acceptor's bindings policy, and its extensions against the extension
/// record.
///
/// # Errors
///
/// Returns [`Error::DefectiveChecksum`] for a missing or malformed checksum,
/// [`Error::BadBindings`] and [`Error::MissingBindings`] by the policy,
/// [`Error::DefectiveToken`] without a sequence number, and the [`Fault`] of
/// an `IAKERB-FINISHED` the record does not expect or that does not verify.
fn check<E>(
    authenticator: &rasn_kerberos::Authenticator,
    options: &AcceptorOptions,
    extensions: Extensions<'_>,
) -> Result<Checked, E>
where
    E: From<Error> + From<Fault>,
{
    let value = authenticator
        .cksum
        .as_ref()
        .ok_or(Error::DefectiveChecksum(
            "the authenticator has no checksum",
        ))?;
    if value.r#type != checksum::CHECKSUM_TYPE {
        return Err(Error::DefectiveChecksum("not a GSS checksum").into());
    }
    let mut decoded = checksum::decode(&value.checksum)?;
    let ours = options.bindings.as_ref().map(ChannelBindings::digest);
    let present = *decoded.bindings() != [0; 16];
    let bound = present && ours.is_some_and(|digest| bindings::same(decoded.bindings(), &digest));
    if present && ours.is_some() && !bound {
        return Err(Error::BadBindings.into());
    }
    if checksum::asserts_cbt(authenticator.authorization_data.as_ref())? && ours.is_some() && !bound
    {
        return Err(Error::BadBindings.into());
    }
    if options.require_bindings && !bound {
        return Err(Error::MissingBindings.into());
    }
    if authenticator.seq_number.is_none() {
        return Err(Error::DefectiveToken("the authenticator has no sequence number").into());
    }
    finished::check(
        extensions.conversation(),
        decoded.finished(),
        authenticator.subkey.as_ref(),
    )?;
    Ok(Checked {
        flags: decoded.flags(),
        bound,
        delegation: decoded.take_delegation(),
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

/// The delegated credential: the KRB-CRED decrypted in the session key, or the
/// initiator subkey (MIT `rd_and_store_for_creds`, `accept_sec_context.c:161-237`).
///
/// # Errors
///
/// Returns [`Error::DelegatedCredential`] when neither key opens it or it holds
/// no credential.
fn delegated(validated: &ValidatedApReq, bytes: &[u8]) -> Result<Credential, Error> {
    let policy = validated.crypto_policy();
    let opened = krb_cred::import::decode_decrypt(policy, bytes, validated.session_key()).or_else(
        |failure| {
            validated.subkey().map_or_else(
                || Err(failure),
                |subkey| krb_cred::import::decode_decrypt(policy, bytes, subkey),
            )
        },
    );
    let credentials = opened.map_err(Error::DelegatedCredential)?;
    let first = credentials.first().ok_or(Error::DefectiveToken(
        "the delegated KRB-CRED holds no credential",
    ))?;
    let mut cache = CCache::new(first.client().clone());
    for entry in credentials {
        drop(cache.upsert_credential(entry));
    }
    cred::from_ccache(cache)
}

/// A random acceptor subkey of `etype`, none for the legacy enctypes.
///
/// # Errors
///
/// Returns the random source and key errors.
fn acceptor_subkey(etype: i32) -> Result<Option<EncryptionKey>, Error> {
    match KerberosEtype::from_etype_id(etype) {
        Some(KerberosEtype::Sha1(_) | KerberosEtype::Sha2(_) | KerberosEtype::Camellia(_)) => {
            Ok(Some(initiator::random_key(etype)?))
        }
        Some(KerberosEtype::Des3CbcSha1Kd(_) | KerberosEtype::Rc4Hmac(_)) | None => Ok(None),
    }
}

/// The AP-REP of a mutually authenticated context: the acceptor's sequence
/// number and subkey, and the token, framed with the mechanism `frame` names
/// or raw without one.
///
/// # Errors
///
/// Returns the key, random-source and AP-REP errors.
fn reply(
    validated: &ValidatedApReq,
    frame: Option<&ObjectIdentifier>,
    dce_style: bool,
) -> Result<(u32, Option<EncryptionKey>, Vec<u8>), Error> {
    let current = validated
        .subkey()
        .unwrap_or_else(|| validated.session_key());
    // DCE style implies an acceptor subkey (`accept_sec_context.c:933-934,1020`).
    let subkey = if dce_style {
        Some(initiator::random_key(current.etype())?)
    } else {
        acceptor_subkey(current.etype())?
    };
    let send = initiator::random_sequence()?;
    let reply_options = ApRepOptions::default()
        .with_subkey(subkey.clone())
        .with_sequence_number(Some(send));
    let etype = KerberosEtype::from_etype_id(validated.session_key().etype())
        .ok_or(Error::LegacyTokenFormat(validated.session_key().etype()))?;
    let mut confounder = Zeroizing::new(vec![0; etype.confounder_len()]);
    getrandom::fill(&mut confounder).map_err(Error::Random)?;
    let reply = validated.build_ap_rep_with_confounder(&confounder, &reply_options)?;
    let answer = match frame {
        Some(mechanism) => {
            let mut answer = Krb5MechToken::ap_rep(reply);
            answer.set_oid(mechanism.clone());
            answer.encode()?
        }
        // A raw AP-REP (`accept_sec_context.c:1067-1076`).
        None => reply,
    };
    Ok((send, subkey, answer))
}

/// Whether the AP-REQ `request` asks for mutual authentication.
///
/// # Errors
///
/// Returns the AP-REQ decoding errors.
fn mutual_required(request: &[u8]) -> Result<bool, Error> {
    Ok(ap_req::decode(request)?
        .ap_options
        .0
        .get(MUTUAL_REQUIRED_BIT)
        .is_some_and(|bit| *bit))
}

/// An AP-REQ as it arrived: its DER and the mechanism of its frame, `None`
/// for a raw (DCE-style) one.
pub(super) struct Request<'token> {
    /// The DER AP-REQ.
    der: &'token [u8],
    /// The mechanism of the frame.
    frame: Option<ObjectIdentifier>,
}

impl<'token> Request<'token> {
    /// The AP-REQ `der`, framed with `frame` or raw.
    pub(super) const fn new(der: &'token [u8], frame: Option<ObjectIdentifier>) -> Self {
        Self { der, frame }
    }
}

/// Accept the initiator's first token.
///
/// # Errors
///
/// Returns the errors of [`super::Acceptor::accept_sec_context`].
pub(super) fn accept(acceptor: &mut Acceptor<'_>, token: &[u8]) -> Result<Accepted, Error> {
    if token.len() > MAX_TOKEN_LEN {
        return Err(Error::TokenTooLarge {
            maximum: MAX_TOKEN_LEN,
            actual: token.len(),
        });
    }
    // A raw AP-REQ is the DCE-style first leg (`accept_sec_context.c:770-776`).
    let raw = dce::is_raw_ap_req(token);
    let mech = if raw {
        None
    } else {
        Some(Krb5MechToken::decode(token)?)
    };
    let der = match &mech {
        Some(framed) => framed
            .ap_req_bytes()
            .ok_or(Error::DefectiveToken("the first token is not an AP-REQ"))?,
        None => token,
    };
    let request = Request::new(der, mech.as_ref().map(|framed| framed.oid().clone()));
    establish(acceptor, &request, Extensions::KRB5)
}

/// Validate an AP-REQ and establish its context.
///
/// The mechanism's extension record is applied before the replay cache
/// commits the authenticator (MIT `krb5_gss_accept_sec_context_ext`,
/// `accept_sec_context.c:665-1150`).
///
/// # Errors
///
/// Returns the errors of [`super::Acceptor::accept_sec_context`] and the
/// [`Fault`] of the `IAKERB-FINISHED`.
pub(super) fn establish<E>(
    acceptor: &mut Acceptor<'_>,
    request: &Request<'_>,
    extensions: Extensions<'_>,
) -> Result<Accepted, E>
where
    E: From<Error> + From<Fault> + From<Service>,
{
    let mutual = mutual_required(request.der)?;
    let found = RefCell::new(None);
    let options = &acceptor.options;
    let validated = acceptor.validator.validate_ap_req_with_check(
        request.der,
        |authenticator, _session_key| {
            *found.borrow_mut() = Some(check::<E>(authenticator, options, extensions)?);
            Ok::<(), E>(())
        },
    )?;
    let checked = found
        .into_inner()
        .ok_or(Error::UnexpectedStep("the authenticator was not checked"))?;
    let outcome = Outcome {
        request,
        validated,
        checked,
        mutual,
    };
    Ok(context(acceptor.credential, outcome)?)
}

/// A validated AP-REQ and what its checks found.
struct Outcome<'request, 'token> {
    /// The AP-REQ as it arrived.
    request: &'request Request<'token>,
    /// The validated AP-REQ.
    validated: ValidatedApReq,
    /// What the authenticator checksum told.
    checked: Checked,
    /// Whether the AP options ask for mutual authentication.
    mutual: bool,
}

/// The established context and its AP-REP of a validated AP-REQ; `own` is the
/// acceptor's credential, which composes a proxy credential when it can also
/// initiate.
///
/// # Errors
///
/// Returns the DCE-style, delegation, sequence, key and AP-REP errors.
fn context(own: Option<&Credential>, outcome: Outcome<'_, '_>) -> Result<Accepted, Error> {
    let Outcome {
        request,
        validated,
        checked,
        mutual,
    } = outcome;
    let raw = request.frame.is_none();
    let dce_style = checked.flags.contains(ContextFlags::DCE_STYLE);
    if raw != dce_style {
        // Only DCE-style initiators send raw AP-REQs (`accept_sec_context.c:855-860`).
        return Err(Error::DefectiveToken(
            "a raw AP-REQ needs DCE style and DCE style needs a raw AP-REQ",
        ));
    }
    let mut flags = checked.flags.intersection(INITIATOR_FLAGS)
        | ContextFlags::TRANS
        | ContextFlags::PROT_READY;
    if checked.bound {
        flags = flags | ContextFlags::CHANNEL_BOUND;
    }
    // DCE style never returns a delegated credential (`accept_sec_context.c:349-351`).
    let from_initiator = match &checked.delegation {
        Some(_) if dce_style => None,
        Some(bytes) => {
            flags = flags | ContextFlags::DELEG;
            Some(Box::new(delegated(&validated, bytes)?))
        }
        None => None,
    };
    // An acceptor that can also initiate composes a proxy credential
    // (`kg_compose_deleg_cred`, `accept_sec_context.c:943-952`).
    let delegated_credential = match (from_initiator, own) {
        (None, Some(both)) if both.usage == CredentialUsage::Both && !dce_style => {
            let client = principal(validated.client());
            let evidence = impersonate::evidence(request.der, &client, &validated)?;
            flags = flags | ContextFlags::DELEG;
            Some(Box::new(impersonate::proxy(&evidence, both)))
        }
        (other, _) => other,
    };
    if mutual || dce_style {
        // DCE style implies mutual authentication (`accept_sec_context.c:980-981`).
        flags = flags | ContextFlags::MUTUAL;
    }
    let received = validated.sequence_number().ok_or(Error::DefectiveToken(
        "the authenticator has no sequence number",
    ))?;
    let (send, subkey, output_token) = if flags.contains(ContextFlags::MUTUAL) {
        let (send, subkey, answer) = reply(&validated, request.frame.as_ref(), dce_style)?;
        (send, subkey, Some(answer))
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
        delegated: delegated_credential,
        pac: validated.pac().cloned(),
        auth_indicators: validated.auth_indicators().to_vec(),
        open: !dce_style,
    };
    Ok(Accepted {
        context,
        output_token,
    })
}
