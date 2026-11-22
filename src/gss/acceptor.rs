//! The krb5 mechanism's acceptor (MIT 1.22.2 `accept_sec_context.c:406-621`
//! for the checksum and channel bindings, `:665-1150` for the context and the
//! AP-REP).

use core::cell::RefCell;

use zeroize::Zeroizing;

use super::{
    Accepted, Acceptor, AcceptorOptions, ChannelBindings, ContextFlags, Credential,
    CredentialUsage, EncryptionKey, Error, EstablishedContext, Name, Principal, bindings, checksum,
    cred, initiator, seq,
};
use crate::{
    ap_req,
    ccache::CCache,
    crypto::KerberosEtype,
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
    if let Some(cache) = &credential.replay {
        validator = validator.with_shared_replay_cache(cache.clone())?;
    }
    if let Some(name) = &credential.name {
        validator.set_acceptor_name(cred::acceptor_name(name, options.ignore_acceptor_hostname));
    }
    Ok(Acceptor { validator, options })
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
/// acceptor's bindings policy.
///
/// # Errors
///
/// Returns [`Error::DefectiveChecksum`] for a missing or malformed checksum,
/// [`Error::BadBindings`] and [`Error::MissingBindings`] by the policy, and
/// [`Error::DefectiveToken`] without a sequence number.
fn check(
    authenticator: &rasn_kerberos::Authenticator,
    options: &AcceptorOptions,
) -> Result<Checked, Error> {
    let value = authenticator
        .cksum
        .as_ref()
        .ok_or(Error::DefectiveChecksum(
            "the authenticator has no checksum",
        ))?;
    if value.r#type != checksum::CHECKSUM_TYPE {
        return Err(Error::DefectiveChecksum("not a GSS checksum"));
    }
    let mut decoded = checksum::decode(&value.checksum)?;
    let ours = options.bindings.as_ref().map(ChannelBindings::digest);
    let present = *decoded.bindings() != [0; 16];
    let bound = present && ours.is_some_and(|digest| bindings::same(decoded.bindings(), &digest));
    if present && ours.is_some() && !bound {
        return Err(Error::BadBindings);
    }
    if checksum::asserts_cbt(authenticator.authorization_data.as_ref())? && ours.is_some() && !bound
    {
        return Err(Error::BadBindings);
    }
    if options.require_bindings && !bound {
        return Err(Error::MissingBindings);
    }
    if authenticator.seq_number.is_none() {
        return Err(Error::DefectiveToken(
            "the authenticator has no sequence number",
        ));
    }
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
        |failure| match validated.subkey() {
            Some(subkey) => krb_cred::import::decode_decrypt(policy, bytes, subkey),
            None => Err(failure),
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
    let mech = Krb5MechToken::decode(token)?;
    let request = mech
        .ap_req_bytes()
        .ok_or(Error::DefectiveToken("the first token is not an AP-REQ"))?;
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
                *outcome.borrow_mut() = Some(check(authenticator, options)?);
                Ok::<(), Error>(())
            })?;
    let checked = outcome
        .into_inner()
        .ok_or(Error::UnexpectedStep("the authenticator was not checked"))?;
    let mut flags = checked.flags.intersection(INITIATOR_FLAGS)
        | ContextFlags::TRANS
        | ContextFlags::PROT_READY;
    if checked.bound {
        flags = flags | ContextFlags::CHANNEL_BOUND;
    }
    let delegated_credential = match &checked.delegation {
        Some(bytes) => {
            flags = flags | ContextFlags::DELEG;
            Some(Box::new(delegated(&validated, bytes)?))
        }
        None => None,
    };
    if mutual_option {
        flags = flags | ContextFlags::MUTUAL;
    }
    let received = validated.sequence_number().ok_or(Error::DefectiveToken(
        "the authenticator has no sequence number",
    ))?;
    let (send, subkey, output_token) = if flags.contains(ContextFlags::MUTUAL) {
        let current = validated.subkey().unwrap_or(validated.session_key());
        let subkey = acceptor_subkey(current.etype())?;
        let send = initiator::random_sequence()?;
        let reply_options = ApRepOptions::default()
            .with_subkey(subkey.clone())
            .with_sequence_number(Some(send));
        let etype = KerberosEtype::from_etype_id(validated.session_key().etype())
            .ok_or(Error::LegacyTokenFormat(validated.session_key().etype()))?;
        let mut confounder = Zeroizing::new(vec![0; etype.confounder_len()]);
        getrandom::fill(&mut confounder)?;
        let reply = validated.build_ap_rep_with_confounder(&confounder, &reply_options)?;
        let mut answer = Krb5MechToken::ap_rep(reply);
        answer.set_oid(mech.oid().clone());
        (send, subkey, Some(answer.encode()?))
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
    };
    Ok(Accepted {
        context,
        output_token,
    })
}
