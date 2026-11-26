//! The authenticator and the AP-REQ of the krb5 initiator.
//!
//! Names, time, the negotiated flags, the delegated KRB-CRED and the AP-REQ
//! encoding (MIT `init_sec_context.c:240-345, 537-586`).

use core::{slice, time::Duration};
use std::time::{SystemTime, UNIX_EPOCH};

use rasn_kerberos::KerberosTime;
use zeroize::Zeroizing;

use super::{
    ContextFlags, Credential, EncryptionKey, Error, MUTUAL_REQUIRED, Principal, SENT_FLAGS,
    TgsRepSession, cred,
};
use crate::{ap_req, crypto::KerberosEtype, krb_cred, ticket};

/// A Kerberos string.
///
/// # Errors
///
/// Returns [`Error::BadName`] for a string Kerberos cannot carry.
pub(super) fn kerberos_string(value: &str) -> Result<rasn_kerberos::KerberosString, Error> {
    rasn_kerberos::KerberosString::from_bytes(value.as_bytes())
        .map_err(|_invalid| Error::BadName("not a Kerberos string"))
}

/// The ASN.1 name of `principal`.
///
/// # Errors
///
/// Returns [`Error::BadName`] for a component Kerberos cannot carry.
pub(super) fn principal_name(principal: &Principal) -> Result<rasn_kerberos::PrincipalName, Error> {
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
pub(super) fn now() -> Result<(SystemTime, u32, KerberosTime), Error> {
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
pub(super) fn negotiate(
    requested: ContextFlags,
    enforce: bool,
    ok_as_delegate: bool,
) -> ContextFlags {
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
pub(super) fn delegation(
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

/// The DER AP-REQ of `authenticator` with the service ticket.
///
/// # Errors
///
/// Returns the ticket and AP-REQ errors.
pub(super) fn ap_req_der(
    ticket: &TgsRepSession,
    authenticator: &rasn_kerberos::Authenticator,
    mutual: bool,
) -> Result<Zeroizing<Vec<u8>>, Error> {
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
    Ok(Zeroizing::new(
        ap_req::encode(&message).map_err(Error::ApReq)?,
    ))
}
