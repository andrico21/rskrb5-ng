//! Shared early client policy checks; no cryptographic work occurs here.

#[cfg(feature = "tokio")]
use core::error::Error as _;

use super::{AsRepSession, Error, ticket_error};
#[cfg(feature = "tokio")]
use crate::config::LibDefaults;
use crate::{
    crypto::{CryptoPolicy, Use, selection},
    error::Policy,
    keytab::EncryptionKey,
    ticket,
};

/// Check explicit PA selections before preparing cryptographic request data.
/// # Errors
/// Returns permanent draft-9 rejection for outgoing PA types 14 or 15.
pub(super) fn padata(data: &[rasn_kerberos::PaData]) -> Result<(), Error> {
    for entry in data {
        selection::preauth(entry.r#type)?;
    }
    Ok(())
}

/// Resolve public defaults without allowing invalid input to become unrestricted.
/// # Errors
/// Returns typed policy rejection for invalid configuration.
#[cfg(feature = "tokio")]
pub(super) fn configured(defaults: &LibDefaults) -> Result<CryptoPolicy, Error> {
    CryptoPolicy::from_libdefaults(defaults)
        .map_err(|_invalid_config| Policy::InvalidConfiguration.into())
}

/// Check every requested enctype before encoding, derivation or transport.
/// # Errors
/// Returns a typed policy refusal or the existing empty-request error.
pub(super) fn request(
    policy: &Result<CryptoPolicy, Policy>,
    etypes: &[i32],
) -> Result<CryptoPolicy, Error> {
    let active = policy.as_ref().map_err(|error| *error)?;
    for &etype in etypes {
        active.check_use(etype, Use::RequestList)?;
    }
    (!etypes.is_empty()).ok_or(Error::EmptyEtypes)?;
    Ok(active.clone())
}

/// Check session and visible ticket enctypes before admission or use.
/// # Errors
/// Returns policy rejection before key use, or a malformed-ticket error.
pub(super) fn session(
    policy: &CryptoPolicy,
    session: &AsRepSession,
    usage: Use,
) -> Result<(), Error> {
    policy.check_use(session.session_key.etype, usage)?;
    let ticket = ticket::decode(&session.ticket).map_err(ticket_error)?;
    let ticket_usage = match usage {
        Use::ImportedCredential => Use::ImportedCredential,
        Use::RequestList
        | Use::ReplyKey
        | Use::SessionKey
        | Use::TicketKey
        | Use::AcceptorTicket
        | Use::AcceptorSubkey
        | Use::CheckedLowLevel => Use::TicketKey,
    };
    policy.check_use(ticket.enc_part.etype, ticket_usage)?;
    let service = super::principal_from_parts(&ticket.realm, &ticket.sname)?;
    super::principal_matches(&service, &session.service).ok_or_else(|| {
        Error::ServicePrincipalMismatch {
            expected: session.service.name(),
            actual: service.name(),
        }
    })?;
    Ok(())
}

/// Recover a typed policy cause while retaining legacy constructor signatures.
#[cfg(feature = "tokio")]
pub(super) fn cause(error: &Error) -> Option<Policy> {
    let mut source = error.source();
    while let Some(current) = source {
        if let Some(policy) = current.downcast_ref::<Policy>() {
            return Some(*policy);
        }
        source = current.source();
    }
    None
}

/// Refuse deferred import/configuration failures before any client effect.
/// # Errors
/// Returns the original policy refusal or an invalid configuration refusal.
#[cfg(feature = "tokio")]
pub(super) fn ready(client: &super::Tokio) -> Result<(), Error> {
    if let Some(error) = client.import_policy_error {
        return Err(error.into());
    }
    drop(configured(&client.config.libdefaults)?);
    Ok(())
}

/// Validate request preferences and the reply key before opening a transport.
/// # Errors
/// Returns the first typed policy refusal without performing I/O.
pub(super) fn before_exchange(
    policy: &CryptoPolicy,
    etypes: &[i32],
    key: &EncryptionKey,
) -> Result<(), Error> {
    for &etype in etypes {
        policy.check_use(etype, Use::RequestList)?;
    }
    policy.check_use(key.etype, Use::ReplyKey)?;
    Ok(())
}

/// Bind delegated identities only after authorizing their ticket encryption types.
/// # Errors
/// Returns policy, missing-delegation-key or existing ticket-validation errors.
pub(super) fn delegated(
    request: &super::BuiltTgsReq,
    ticket: &rasn_kerberos::Ticket,
) -> Result<(), Error> {
    if request
        .message
        .0
        .padata
        .as_deref()
        .is_some_and(|data| super::padata_contains(data, super::PA_FOR_USER))
    {
        let keys = request
            .delegation_keytab
            .as_ref()
            .ok_or(Error::DelegationKeyRequired)?;
        request
            .crypto_policy
            .check_use(ticket.enc_part.etype, Use::TicketKey)?;
        super::validate_delegated_ticket(ticket, &request.client, keys)?;
    }
    if u32::from_be_bytes(super::ticket_flags_to_bytes(&rasn_kerberos::TicketFlags(
        request.message.0.req_body.kdc_options.0.clone(),
    ))) & super::KDC_OPTION_CNAME_IN_ADDL_TKT
        != 0
    {
        let keys = request
            .delegation_keytab
            .as_ref()
            .ok_or(Error::DelegationKeyRequired)?;
        let evidence = request
            .message
            .0
            .req_body
            .additional_tickets
            .as_ref()
            .and_then(|tickets| tickets.first())
            .ok_or(Error::DelegationPrincipalMismatch)?;
        request
            .crypto_policy
            .check_use(evidence.enc_part.etype, Use::TicketKey)?;
        super::validate_delegated_ticket(evidence, &request.client, keys)?;
    }
    Ok(())
}
