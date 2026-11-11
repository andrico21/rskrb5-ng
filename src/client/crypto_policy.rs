//! Shared early client policy checks; no cryptographic work occurs here.

#[cfg(feature = "tokio")]
use core::error::Error as _;

use rasn::{Encode, der};
use zeroize::Zeroizing;

use super::{AsRepSession, Error, ticket_error};
use crate::{
    ap_req,
    config::{LibDefaults, restrictions},
    crypto::{CryptoPolicy, Use, selection},
    error::Policy,
    keytab::EncryptionKey,
    ticket,
};

/// Check explicit PA selections before preparing cryptographic request data.
/// # Errors
/// Returns policy rejection for a forbidden selection, or malformed credential DER.
pub(super) fn padata(policy: &CryptoPolicy, data: &[rasn_kerberos::PaData]) -> Result<(), Error> {
    for entry in data {
        selection::preauth(entry.r#type)?;
        match entry.r#type {
            super::PA_TGS_REQ => {
                let request = ap_req::decode(&entry.value).map_err(super::ap_req_error)?;
                policy.check_use(request.ticket.enc_part.etype, Use::TicketKey)?;
                policy.check_use(request.authenticator.etype, Use::SessionKey)?;
            }
            super::PA_ENC_TIMESTAMP => {
                let encrypted: rasn_kerberos::EncryptedData =
                    super::decode("PA-ENC-TIMESTAMP", &entry.value)?;
                policy.check_use(encrypted.etype, Use::ReplyKey)?;
            }
            // These credential mechanisms have no checked envelope implementation.
            // Reject rather than transmit opaque nested encryption (including FAST).
            5..=9
            | 11..=13
            | 16..=17
            | 19_i32
            | 22..=23
            | 30..=31
            | 41_i32
            | 130_i32
            | 134..=136
            | 138_i32
            | 141..=148
            | 151..=153
            | 165_i32 => {
                return Err(Error::Encode {
                    target: "PA-DATA",
                    message: format!(
                        "unsupported credential preauthentication type {}",
                        entry.r#type
                    ),
                });
            }
            _ => {}
        }
    }
    Ok(())
}

/// Resolve public defaults without allowing invalid input to become unrestricted.
/// # Errors
/// Returns typed policy rejection for invalid configuration.
pub(super) fn configured(defaults: &LibDefaults) -> Result<CryptoPolicy, Error> {
    CryptoPolicy::from_libdefaults(defaults).map_err(|error| {
        match restrictions::configuration_policy(&error) {
            Policy::InvalidConfiguration => Error::from(error),
            policy @ (Policy::UnknownEnctype { etype: _ }
            | Policy::S2kIterationsTooLow {
                etype: _,
                minimum: _,
                actual: _,
            }
            | Policy::InvalidS2kMinimum { minimum: _ }
            | Policy::EnctypeNotPermitted { etype: _, usage: _ }
            | Policy::RejectedFeature {
                feature: _,
                reason: _,
            }) => Error::from(policy),
        }
    })
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
    policy.check_use(session.session_key().etype(), usage)?;
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
    restrictions::config(&client.config)?;
    if let Some(error) = client.import_policy_error {
        return Err(error.into());
    }
    drop(configured(&client.config.libdefaults)?);
    Ok(())
}

/// Require the supplied bytes to encode exactly the message being authorized.
/// # Errors
/// Returns an encoding error for malformed or independently replaced wire bytes.
pub(super) fn wire_message<T>(message: &T, bytes: &[u8], target: &'static str) -> Result<(), Error>
where
    T: Encode,
{
    let encoded = Zeroizing::new(der::encode(message).map_err(|error| Error::Encode {
        target,
        message: error.to_string(),
    })?);
    (encoded.as_slice() == bytes).ok_or_else(|| Error::Encode {
        target,
        message: "request DER does not match the authorized message".to_owned(),
    })
}

/// Authorize every additional credential before request cryptography or transport.
/// # Errors
/// Returns the first ticket encryption policy refusal.
pub(super) fn additional_tickets(
    policy: &CryptoPolicy,
    tickets: &[rasn_kerberos::Ticket],
) -> Result<(), Error> {
    for ticket in tickets {
        policy.check_use(ticket.enc_part.etype, Use::TicketKey)?;
    }
    Ok(())
}

/// Validate every visible request encryption envelope and reply key before transport.
///
/// Body authorization data uses the TGT session key or authenticator subkey
/// (RFC 4120 section 5.4.1, key usages 4/5), classified as `Use::SessionKey`.
/// # Errors
/// Returns the first typed policy refusal without performing I/O.
pub(super) fn before_exchange(
    policy: &CryptoPolicy,
    message: &rasn_kerberos::KdcReq,
    key: &EncryptionKey,
) -> Result<(), Error> {
    padata(policy, message.padata.as_deref().unwrap_or_default())?;
    for &etype in &message.req_body.etype {
        policy.check_use(etype, Use::RequestList)?;
    }
    policy.check_use(key.etype(), Use::ReplyKey)?;
    if let Some(encrypted) = &message.req_body.enc_authorization_data {
        policy.check_use(encrypted.etype, Use::SessionKey)?;
    }
    additional_tickets(
        policy,
        message
            .req_body
            .additional_tickets
            .as_deref()
            .unwrap_or_default(),
    )?;
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
        request.message().0.req_body.kdc_options.0.clone(),
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
