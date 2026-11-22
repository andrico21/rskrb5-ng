//! Shared early client policy checks; no cryptographic work occurs here.

#[cfg(feature = "tokio")]
use core::error::Error as _;

use rasn::{Encode, der};
use rasn_kerberos::otp::PaOtpRequest;
use zeroize::Zeroizing;

use super::{AsRepSession, Error, ticket_error};
use crate::{
    ap_req,
    config::{EnctypeDefaults as _, LibDefaults, restrictions},
    crypto::{CryptoPolicy, Use, selection},
    error::{Config as ConfigError, Policy},
    keytab::EncryptionKey,
    messages, pac,
    preauth::{fast, otp, pkinit, spake},
    routing::s4u,
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
            super::PA_FX_FAST => fast_request(policy, &entry.value)?,
            fast::PA_ENCRYPTED_CHALLENGE => {
                let encrypted: rasn_kerberos::EncryptedData =
                    super::decode("PA-ENCRYPTED-CHALLENGE", &entry.value)?;
                policy.check_use(encrypted.etype, Use::ReplyKey)?;
            }
            // RFC 9588: a client sends only a support message or a response; the
            // response's factor is sealed in a key of the reply key's enctype.
            // RFC 4556: the client sends only a DER PA-PK-AS-REQ; its CMS signs and
            // its key agreement keys nothing under a Kerberos enctype.
            pkinit::PA_PK_AS_REQ => pkinit::outgoing(&entry.value).map_err(Error::Pkinit)?,
            spake::PA_SPAKE => {
                if let Some(etype) = spake::outgoing(&entry.value)? {
                    policy.check_use(etype, Use::ReplyKey)?;
                }
            }
            // MS-SFU and MS-KILE (todo 17): the S4U and RBCD elements a client sends, each its own
            // DER element; PA-S4U-X509-USER's checksum is keyed with a permitted enctype.
            super::PA_FOR_USER => drop(messages::PaForUser::decode_der(&entry.value)?),
            s4u::PA_S4U_X509_USER => s4u::PaS4uX509User::admit(policy, &entry.value)?,
            super::PA_PAC_OPTIONS => drop(messages::PaPacOptions::decode_der(&entry.value)?),
            // MS-KILE PA-PAC-REQUEST (todo 22): only its own element leaves the client.
            pac::PA_PAC_REQUEST => pac::Request::decode_der(&entry.value)
                .map(|_admitted| ())
                .map_err(|source| Error::Encode {
                    target: "PA-PAC-REQUEST",
                    message: source.to_string(),
                })?,
            // RFC 6560: the one OTP type a client sends; its nonce is sealed in the armor key. The
            // challenge (141) and the PIN-change message (144) are KDC halves and stay refused.
            otp::PA_OTP_REQUEST => {
                let request: PaOtpRequest = super::decode("PA-OTP-REQUEST", &entry.value)?;
                policy.check_use(request.enc_data.etype, Use::SessionKey)?;
            }
            // A client does not send enctype hints; the KDC and the peer do.
            11_i32 | 19_i32 | 23_i32 | 165_i32 => {
                return Err(Error::Encode {
                    target: "PA-DATA",
                    message: format!(
                        "outgoing PA type {} is a peer-only enctype hint",
                        entry.r#type
                    ),
                });
            }
            // PA-GET-FROM-TYPED-DATA (RFC 4120, deprecated by RFC 6113) only embeds an element of
            // the other encoding: it is no credential mechanism, and its contents would bypass admission.
            22_i32 => {
                return Err(Error::Encode {
                    target: "PA-DATA",
                    message: format!(
                        "outgoing PA type {} embeds data that cannot be policy-checked",
                        entry.r#type
                    ),
                });
            }
            // PA types this client neither builds nor can policy-check: credential mechanisms
            // (PKINIT, OTP, SPAKE and the like), the halves a KDC sends, FAST armor and
            // authentication sets, and obsolete or vendor ids. Reject rather than transmit
            // opaque nested encryption; the message claims no more than the refusal.
            5..=9
            | 12..=13
            | 17_i32
            | 30..=31
            | 41_i32
            | 134..=135
            | 141_i32
            | 143..=148
            | 152..=153 => {
                return Err(Error::Encode {
                    target: "PA-DATA",
                    message: format!("outgoing PA type {} is not supported", entry.r#type),
                });
            }
            _ => {}
        }
    }
    Ok(())
}

/// Check every encryption a `PA-FX-FAST` request carries (RFC 6113 section
/// 5.4.2): the armor AP-REQ's ticket and authenticator, the keyed request
/// checksum and the armor-key encryption of the inner request.
/// # Errors
/// Returns a decoding error, an unknown armor type, or the policy refusal.
fn fast_request(policy: &CryptoPolicy, value: &[u8]) -> Result<(), Error> {
    let fast::asn1::PaFxFastRequest::ArmoredData(armored) = super::decode("PA-FX-FAST", value)?;
    selection::reject_checksum(armored.req_checksum.r#type)?;
    policy.check_use(armored.enc_fast_req.etype, Use::SessionKey)?;
    if let Some(armor) = &armored.armor {
        (armor.armor_type == fast::ARMOR_AP_REQUEST).ok_or_else(|| Error::Encode {
            target: "PA-DATA",
            message: format!("FAST armor type {} is not supported", armor.armor_type),
        })?;
        let request = ap_req::decode(&armor.armor_value).map_err(super::ap_req_error)?;
        policy.check_use(request.ticket.enc_part.etype, Use::TicketKey)?;
        policy.check_use(request.authenticator.etype, Use::SessionKey)?;
    }
    Ok(())
}

/// Admit what an armor sends in place of the unarmored request: an AS-REQ
/// whose padata and enctype list pass the same checks.
/// # Errors
/// Returns a decoding error or the first policy refusal.
pub(super) fn armored(policy: &CryptoPolicy, message: &[u8]) -> Result<(), Error> {
    let rasn_kerberos::AsReq(request) = super::decode("AS-REQ", message)?;
    padata(policy, request.padata.as_deref().unwrap_or_default())?;
    for &etype in &request.req_body.etype {
        policy.check_use(etype, Use::RequestList)?;
    }
    Ok(())
}

/// Build the snapshot and check both request lists against its permitted list.
/// # Errors
/// Returns the snapshot errors, then named configuration errors for the request lists.
pub(super) fn configured_requests(defaults: &LibDefaults) -> Result<CryptoPolicy, ConfigError> {
    let policy = CryptoPolicy::from_libdefaults(defaults)?;
    defaults.validate_request_enctypes()?;
    Ok(policy)
}

/// Resolve public defaults without allowing invalid input to become unrestricted.
/// # Errors
/// Returns typed policy rejection for invalid configuration.
pub(super) fn configured(defaults: &LibDefaults) -> Result<CryptoPolicy, Error> {
    configured_requests(defaults).map_err(|error| {
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
        // A cross-realm proxy TGT carried to the target realm (MIT 1.22.2
        // `s4u_creds.c:1087-1108`) is sealed for the KDCs; the evidence it stands
        // for was bound when the first S4U2Proxy request of the delegation sent it.
        if !super::is_tgt_wire(&evidence.sname) {
            let keys = request
                .delegation_keytab
                .as_ref()
                .ok_or(Error::DelegationKeyRequired)?;
            super::validate_delegated_ticket(evidence, &request.client, keys)?;
        }
    }
    Ok(())
}
