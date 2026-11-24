//! Impersonation and proxy credentials.
//!
//! `gss_acquire_cred_impersonate_name` and the proxy credentials of MIT 1.22.2
//! `s4u_gss_glue.c:33-303`: an impersonator credential obtains an `S4U2Self`
//! evidence ticket for a user (`kg_impersonate_name`), and a proxy credential
//! for that user gets its service tickets by `S4U2Proxy` with the evidence; an
//! acceptor whose credential can also initiate composes a proxy credential
//! from the ticket it accepted (`kg_compose_deleg_cred`,
//! `accept_sec_context.c:943-952`). The exchanges are todo 17's
//! (`client::Tokio::s4u2self_identity`, `client::Tokio::s4u2proxy`).

use zeroize::Zeroizing;

#[cfg(feature = "tokio")]
use super::Config;
use super::{CCache, Credential, CredentialUsage, Error, Name, Principal, TgsRepSession, cred};
#[cfg(feature = "tokio")]
use crate::client::{Tokio, transport::KdcProtocol};
use crate::{ap_req, service::ValidatedApReq, ticket};

/// A proxy credential of `client`, holding `evidence`, with `impersonator`.
pub(super) fn proxy(evidence: &TgsRepSession, impersonator: &Credential) -> Credential {
    let mut cache = CCache::new(cred::cache_principal(evidence.client()));
    drop(cache.upsert_credential(cred::entry_of(evidence)));
    let mut credential = cred::empty(CredentialUsage::Initiate);
    credential.name = Some(Name::from_principal(evidence.client()));
    credential.cache = Some(cache);
    credential.impersonator = Some(Box::new(cred::duplicate(impersonator)));
    credential
}

/// The evidence ticket of an accepted AP-REQ, for a proxy credential
/// (`kg_compose_deleg_cred`).
///
/// # Errors
///
/// Returns the AP-REQ and ticket encoding errors.
pub(super) fn evidence(
    request: &[u8],
    client: &Principal,
    validated: &ValidatedApReq,
) -> Result<TgsRepSession, Error> {
    let message = ap_req::decode(request)?;
    let ticket = ticket::encode(&message.ticket).map_err(Error::Ticket)?;
    let service = Principal::new(
        validated.service().realm.clone(),
        validated.service().name_type,
        validated.service().components.clone(),
    );
    Ok(TgsRepSession::new(
        client.clone(),
        service,
        validated.session_key().clone(),
        Zeroizing::new(ticket),
        [0; 4],
        validated.ticket_start(),
        validated.ticket_end(),
    ))
}

/// The impersonator's client, with the keytab it needs for `S4U2Self`.
///
/// # Errors
///
/// Returns [`Error::WrongCredentialUsage`] for an acceptor-only credential and
/// [`Error::NoCredential`] without a name or a keytab.
#[cfg(feature = "tokio")]
fn impersonator_client(impersonator: &Credential, config: &Config) -> Result<Tokio, Error> {
    if impersonator.usage == CredentialUsage::Accept {
        return Err(Error::WrongCredentialUsage("initiate"));
    }
    let principal = impersonator
        .name
        .as_ref()
        .map(|name| name.principal().clone())
        .ok_or(Error::NoCredential("the impersonator has no name"))?;
    let keytab = impersonator
        .client_keytab
        .as_ref()
        .or(impersonator.keytab.as_ref())
        .ok_or(Error::NoCredential(
            "impersonation needs the impersonator's keytab",
        ))?;
    Ok(Tokio::with_keytab(
        config.clone(),
        KdcProtocol::Auto,
        principal,
        keytab.clone(),
    ))
}

/// `gss_acquire_cred_impersonate_name`.
///
/// # Errors
///
/// Returns the errors of [`super::Credential::acquire_impersonate_name`].
///
/// # Cancel safety
///
/// cancel-safe: the credential is built only after the exchange completes.
#[cfg(feature = "tokio")]
pub(super) async fn acquire(
    impersonator: &Credential,
    user: &Name,
    config: &Config,
) -> Result<Credential, Error> {
    use crate::routing::{
        CertificateIdentity,
        impersonation::{DelegationOptions, S4uIdentity},
    };

    let mut client = impersonator_client(impersonator, config)?;
    let identity = match user.certificate() {
        Some(certificate) => {
            let realm = impersonator
                .name
                .as_ref()
                .map_or_else(String::new, |name| name.principal().realm.clone());
            S4uIdentity::Certificate(
                CertificateIdentity::new(certificate.to_vec(), realm).map_err(|_invalid| {
                    Error::BadName("a certificate an S4U2Self request cannot carry")
                })?,
            )
        }
        None => S4uIdentity::Principal(Principal::new(
            user.principal().realm.clone(),
            user.principal().name_type,
            user.principal().components.clone(),
        )),
    };
    let evidence = client
        .s4u2self_identity(identity, DelegationOptions::new())
        .await
        .map_err(Error::Client)?;
    Ok(proxy(&evidence, impersonator))
}

/// The `S4U2Proxy` ticket of a proxy credential for `service`.
///
/// # Errors
///
/// Returns [`Error::NoCredential`] without the evidence ticket, and the
/// errors of the impersonator's client and of the `S4U2Proxy` exchange.
///
/// # Cancel safety
///
/// cancel-safe: the ticket is returned, nothing is kept.
#[cfg(feature = "tokio")]
pub(super) async fn proxy_ticket(
    credential: &Credential,
    service: Principal,
    config: &Config,
) -> Result<TgsRepSession, Error> {
    let impersonator = credential
        .impersonator
        .as_deref()
        .ok_or(Error::NoCredential("not a proxy credential"))?;
    let own = impersonator
        .name
        .as_ref()
        .map_or_else(Vec::new, |name| name.principal().components.clone());
    let evidence = credential
        .cache
        .as_ref()
        .and_then(|cache| {
            cache
                .credentials()
                .iter()
                .find(|entry| entry.server().components == own)
        })
        .map(cred::session_of)
        .ok_or(Error::NoCredential(
            "the proxy credential holds no evidence",
        ))?;
    let mut client = impersonator_client(impersonator, config)?;
    client
        .s4u2proxy(&evidence, service)
        .await
        .map_err(Error::Client)
}
