//! `S4U2Self` and `S4U2Proxy` across realms, certificate `S4U2Self` and
//! resource-based constrained delegation (MS-SFU; MIT 1.22.2
//! `src/lib/krb5/krb/s4u_creds.c`).
//!
//! # Security
//!
//! The delegated identity is bound to the decrypted evidence: the user of the
//! final `S4U2Self` ticket is read from the ticket the service decrypts with
//! its own keytab and must equal the user the KDC named under the
//! `PA-S4U-X509-USER` checksum, never a caller-supplied name alone. Whether a
//! delegation is allowed stays the KDCs' decision.

use core::{fmt, str};

use super::{
    CertificateIdentity,
    s4u::{PA_S4U_X509_USER, PaS4uX509User, REQUEST_USAGE, UserId, verify_reply},
};
use crate::{
    client::{
        AsRepSession, KDC_OPTION_CANONICALIZE, KDC_OPTION_CNAME_IN_ADDL_TKT,
        PAC_OPTION_RESOURCE_BASED_CONSTRAINED_DELEGATION, TgsRepSession, build_tgs_req_for_realm,
        options::TgsReq,
        pa_for_user_padata, pa_pac_options_padata,
        principal::Principal,
        process_tgs_rep_with_referral,
        transport::{KdcProtocol, Tokio as Transport},
        validate_delegated_ticket,
    },
    config::Config,
    error::Client as Error,
    kdc_rep,
    keytab::Keytab,
    ticket,
};

/// The KDC option `forwardable` (RFC 4120 section 5.4.1, bit 1).
const FORWARDABLE: u32 = 0x4000_0000;
/// MIT's referral hop bound (`KRB5_REFERRAL_MAXHOPS`).
const MAX_HOPS: usize = 10;
/// The enterprise principal name type (`KRB5_NT_ENTERPRISE_PRINCIPAL`).
const NT_ENTERPRISE: i32 = 10;
/// The TGS principal name type.
const NT_SRV_INST: i32 = 2;

/// The user a service impersonates with `S4U2Self`.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum S4uIdentity {
    /// A user principal; its realm is where the request starts.
    Principal(Principal),
    /// A user certificate (MS-SFU `PA-S4U-X509-USER` with a subject
    /// certificate); the KDC names the user.
    Certificate(CertificateIdentity),
}

impl S4uIdentity {
    /// The user's realm.
    fn realm(&self) -> &str {
        match self {
            Self::Principal(user) => &user.realm,
            Self::Certificate(identity) => identity.realm(),
        }
    }

    /// The user's name, when the caller supplied one.
    fn principal(&self) -> Option<Principal> {
        match self {
            Self::Principal(user) => Some(user.clone()),
            Self::Certificate(identity) => (!identity.name().is_empty()).then(|| {
                Principal::new(
                    identity.realm(),
                    1,
                    identity.name().iter().map(String::as_str),
                )
            }),
        }
    }
}

/// Options of a delegation (`Tokio::delegate`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DelegationOptions {
    /// Ask for a forwardable `S4U2Self` evidence ticket.
    forwardable: bool,
    /// Send PA-PAC-OPTIONS with resource-based constrained delegation.
    resource_based: bool,
}

impl DelegationOptions {
    /// A forwardable evidence ticket and resource-based constrained delegation,
    /// as MIT requests it (`s4u_creds.c:1013`). Samba refuses `S4U2Proxy` for a
    /// non-forwardable evidence ticket even for resource-based constrained
    /// delegation (Samba 4.22.11 `mssfu.c:492-499`).
    #[must_use]
    #[inline]
    pub const fn new() -> Self {
        Self {
            forwardable: true,
            resource_based: true,
        }
    }

    /// Ask for a forwardable evidence ticket, or not.
    #[must_use]
    #[inline]
    pub const fn with_forwardable(mut self, forwardable: bool) -> Self {
        self.forwardable = forwardable;
        self
    }

    /// Send PA-PAC-OPTIONS resource-based constrained delegation, or not
    /// (classic constrained delegation only).
    #[must_use]
    #[inline]
    pub const fn with_resource_based(mut self, resource_based: bool) -> Self {
        self.resource_based = resource_based;
        self
    }

    /// Whether the evidence ticket is asked forwardable.
    pub(crate) const fn forwardable(self) -> bool {
        self.forwardable
    }

    /// Whether PA-PAC-OPTIONS resource-based constrained delegation is sent.
    pub(crate) const fn resource_based(self) -> bool {
        self.resource_based
    }
}

impl Default for DelegationOptions {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

/// A completed delegation: the `S4U2Self` evidence and the delegated ticket.
///
/// # Security
///
/// Both tickets carry session keys; `Debug` shows them through their own
/// redacted `Debug`.
#[derive(Clone)]
#[non_exhaustive]
pub struct Delegation {
    /// The `S4U2Self` evidence ticket, for the service itself.
    evidence: TgsRepSession,
    /// The `S4U2Proxy` ticket for the target, in the user's name.
    ticket: TgsRepSession,
}

impl Delegation {
    /// The `S4U2Self` evidence ticket.
    #[must_use]
    #[inline]
    pub const fn evidence(&self) -> &TgsRepSession {
        &self.evidence
    }

    /// The delegated ticket for the target.
    #[must_use]
    #[inline]
    pub const fn ticket(&self) -> &TgsRepSession {
        &self.ticket
    }

    /// Assemble a delegation from its evidence and delegated tickets.
    #[must_use]
    #[inline]
    pub const fn new(evidence: TgsRepSession, ticket: TgsRepSession) -> Self {
        Self { evidence, ticket }
    }
}

impl fmt::Debug for Delegation {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Delegation")
            .field("evidence", &self.evidence)
            .field("ticket", &self.ticket)
            .finish()
    }
}

/// What a delegation exchange runs with.
pub(crate) struct Session<'session> {
    /// The KDC transport.
    transport: &'session Transport,
    /// The profile: KDC locations, `[capaths]` and crypto policy.
    config: &'session Config,
    /// The KDC transport protocol.
    protocol: KdcProtocol,
    /// The service's keytab, which decrypts the evidence.
    keytab: Option<&'session Keytab>,
}

impl<'session> Session<'session> {
    /// A session over `transport` with `config`.
    pub(crate) const fn new(
        transport: &'session Transport,
        config: &'session Config,
        protocol: KdcProtocol,
    ) -> Self {
        Self {
            transport,
            config,
            protocol,
            keytab: None,
        }
    }

    /// The service's keytab, which decrypts the evidence.
    pub(crate) const fn with_keytab(mut self, keytab: Option<&'session Keytab>) -> Self {
        self.keytab = keytab;
        self
    }
}

/// `S4U2Self` for `identity` with the service TGT `service_tgt`, across realms.
///
/// MIT 1.22.2 `krb5_get_self_cred_from_kdc` (`s4u_creds.c:420-645`): a TGT to
/// the user's realm, then one request per realm from the user's realm back to
/// the service's, each carrying `PA-S4U-X509-USER` (and PA-FOR-USER in the
/// service's realm) and verifying the KDC's checksummed answer.
///
/// # Errors
///
/// Returns [`Error::DelegationKeyRequired`] without a keytab,
/// [`Error::S4uReplyModified`] when a KDC's identity answer does not match,
/// [`Error::DelegationPrincipalMismatch`] when the decrypted ticket names
/// another user, [`Error::ReferralLoop`], [`Error::MaxReferralDepth`] and the
/// errors of each TGS exchange.
///
/// # Cancel safety
///
/// cancel-safe: it changes no client state; dropping the future abandons the
/// exchange and closes its sockets, and a KDC that already answered keeps no
/// state the caller depends on, so the call can be repeated.
pub(crate) async fn s4u2self(
    session: &Session<'_>,
    service_tgt: &AsRepSession,
    identity: &S4uIdentity,
    request: (TgsReq, bool),
) -> Result<TgsRepSession, Error> {
    let keytab = session.keytab.ok_or(Error::DelegationKeyRequired)?;
    let (options, forwardable) = request;
    let service = service_tgt.client().clone();
    let mut tgt = if identity.realm() == service.realm {
        service_tgt.clone()
    } else {
        let to_user_realm = Principal::new(
            service.realm.as_str(),
            NT_SRV_INST,
            ["krbtgt", identity.realm()],
        );
        session
            .transport
            .get_service_ticket_with_referral_trace(
                session.config,
                session.protocol,
                service_tgt,
                to_user_realm,
                options.clone(),
            )
            .await?
            .into_parts()
            .0
    };
    let mut user = identity.principal();
    let mut seen: Vec<String> = Vec::new();
    for hop in 0..MAX_HOPS {
        let realm = tgt_realm(&tgt)?;
        let at_service = realm == service.realm;
        let server = if at_service {
            service.clone()
        } else {
            enterprise(&service, &realm)
        };
        let nonce = random_nonce()?;
        let user_id = UserId::new(
            nonce,
            user.as_ref().map(rasn_name).transpose()?,
            kerberos_string(identity.realm())?,
            match identity {
                S4uIdentity::Certificate(certificate) if hop == 0 => {
                    Some(certificate.certificate().to_vec())
                }
                S4uIdentity::Principal(_) | S4uIdentity::Certificate(_) => None,
            },
        );
        let mut padata = vec![rasn_kerberos::PaData {
            r#type: PA_S4U_X509_USER,
            value: PaS4uX509User::sign(user_id.clone(), tgt.session_key(), REQUEST_USAGE)?
                .encode_der()?
                .into(),
        }];
        if at_service && let Some(named) = &user {
            padata.push(pa_for_user_padata(named, tgt.session_key())?);
        }
        let bits = options.kdc_option_bits()
            | KDC_OPTION_CANONICALIZE
            | if forwardable { FORWARDABLE } else { 0 };
        let mut hop_options = options
            .clone()
            .with_kdc_option_bits(bits)
            .with_padata(padata)
            .with_delegation_keytab(keytab.clone());
        hop_options.set_nonce(nonce);
        let mut built = build_tgs_req_for_realm(&tgt, realm.clone(), server, hop_options)?;
        if let Some(named) = &user {
            built.set_client(named.clone());
        }
        let reply = session
            .transport
            .send_to_realm(session.config, session.protocol, &realm, built.der())
            .await?;
        match answered_user(&reply, &user_id, &tgt)? {
            None if user.is_none() => return Err(Error::S4uReplyModified),
            Some(named) if hop == 0 => {
                built.set_client(named.clone());
                user = Some(named);
            }
            Some(named) if user.as_ref() != Some(&named) => return Err(Error::S4uReplyModified),
            Some(_) | None => {}
        }
        let ticket = process_tgs_rep_with_referral(&built, &reply, tgt.session_key())?;
        if ticket.service().components == service.components {
            let expected = user.ok_or(Error::S4uReplyModified)?;
            bind_evidence(&ticket, &expected, keytab)?;
            return Ok(ticket);
        }
        let next = tgt_realm(&ticket)?;
        if next == realm || seen.contains(&next) {
            return Err(Error::ReferralLoop { realm: next });
        }
        seen.push(next);
        tgt = ticket;
    }
    Err(Error::MaxReferralDepth { max: MAX_HOPS })
}

/// `S4U2Proxy` for the user of `evidence` to `target`, across realms.
///
/// MIT 1.22.2 `get_proxy_cred_from_kdc` (`s4u_creds.c:984-1145`): the request
/// goes with the service TGT `service_tgt` to the service's realm; a KDC
/// that answers with a cross-realm proxy TGT is followed by the service's own
/// TGT to the target realm, the proxy TGT carried to the target realm, and a
/// last request there with that proxy TGT as evidence.
///
/// # Errors
///
/// Returns [`Error::DelegationKeyRequired`] without a keytab,
/// [`Error::DelegationPrincipalMismatch`] when the evidence does not name its
/// user, [`Error::ServicePrincipalMismatch`] for a reply for another service,
/// and the errors of each TGS exchange.
///
/// # Cancel safety
///
/// cancel-safe: it changes no client state; dropping the future abandons the
/// exchange and closes its sockets, and a KDC that already answered keeps no
/// state the caller depends on, so the call can be repeated.
pub(crate) async fn s4u2proxy(
    session: &Session<'_>,
    service_tgt: &AsRepSession,
    tickets: (&TgsRepSession, Principal),
    request: (TgsReq, bool),
) -> Result<TgsRepSession, Error> {
    let keytab = session.keytab.ok_or(Error::DelegationKeyRequired)?;
    let (evidence, target) = tickets;
    let (options, resource_based) = request;
    let service_realm = tgt_realm(service_tgt)?;
    let first = proxy_request(
        service_tgt,
        (evidence.ticket(), evidence.client()),
        (target.clone(), service_realm.clone()),
        (&options, resource_based),
    )?
    .with_delegation_keytab(keytab.clone());
    let reply = exchange(session, first).await?;
    if reply.service().components == target.components {
        return Ok(reply);
    }
    let proxy_realm = tgt_realm(&reply)?;
    let target_realm = target.realm.clone();
    let service_to_target = session
        .transport
        .get_service_ticket_with_referral_trace(
            session.config,
            session.protocol,
            service_tgt,
            Principal::new(
                service_realm.as_str(),
                NT_SRV_INST,
                ["krbtgt", target_realm.as_str()],
            ),
            options.clone(),
        )
        .await?
        .into_parts()
        .0;
    let proxy_tgt = if proxy_realm == target_realm {
        reply
    } else {
        session
            .transport
            .get_service_ticket_with_referral_trace(
                session.config,
                session.protocol,
                &reply,
                Principal::new(
                    proxy_realm.as_str(),
                    NT_SRV_INST,
                    ["krbtgt", target_realm.as_str()],
                ),
                options.clone(),
            )
            .await?
            .into_parts()
            .0
    };
    let last = proxy_request(
        &service_to_target,
        (proxy_tgt.ticket(), evidence.client()),
        (target.clone(), target_realm.clone()),
        (&options, resource_based),
    )?;
    let ticket = exchange(session, last).await?;
    if ticket.service().components != target.components {
        return Err(Error::ServicePrincipalMismatch {
            expected: target.name(),
            actual: ticket.service().name(),
        });
    }
    Ok(ticket)
}

/// The options of one `S4U2Proxy` request: the evidence as the additional
/// ticket, CNAME-IN-ADDL-TKT and CANONICALIZE, and PA-PAC-OPTIONS resource-based
/// constrained delegation when asked for.
///
/// # Errors
///
/// Returns the decode error of the evidence ticket and the encode error of the
/// PA-PAC-OPTIONS element.
fn proxy_request(
    tgt: &AsRepSession,
    evidence: (&[u8], &Principal),
    server: (Principal, String),
    options: (&TgsReq, bool),
) -> Result<ProxyRequest, Error> {
    let (template, resource_based) = options;
    let additional = ticket::decode(evidence.0).map_err(|error| Error::Decode {
        target: "Ticket",
        message: error.to_string(),
    })?;
    let mut request = template
        .clone()
        .with_kdc_option_bits(
            template.kdc_option_bits() | KDC_OPTION_CNAME_IN_ADDL_TKT | KDC_OPTION_CANONICALIZE,
        )
        .with_additional_tickets(vec![additional]);
    if resource_based {
        request = request.with_padata(vec![pa_pac_options_padata(
            PAC_OPTION_RESOURCE_BASED_CONSTRAINED_DELEGATION,
        )?]);
    }
    request.set_nonce(random_nonce()?);
    Ok(ProxyRequest {
        tgt: tgt.clone(),
        options: request,
        server: server.0,
        realm: server.1,
        client: evidence.1.clone(),
    })
}

/// One `S4U2Proxy` request before it is built.
struct ProxyRequest {
    /// The TGT the request is made with.
    tgt: AsRepSession,
    /// The request options.
    options: TgsReq,
    /// The requested target.
    server: Principal,
    /// The realm whose KDC receives the request.
    realm: String,
    /// The user the reply names.
    client: Principal,
}

impl ProxyRequest {
    /// Attach the keytab that decrypts the evidence.
    fn with_delegation_keytab(mut self, keytab: Keytab) -> Self {
        self.options = self.options.with_delegation_keytab(keytab);
        self
    }
}

/// Send one `S4U2Proxy` request and process its reply, a referral included.
///
/// # Errors
///
/// Returns the build, transport and reply-processing errors.
///
/// # Cancel safety
///
/// cancel-safe: it changes no client state; dropping the future abandons the
/// exchange and closes its sockets, and a KDC that already answered keeps no
/// state the caller depends on, so the call can be repeated.
async fn exchange(session: &Session<'_>, request: ProxyRequest) -> Result<TgsRepSession, Error> {
    let ProxyRequest {
        tgt,
        options,
        server,
        realm,
        client,
    } = request;
    let mut built = build_tgs_req_for_realm(&tgt, realm.clone(), server, options)?;
    built.set_client(client);
    let reply = session
        .transport
        .send_to_realm(session.config, session.protocol, &realm, built.der())
        .await?;
    process_tgs_rep_with_referral(&built, &reply, tgt.session_key())
}

/// The user a KDC answered with under the `PA-S4U-X509-USER` checksum, or
/// `None` when the reply carries no such element (MIT `s4u_creds.c:302-310`).
///
/// # Errors
///
/// Returns the errors of [`verify_reply`].
fn answered_user(
    reply: &[u8],
    request: &UserId,
    tgt: &AsRepSession,
) -> Result<Option<Principal>, Error> {
    let Ok(decoded) = kdc_rep::decode_tgs_rep(reply) else {
        return Ok(None);
    };
    let Some(element) = decoded
        .0
        .padata
        .as_ref()
        .and_then(|padata| padata.iter().find(|entry| entry.r#type == PA_S4U_X509_USER))
    else {
        return Ok(None);
    };
    let answered = verify_reply(request, &element.value, tgt.session_key())?;
    let realm = string(&answered.crealm)?;
    let name = answered.cname.ok_or(Error::S4uReplyModified)?;
    Ok(Some(Principal::new(
        realm,
        name.r#type,
        name.string
            .iter()
            .map(string)
            .collect::<Result<Vec<_>, _>>()?,
    )))
}

/// Bind the user of the final ticket to `expected` through its decrypted part.
///
/// # Errors
///
/// Returns the keytab and decryption errors and
/// [`Error::DelegationPrincipalMismatch`].
fn bind_evidence(
    ticket: &TgsRepSession,
    expected: &Principal,
    keytab: &Keytab,
) -> Result<(), Error> {
    let wire = ticket::decode(ticket.ticket()).map_err(|error| Error::Decode {
        target: "Ticket",
        message: error.to_string(),
    })?;
    validate_delegated_ticket(&wire, expected, keytab)
}

/// The realm of a TGT `krbtgt/<realm>@...`.
///
/// # Errors
///
/// Returns [`Error::InvalidReferralTicket`] for a ticket that is not a TGT.
fn tgt_realm(tgt: &AsRepSession) -> Result<String, Error> {
    match tgt.service().components.as_slice() {
        [first, realm] if first == "krbtgt" => Ok(realm.clone()),
        _ => Err(Error::InvalidReferralTicket {
            service: tgt.service().name(),
        }),
    }
}

/// The enterprise form of `service` for a foreign realm (MIT
/// `convert_to_enterprise`, `s4u_creds.c:399-418`).
fn enterprise(service: &Principal, realm: &str) -> Principal {
    Principal::new(
        realm,
        NT_ENTERPRISE,
        [format!(
            "{}@{}",
            service.components.join("/"),
            service.realm
        )],
    )
}

/// A random request nonce.
///
/// # Errors
///
/// Returns [`Error::Random`].
fn random_nonce() -> Result<u32, Error> {
    let mut bytes = [0_u8; 4];
    getrandom::fill(&mut bytes)?;
    Ok(u32::from_be_bytes(bytes) & 0x7fff_ffff)
}

/// A Kerberos string.
///
/// # Errors
///
/// Returns [`Error::InvalidKerberosString`].
fn kerberos_string(value: &str) -> Result<rasn_kerberos::KerberosString, Error> {
    rasn_kerberos::KerberosString::from_bytes(value.as_bytes())
        .map_err(|_invalid| Error::InvalidKerberosString(value.to_owned()))
}

/// The text of a Kerberos string.
///
/// # Errors
///
/// Returns [`Error::InvalidString`].
fn string(value: &rasn_kerberos::KerberosString) -> Result<String, Error> {
    Ok(str::from_utf8(value.as_bytes())?.to_owned())
}

/// The DER principal name of `principal`.
///
/// # Errors
///
/// Returns [`Error::InvalidKerberosString`].
fn rasn_name(principal: &Principal) -> Result<rasn_kerberos::PrincipalName, Error> {
    Ok(rasn_kerberos::PrincipalName {
        r#type: principal.name_type,
        string: principal
            .components
            .iter()
            .map(|component| kerberos_string(component))
            .collect::<Result<_, _>>()?,
    })
}
