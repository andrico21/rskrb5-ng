//! HTTP Negotiate (SPNEGO) scenarios with Samba-issued tickets and PACs.
//!
//! Service tickets issued by the Samba KDCs are accepted with the SPN keytabs
//! Samba exported. Unlike the MIT fixture's services, Samba always issues a
//! PAC with `KERB_VALIDATION_INFO`, so the acceptor verifies it with the
//! service key and the scenarios read the client's identity, domain and
//! claims from it.

use core::error::Error;
use std::time::SystemTime;

use rskrb5_ng::{
    client::{Tokio, principal::Principal, transport::KdcProtocol},
    error::{Service as ServiceError, Spnego as SpnegoError},
    keytab::Keytab,
    pac::ClaimValues,
    service::{ApRepOptions, Principal as ServicePrincipal, Validator},
    spnego::{self, oid::ObjectIdentifier},
};

use super::{
    AES256_SHA1, SAMBA_RES, SAMBA_USER, config, password, res_realm, runtime, service, shown,
    ticket_etype, transport, user, user_realm,
};
use crate::harness::{self, assert_negotiated_enctype, assert_negotiated_mechanism};

/// A password client of testuser1, configured for both domains.
fn client() -> Result<Tokio, Box<dyn Error>> {
    Ok(Tokio::with_password(
        config("")?,
        KdcProtocol::Tcp,
        user("INTEROP_SAMBA_USER_USER")?,
        password("INTEROP_SAMBA_USER_USER_PASSWORD")?,
    )
    .with_transport(transport()))
}

/// A Negotiate header for `HTTP/user2.user.rskrb5` is accepted with the SPN
/// keytab Samba exported: the krb5 mechanism is negotiated, the PAC names
/// testuser1 of the USER domain, a replay is refused, and the AP-REP answer
/// verifies on the client.
#[test]
fn negotiate_header_with_samba_pac_is_accepted_with_the_http_keytab() -> Result<(), Box<dyn Error>>
{
    if !harness::require(
        "negotiate_header_with_samba_pac_is_accepted_with_the_http_keytab",
        &[SAMBA_USER],
    )? {
        return Ok(());
    }
    runtime()?
        .block_on(async {
            let http = service(user_realm()?, "INTEROP_SAMBA_USER_HTTP_SERVICE")?;
            let ticket = client()?.get_service_ticket(http).await?;
            assert_negotiated_enctype(
                "HTTP service ticket",
                AES256_SHA1,
                ticket_etype(ticket.ticket().as_slice())?,
            )?;
            let context = spnego::init_sec_context(&ticket, spnego::InitiatorContextOptions::new())
                .map_err(|error| format!("the initiator could not build the token: {error}"))?;
            let keytab = Keytab::load(harness::var("INTEROP_SAMBA_USER_HTTP_KEYTAB")?)?;
            let mut validator = Validator::new(&keytab).with_now(SystemTime::now());
            let accepted = spnego::accept_sec_context_header(&mut validator, context.header_ref())
                .map_err(|error| {
                    format!("the acceptor refused the Samba-issued ticket: {error}")
                })?;
            let krb5 = ObjectIdentifier::krb5();
            assert_negotiated_mechanism(krb5.arcs(), accepted.selected_mechanism().arcs())?;
            assert_negotiated_mechanism(krb5.arcs(), accepted.token_mechanism().arcs())?;
            let user_name = harness::var("INTEROP_SAMBA_USER_USER")?;
            assert_eq!(
                accepted.ap_req().client().clone(),
                ServicePrincipal::new(user_realm()?, 1, vec![user_name.clone()]),
                "the acceptor sees testuser1"
            );
            let pac = accepted
                .ap_req()
                .pac()
                .ok_or("a Samba service ticket has a PAC")?;
            let credentials = pac.ad_credentials().ok_or("the PAC has validation info")?;
            assert_eq!(credentials.effective_name, user_name);
            assert_eq!(
                credentials.logon_domain_name,
                harness::var("INTEROP_SAMBA_USER_NETBIOS")?
            );
            let replay = spnego::accept_sec_context_header(&mut validator, context.header_ref())
                .err()
                .ok_or("a replayed header must be rejected")?;
            assert!(
                matches!(replay, SpnegoError::Service(ServiceError::Replay)),
                "expected a replay rejection, got {replay}"
            );
            let answer = accepted.ap_rep_response_header(&ApRepOptions::default())?;
            let verified = context
                .verify_ap_rep_response_header(&answer)
                .map_err(|error| format!("the initiator refused the AP-REP: {error}"))?;
            assert_eq!(
                verified.ctime(),
                context.authenticator_ctime(),
                "the AP-REP answers this authenticator"
            );
            Ok::<_, Box<dyn Error>>(())
        })
        .map_err(shown)
}

/// In the resource domain (functional level 2016), resuser's Negotiate header
/// for `HTTP/host.res.rskrb5` is accepted with the RES SPN keytab, and the
/// PAC carries resuser's `Department` claim (`PAC_CLIENT_CLAIMS_INFO`).
#[test]
fn negotiate_pac_carries_the_resource_domain_claim() -> Result<(), Box<dyn Error>> {
    if !harness::require(
        "negotiate_pac_carries_the_resource_domain_claim",
        &[SAMBA_RES],
    )? {
        return Ok(());
    }
    runtime()?
        .block_on(async {
            let realm = res_realm()?;
            let name = harness::var("INTEROP_SAMBA_RES_USER")?;
            let mut client = Tokio::with_password(
                config("")?,
                KdcProtocol::Tcp,
                Principal::user(realm.as_str(), name.as_str()),
                password("INTEROP_SAMBA_RES_USER_PASSWORD")?,
            )
            .with_transport(transport());
            let http = service(realm.clone(), "INTEROP_SAMBA_RES_HTTP_SERVICE")?;
            let ticket = client.get_service_ticket(http).await?;
            assert_negotiated_enctype(
                "resource-domain HTTP service ticket",
                AES256_SHA1,
                ticket_etype(ticket.ticket().as_slice())?,
            )?;
            let context = spnego::init_sec_context(&ticket, spnego::InitiatorContextOptions::new())
                .map_err(|error| format!("the initiator could not build the token: {error}"))?;
            let keytab = Keytab::load(harness::var("INTEROP_SAMBA_RES_HTTP_KEYTAB")?)?;
            let mut validator = Validator::new(&keytab).with_now(SystemTime::now());
            let accepted = spnego::accept_sec_context_header(&mut validator, context.header_ref())
                .map_err(|error| {
                    format!("the acceptor refused the Samba-issued ticket: {error}")
                })?;
            assert_negotiated_mechanism(
                ObjectIdentifier::krb5().arcs(),
                accepted.selected_mechanism().arcs(),
            )?;
            let pac = accepted
                .ap_req()
                .pac()
                .ok_or("a Samba service ticket has a PAC")?;
            let credentials = pac.ad_credentials().ok_or("the PAC has validation info")?;
            assert_eq!(credentials.effective_name, name);
            assert_eq!(
                credentials.logon_domain_name,
                harness::var("INTEROP_SAMBA_RES_NETBIOS")?
            );
            let claim_type = harness::var("INTEROP_SAMBA_RES_CLAIM_TYPE")?;
            let claim_value = harness::var("INTEROP_SAMBA_RES_CLAIM_VALUE")?;
            let claims = pac
                .client_claims_info()
                .ok_or("the PAC carries client claims")?;
            let department = claims
                .claims_set
                .claims_arrays
                .iter()
                .flat_map(|array| array.claim_entries.iter())
                .find(|entry| entry.id.contains(claim_type.as_str()))
                .ok_or("the client claims include the Department claim")?;
            assert_eq!(department.values, ClaimValues::String(vec![claim_value]));
            Ok::<_, Box<dyn Error>>(())
        })
        .map_err(shown)
}
