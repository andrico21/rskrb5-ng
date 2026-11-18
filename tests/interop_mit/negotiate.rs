//! HTTP Negotiate (SPNEGO) scenarios.
//!
//! Service tickets issued by the MIT KDC are accepted with the keytabs MIT exported.

use core::error::Error;
use std::time::SystemTime;

use rskrb5_ng::{
    client::{Tokio, transport::KdcProtocol},
    error::{Service as ServiceError, Spnego as SpnegoError},
    keytab::Keytab,
    service::{ApRepOptions, Principal as ServicePrincipal, Validator},
    spnego::{self, oid::ObjectIdentifier},
};

use super::{
    AES256_SHA2, MIT_KDC, config, password, realm, runtime, service, ticket_etype, transport, user,
};
use crate::harness::{self, assert_negotiated_enctype, assert_negotiated_mechanism};

/// A client of the test user, configured for the fixture.
fn client() -> Result<Tokio, Box<dyn Error>> {
    Ok(Tokio::with_password(
        config("")?,
        KdcProtocol::Auto,
        user("INTEROP_MIT_USER")?,
        password("INTEROP_MIT_USER_PASSWORD")?,
    )
    .with_transport(transport()))
}

/// A Negotiate header for `HTTP/http.test.rskrb5` is accepted with the MIT
/// HTTP keytab, the krb5 mechanism (not the Microsoft legacy OID) is
/// negotiated, and the AP-REP answer verifies on the client.
#[test]
fn negotiate_header_is_accepted_with_the_mit_http_keytab() -> Result<(), Box<dyn Error>> {
    if !harness::require(
        "negotiate_header_is_accepted_with_the_mit_http_keytab",
        &[MIT_KDC],
    )? {
        return Ok(());
    }
    runtime()?.block_on(async {
        let http = service("INTEROP_MIT_HTTP_SERVICE")?;
        let mut client = client()?;
        let ticket = client.get_service_ticket(http.clone()).await?;
        assert_negotiated_enctype(
            "HTTP service ticket",
            AES256_SHA2,
            ticket_etype(ticket.ticket().as_slice())?,
        )?;
        let context = spnego::init_sec_context(&ticket, spnego::InitiatorContextOptions::new())?;
        let keytab = Keytab::load(harness::var("INTEROP_MIT_HTTP_KEYTAB")?)?;
        let mut validator = Validator::new(&keytab).with_now(SystemTime::now());
        let accepted = spnego::accept_sec_context_header(&mut validator, context.header_ref())?;
        let krb5 = ObjectIdentifier::krb5();
        assert_negotiated_mechanism(krb5.arcs(), accepted.selected_mechanism().arcs())?;
        assert_negotiated_mechanism(krb5.arcs(), accepted.token_mechanism().arcs())?;
        assert_eq!(
            accepted.ap_req().client().clone(),
            ServicePrincipal::new(realm()?, 1, vec![harness::var("INTEROP_MIT_USER")?]),
            "the acceptor sees the test user"
        );
        let answer = accepted.ap_rep_response_header(&ApRepOptions::default())?;
        let verified = context.verify_ap_rep_response_header(&answer)?;
        assert_eq!(
            verified.ctime(),
            context.authenticator_ctime(),
            "the AP-REP answers this authenticator"
        );
        Ok::<_, Box<dyn Error>>(())
    })
}

/// The acceptor refuses a replay of an accepted Negotiate header.
#[test]
fn negotiate_acceptor_rejects_a_replayed_header() -> Result<(), Box<dyn Error>> {
    if !harness::require("negotiate_acceptor_rejects_a_replayed_header", &[MIT_KDC])? {
        return Ok(());
    }
    runtime()?.block_on(async {
        let mut client = client()?;
        let ticket = client
            .get_service_ticket(service("INTEROP_MIT_HTTP_SERVICE")?)
            .await?;
        let context = spnego::init_sec_context(&ticket, spnego::InitiatorContextOptions::new())?;
        let keytab = Keytab::load(harness::var("INTEROP_MIT_HTTP_KEYTAB")?)?;
        let mut validator = Validator::new(&keytab).with_now(SystemTime::now());
        let accepted = spnego::accept_sec_context_header(&mut validator, context.header_ref())?;
        assert_negotiated_mechanism(
            ObjectIdentifier::krb5().arcs(),
            accepted.selected_mechanism().arcs(),
        )?;
        let replay = spnego::accept_sec_context_header(&mut validator, context.header_ref())
            .err()
            .ok_or("a replayed header must be rejected")?;
        assert!(
            matches!(replay, SpnegoError::Service(ServiceError::Replay)),
            "expected a replay rejection, got {replay}"
        );
        Ok::<_, Box<dyn Error>>(())
    })
}

/// A ticket for `host/mit-kdc.test.rskrb5` is accepted with the host keytab
/// MIT exported (the keytab later `verify_init_creds` work uses).
#[test]
fn host_keytab_accepts_a_mit_issued_ticket() -> Result<(), Box<dyn Error>> {
    if !harness::require("host_keytab_accepts_a_mit_issued_ticket", &[MIT_KDC])? {
        return Ok(());
    }
    runtime()?.block_on(async {
        let host = service("INTEROP_MIT_HOST_SERVICE")?;
        let mut client = client()?;
        let ticket = client.get_service_ticket(host.clone()).await?;
        assert_negotiated_enctype(
            "host service ticket",
            AES256_SHA2,
            ticket_etype(ticket.ticket().as_slice())?,
        )?;
        let context = spnego::init_sec_context(&ticket, spnego::InitiatorContextOptions::new())?;
        let keytab = Keytab::load(harness::var("INTEROP_MIT_HOST_KEYTAB")?)?;
        let mut validator = Validator::new(&keytab).with_now(SystemTime::now());
        let accepted = spnego::accept_sec_context_header(&mut validator, context.header_ref())?;
        assert_negotiated_mechanism(
            ObjectIdentifier::krb5().arcs(),
            accepted.selected_mechanism().arcs(),
        )?;
        assert_eq!(
            accepted.ap_req().service().name(),
            harness::var("INTEROP_MIT_HOST_SERVICE")?,
            "the acceptor sees the host service"
        );
        Ok::<_, Box<dyn Error>>(())
    })
}
