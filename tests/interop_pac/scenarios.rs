//! The MIT PAC scenarios: a default-PAC service ticket against the acceptor.

use core::{error::Error, time::Duration};
use std::{
    io,
    time::{SystemTime, UNIX_EPOCH},
};

use rskrb5_ng::{
    client::{
        TgsRepSession, Tokio, build_ap_req_with_confounder,
        options::ApReq,
        principal::Principal,
        transport::{KdcProtocol, Tokio as TokioKdcTransport},
    },
    config::Config,
    crypto::KerberosEtype,
    keytab::Keytab,
    service::{ValidatedApReq, Validator},
};
use tokio::runtime::{Builder, Runtime};

use crate::harness::{self, Fixture};

/// The TEST.RSKRB5 KDC (fixture `mit-kdc`).
const MIT_KDC: Fixture = Fixture::new("mit-kdc", "INTEROP_MIT_KDC");

/// The current-thread Tokio runtime the scenarios run on.
fn runtime() -> io::Result<Runtime> {
    Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
}

/// The fixture profile. The realm offers SPAKE, which the client answers before the encrypted
/// timestamp: an empty `spake_preauth_groups` pins the login to the encrypted timestamp, so these
/// scenarios prove the PAC and no preauthentication mechanism by accident.
fn config() -> Result<Config, Box<dyn Error>> {
    Ok(Config::parse(&format!(
        "[libdefaults]\n default_realm = {}\n dns_lookup_kdc = false\n dns_lookup_realm = false\n \
         spake_preauth_groups =\n[realms]\n {} = {{\n  kdc = {}\n }}\n",
        harness::var("INTEROP_MIT_REALM")?,
        harness::var("INTEROP_MIT_REALM")?,
        harness::var("INTEROP_MIT_KDC")?,
    ))?)
}

/// A client of the test user.
fn client() -> Result<Tokio, Box<dyn Error>> {
    Ok(Tokio::with_password(
        config()?,
        KdcProtocol::Auto,
        Principal::user(
            harness::var("INTEROP_MIT_REALM")?,
            harness::var("INTEROP_MIT_USER")?,
        ),
        harness::var("INTEROP_MIT_USER_PASSWORD")?.into_bytes(),
    )
    .with_transport(TokioKdcTransport::new().with_timeout(Duration::from_secs(10))))
}

/// The default-PAC service of the fixture.
fn pac_service() -> Result<Principal, Box<dyn Error>> {
    let name = harness::var("INTEROP_MIT_PAC_SERVICE")?;
    Ok(Principal::new(
        harness::var("INTEROP_MIT_REALM")?,
        2,
        name.split('/'),
    ))
}

/// An AP-REQ for `ticket`, built with a fixed confounder at the current time.
fn ap_req(ticket: &TgsRepSession) -> Result<Vec<u8>, Box<dyn Error>> {
    let etype = KerberosEtype::from_etype_id(ticket.session_key().etype())
        .ok_or("ticket session key etype is supported")?;
    let confounder = vec![0x42_u8; etype.confounder_len()];
    let elapsed = SystemTime::now().duration_since(UNIX_EPOCH)?;
    let seconds = UNIX_EPOCH
        .checked_add(Duration::from_secs(elapsed.as_secs()))
        .ok_or("time overflow")?;
    let built = build_ap_req_with_confounder(
        ticket,
        ApReq::new(),
        seconds,
        elapsed.subsec_micros(),
        &confounder,
    )?;
    Ok(built.der().to_vec())
}

/// Replaces `error` by its `Display` text.
fn shown(error: Box<dyn Error>) -> Box<dyn Error> {
    let text = error.to_string();
    drop(error);
    text.into()
}

/// Fetch a service ticket for the default-PAC service and validate it as an AP-REQ.
async fn accepted_ticket() -> Result<(ValidatedApReq, Vec<u8>), Box<dyn Error>> {
    let mut client = client()?;
    let ticket = client.get_service_ticket(pac_service()?).await?;
    let request = ap_req(&ticket)?;
    let keytab = Keytab::load(harness::var("INTEROP_MIT_PAC_KEYTAB")?)?;
    let mut validator = Validator::new(&keytab).with_now(SystemTime::now());
    let accepted = validator
        .validate_ap_req(&request)
        .map_err(|error| format!("the acceptor refused the MIT-issued ticket: {error}"))?;
    Ok((accepted, request))
}

/// FU-SVC-P01: the PAC MIT 1.22.2 builds for a default service (client info and checksums, no
/// `KERB_VALIDATION_INFO`) is accepted with the service keytab and names the client.
#[test]
fn a_default_mit_service_ticket_with_a_pac_is_accepted() -> Result<(), Box<dyn Error>> {
    if !harness::require(
        "a_default_mit_service_ticket_with_a_pac_is_accepted",
        &[MIT_KDC],
    )? {
        return Ok(());
    }
    runtime()?
        .block_on(async {
            let (accepted, _request) = accepted_ticket().await?;
            let pac = accepted
                .pac()
                .ok_or("a default MIT service ticket carries a PAC")?;
            assert_eq!(
                pac.client_info().ok_or("the PAC has client info")?.name,
                harness::var("INTEROP_MIT_USER")?,
                "the PAC names the ticket's client"
            );
            assert!(
                pac.kerb_validation_info().is_none(),
                "MIT builds no KERB_VALIDATION_INFO"
            );
            Ok::<_, Box<dyn Error>>(())
        })
        .map_err(shown)
}
