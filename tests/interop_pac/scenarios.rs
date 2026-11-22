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
    error::{Pac as PacError, Service as ServiceError},
    keytab::{EncryptionKey, Keytab},
    pac::VerificationPolicy,
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
fn accepted_ticket() -> Result<(ValidatedApReq, Vec<u8>), Box<dyn Error>> {
    runtime()?
        .block_on(async {
            let mut client = client()?;
            let ticket = client.get_service_ticket(pac_service()?).await?;
            let request = ap_req(&ticket)?;
            let keytab = Keytab::load(harness::var("INTEROP_MIT_PAC_KEYTAB")?)?;
            let mut validator = Validator::new(&keytab).with_now(SystemTime::now());
            let accepted = validator
                .validate_ap_req(&request)
                .map_err(|error| format!("the acceptor refused the MIT-issued ticket: {error}"))?;
            Ok::<_, Box<dyn Error>>((accepted, request))
        })
        .map_err(shown)
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
    let (accepted, _request) = accepted_ticket()?;
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
    // Without the KDC key only the server signature and the client are verified.
    let checks = pac.checks();
    assert!(checks.server() && checks.client() && !checks.kdc());
    Ok(())
}

/// The KDC key of the realm that signed the PAC, from the exported `krbtgt` keytab: the key of the
/// enctype whose mandatory checksum type `checksum_type` is.
fn kdc_key(checksum_type: u32) -> Result<EncryptionKey, Box<dyn Error>> {
    let etype = match checksum_type {
        15 => 17_i32,
        16 => 18_i32,
        19 => 19_i32,
        20 => 20_i32,
        other => return Err(format!("unexpected PAC checksum type {other}").into()),
    };
    let realm = harness::var("INTEROP_MIT_REALM")?;
    let keytab = Keytab::load(harness::var("INTEROP_MIT_PAC_KDC_KEYTAB")?)?;
    let (key, _kvno) = keytab.find_key(&["krbtgt", realm.as_str()], &realm, 0, etype)?;
    Ok(key.clone())
}

/// The checksum type of the KDC signature of the accepted ticket's PAC.
fn kdc_checksum_type(accepted: &ValidatedApReq) -> Result<u32, Box<dyn Error>> {
    Ok(accepted
        .pac()
        .ok_or("the ticket carries a PAC")?
        .pac()
        .kdc_checksum()
        .ok_or("the PAC has a KDC signature")?
        .signature_type)
}

/// MIT-pac-2, MIT-pac-3: with the exported `krbtgt` key the acceptor verifies all four signatures
/// of the PAC MIT 1.22.2 builds (server, KDC, ticket and the KB5020805 full checksum) and its
/// client info: the ticket signature binds the PAC to the re-encoded ticket.
#[test]
fn the_four_signatures_of_the_mit_pac_verify_with_the_krbtgt_key() -> Result<(), Box<dyn Error>> {
    if !harness::require(
        "the_four_signatures_of_the_mit_pac_verify_with_the_krbtgt_key",
        &[MIT_KDC],
    )? {
        return Ok(());
    }
    let (first, request) = accepted_ticket()?;
    let key = kdc_key(kdc_checksum_type(&first)?)?;
    let keytab = Keytab::load(harness::var("INTEROP_MIT_PAC_KEYTAB")?)?;
    let accepted = Validator::new(&keytab)
        .with_now(SystemTime::now())
        .with_pac_kdc_key(key)
        .with_pac_policy(VerificationPolicy::kdc())
        .validate_ap_req(&request)
        .map_err(|error| format!("the MIT PAC did not verify with the krbtgt key: {error}"))?;
    let checks = accepted.pac().ok_or("a PAC")?.checks();
    assert!(
        checks.server() && checks.kdc() && checks.ticket() && checks.full() && checks.client(),
        "every check passed: {checks:?}"
    );
    Ok(())
}

/// A PAC checked under the wrong KDC key is refused: the service's own key (same enctype) stands in
/// for a forger's guess.
#[test]
fn a_pac_checked_under_the_wrong_kdc_key_is_refused() -> Result<(), Box<dyn Error>> {
    if !harness::require(
        "a_pac_checked_under_the_wrong_kdc_key_is_refused",
        &[MIT_KDC],
    )? {
        return Ok(());
    }
    let (first, request) = accepted_ticket()?;
    let keytab = Keytab::load(harness::var("INTEROP_MIT_PAC_KEYTAB")?)?;
    let realm = harness::var("INTEROP_MIT_REALM")?;
    let name = harness::var("INTEROP_MIT_PAC_SERVICE")?;
    let components: Vec<&str> = name.split('/').collect();
    let (service_key, _kvno) = keytab.find_key(
        &components,
        &realm,
        0,
        match kdc_checksum_type(&first)? {
            16 => 18_i32,
            _ => 20_i32,
        },
    )?;
    let refused = Validator::new(&keytab)
        .with_now(SystemTime::now())
        .with_pac_kdc_key(service_key.clone())
        .with_pac_policy(VerificationPolicy::kdc())
        .validate_ap_req(&request);
    assert!(
        matches!(
            refused,
            Err(ServiceError::Pac(PacError::KdcChecksumVerificationFailed))
        ),
        "the wrong KDC key must fail the KDC signature"
    );
    Ok(())
}
