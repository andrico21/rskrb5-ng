//! Regressions of the PAC acceptor found by live interoperability (FU-IOP-P14, FU-SVC-P01).
//!
//! MIT krb5 1.22.2 puts a PAC without `KERB_VALIDATION_INFO` into every ticket for a service that
//! is not `+no_auth_data_required`; Samba 4.22 sends a zero-length client-claims buffer for an
//! account without claims and for every ticket issued across a trust.

use core::error::Error;

use rskrb5_ng::{pac::Pac, service::Validator};

use super::{pac_ticket, pac_vectors, vector};

/// A zero-length `PAC_CLIENT_CLAIMS_INFO` buffer means the account has no claims (FU-IOP-P14).
#[test]
fn a_zero_length_client_claims_buffer_is_no_claims() -> Result<(), Box<dyn Error>> {
    // Given a Samba-shaped PAC whose claims buffer (type 13) is empty.
    let bytes = vector(pac_vectors::EMPTY_CLAIMS_PAC_AES256)?;
    // When it is parsed and processed.
    let pac = Pac::parse_and_process(&bytes)?;
    // Then it parses, the claims are absent and the client info is intact.
    assert!(pac.client_claims_info().is_none(), "empty claims buffer");
    assert_eq!(pac.client_info().ok_or("client info")?.name, "pacuser");
    Ok(())
}

/// A default MIT PAC has no `KERB_VALIDATION_INFO`; its server signature still verifies
/// (FU-SVC-P01).
#[test]
fn a_mit_pac_without_validation_info_verifies() -> Result<(), Box<dyn Error>> {
    // Given the MIT-shaped service PAC and its service key.
    let pac = Pac::parse_and_process(&vector(pac_vectors::SERVICE_PAC_AES256)?)?;
    let key = pac_ticket::key(&vector(pac_vectors::SERVER_KEY_AES256)?);
    // When the service verifies it.
    // Then it verifies although it carries no validation info.
    assert!(pac.kerb_validation_info().is_none(), "no validation info");
    pac.verify(&key)?;
    Ok(())
}

/// The acceptor accepts a ticket whose PAC is the one MIT builds (FU-SVC-P01).
#[test]
fn the_acceptor_accepts_a_mit_pac_without_validation_info() -> Result<(), Box<dyn Error>> {
    // Given a ticket carrying the MIT-shaped PAC, sealed under the service key.
    let service_key = vector(pac_vectors::SERVER_KEY_AES256)?;
    let pac = vector(pac_vectors::SERVICE_PAC_AES256)?;
    let ticket = pac_ticket::enc_ticket(
        "pacuser",
        pac_ticket::AUTH_TIME,
        Some(pac_ticket::authorization_data(pac)?),
    )?;
    let request = pac_ticket::ap_req(&ticket, &service_key)?;
    let keytab = pac_ticket::service_keytab(&service_key)?;
    // When the acceptor validates the AP-REQ.
    let accepted = Validator::new(&keytab)
        .with_now(pac_ticket::now()?)
        .validate_ap_req(&request)?;
    // Then the ticket is accepted and its PAC names the client.
    let info = accepted
        .pac()
        .ok_or("the PAC is exposed")?
        .client_info()
        .ok_or("client info")?;
    assert_eq!(info.name, "pacuser");
    Ok(())
}

/// The acceptor accepts a Samba PAC with a zero-length claims buffer (FU-IOP-P14).
#[test]
fn the_acceptor_accepts_a_pac_with_an_empty_claims_buffer() -> Result<(), Box<dyn Error>> {
    // Given a ticket carrying the Samba-shaped PAC with an empty claims buffer.
    let service_key = vector(pac_vectors::SERVER_KEY_AES256)?;
    let pac = vector(pac_vectors::EMPTY_CLAIMS_PAC_AES256)?;
    let ticket = pac_ticket::enc_ticket(
        "pacuser",
        pac_ticket::AUTH_TIME,
        Some(pac_ticket::authorization_data(pac)?),
    )?;
    let request = pac_ticket::ap_req(&ticket, &service_key)?;
    let keytab = pac_ticket::service_keytab(&service_key)?;
    // When the acceptor validates the AP-REQ.
    let accepted = Validator::new(&keytab)
        .with_now(pac_ticket::now()?)
        .validate_ap_req(&request)?;
    // Then the PAC is accepted and carries no claims.
    let verified = accepted.pac().ok_or("the PAC is exposed")?;
    assert!(verified.client_claims_info().is_none(), "no claims");
    Ok(())
}
