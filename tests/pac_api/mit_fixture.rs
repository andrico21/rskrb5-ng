//! A PAC and its ticket captured from MIT krb5 1.22.2: every signature, the re-encoded ticket
//! bytes the ticket signature covers, and the rejections.

use core::{error::Error, time::Duration};
use std::time::UNIX_EPOCH;

use rasn::der;
use rskrb5_ng::{
    error::Pac as PacError,
    keytab::EncryptionKey,
    pac::{
        ClientBinding, Pac, Verification, VerificationPolicy, find_pac_in_authorization_data,
        ticket_signature_input,
    },
};

use super::{super::pac_mit_capture, vector};

/// The captured ticket and its PAC.
fn captured() -> Result<(rasn_kerberos::EncTicketPart, Pac), Box<dyn Error>> {
    let ticket: rasn_kerberos::EncTicketPart =
        der::decode(&vector(pac_mit_capture::ENC_TICKET_PART)?)?;
    let pac = find_pac_in_authorization_data(
        ticket
            .authorization_data
            .as_ref()
            .ok_or("the ticket has authorization data")?,
    )?
    .ok_or("the ticket carries a PAC")?;
    Ok((ticket, pac))
}

/// The client of the captured ticket: its name and authentication time.
fn client(ticket: &rasn_kerberos::EncTicketPart) -> Result<ClientBinding, Box<dyn Error>> {
    let seconds = u64::try_from(ticket.auth_time.0.timestamp())?;
    let time = UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds))
        .ok_or("time")?;
    Ok(ClientBinding::new("testuser1", time))
}

/// An aes256-cts-hmac-sha384-192 key of the capture.
fn key(hex_text: &str) -> Result<EncryptionKey, Box<dyn Error>> {
    Ok(EncryptionKey::new(20, vector(hex_text)?))
}

/// The PAC MIT 1.22.2 built verifies in full under its two keys (checksum type 20).
///
/// That is the server signature, the KDC signature, the ticket signature over the re-encoded
/// ticket, the KB5020805 full checksum and the client info.
#[test]
fn the_pac_mit_built_verifies_under_both_keys() -> Result<(), Box<dyn Error>> {
    // Given the captured ticket, its PAC and the two keys.
    let (ticket, pac) = captured()?;
    let (service, kdc) = (
        key(pac_mit_capture::SERVICE_KEY)?,
        key(pac_mit_capture::KDC_KEY)?,
    );
    let input = ticket_signature_input(&ticket)?;
    // When it is verified with every signature required.
    let request = Verification::new(VerificationPolicy::kdc())
        .with_server_key(&service)
        .with_kdc_key(&kdc)
        .with_ticket_signature_input(&input)
        .with_client(client(&ticket)?);
    let verified = pac.verify_ext(&request)?;
    // Then every check passed, and MIT built no logon info.
    let checks = verified.checks();
    assert!(checks.server() && checks.kdc() && checks.ticket() && checks.full() && checks.client());
    assert!(verified.kerb_validation_info().is_none());
    Ok(())
}

/// The captured PAC is the container the ticket's authorization data holds.
#[test]
fn the_pac_in_the_ticket_is_the_captured_pac() -> Result<(), Box<dyn Error>> {
    // Given the ticket and the PAC bytes captured next to it.
    let (_ticket, pac) = captured()?;
    // When they are compared.
    // Then they are the same bytes.
    assert_eq!(pac.data(), vector(pac_mit_capture::PAC)?.as_slice());
    Ok(())
}

/// Decoding and encoding the ticket reproduces MIT's DER: the ticket signature does not depend on
/// a re-encoding that could differ from the KDC's.
#[test]
fn the_ticket_re_encodes_to_the_kdcs_der() -> Result<(), Box<dyn Error>> {
    // Given the captured ticket.
    let (ticket, _pac) = captured()?;
    // When it is encoded again.
    // Then the bytes are the KDC's.
    assert_eq!(
        der::encode(&ticket)?,
        vector(pac_mit_capture::ENC_TICKET_PART)?
    );
    Ok(())
}

/// A change to the ticket after the PAC was signed breaks the ticket signature.
#[test]
fn a_changed_ticket_fails_the_ticket_signature() -> Result<(), Box<dyn Error>> {
    // Given the ticket with its end time moved by a second.
    let (mut ticket, pac) = captured()?;
    ticket.end_time.0 += chrono::TimeDelta::seconds(1);
    let (service, kdc) = (
        key(pac_mit_capture::SERVICE_KEY)?,
        key(pac_mit_capture::KDC_KEY)?,
    );
    let input = ticket_signature_input(&ticket)?;
    // When the PAC is verified against it.
    let request = Verification::new(VerificationPolicy::kdc())
        .with_server_key(&service)
        .with_kdc_key(&kdc)
        .with_ticket_signature_input(&input)
        .with_client(client(&ticket)?);
    // Then the ticket signature fails and nothing else is blamed.
    assert!(matches!(
        pac.verify_ext(&request),
        Err(PacError::TicketChecksumVerificationFailed)
    ));
    Ok(())
}

/// The service key does not verify the KDC signature, and the KDC key does not verify the server
/// signature.
#[test]
fn the_keys_are_not_interchangeable() -> Result<(), Box<dyn Error>> {
    // Given the captured PAC and its keys swapped.
    let (ticket, pac) = captured()?;
    let (service, kdc) = (
        key(pac_mit_capture::SERVICE_KEY)?,
        key(pac_mit_capture::KDC_KEY)?,
    );
    let swapped = Verification::new(VerificationPolicy::acceptor())
        .with_server_key(&kdc)
        .with_client(client(&ticket)?);
    let wrong_kdc = Verification::new(VerificationPolicy::acceptor())
        .with_server_key(&service)
        .with_kdc_key(&service)
        .with_client(client(&ticket)?);
    // When they are verified.
    // Then the server signature, then the KDC signature, fail.
    assert!(matches!(
        pac.clone().verify_ext(&swapped),
        Err(PacError::ServerChecksumVerificationFailed)
    ));
    assert!(matches!(
        pac.verify_ext(&wrong_kdc),
        Err(PacError::KdcChecksumVerificationFailed)
    ));
    Ok(())
}
