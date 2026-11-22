//! The acceptor under explicit PAC policies, with tickets signed by the builder.

use core::error::Error;

use rskrb5_ng::{
    error::{Pac as PacError, Service as ServiceError},
    keytab::EncryptionKey,
    pac::{Builder, Signing, VerificationPolicy},
    service::Validator,
};

use super::{
    client, kdc_key,
    pac_ticket::{AUTH_TIME, ap_req, authorization_data, enc_ticket, now, service_keytab},
    pac_vectors, server_key, vector,
};

/// An AP-REQ whose ticket carries a PAC the builder signed with `server` and `kdc`.
fn signed_request(server: &EncryptionKey, kdc: &EncryptionKey) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut ticket = enc_ticket("pacuser", AUTH_TIME, None)?;
    Builder::new().sign_ticket(
        &mut ticket,
        &Signing::new(server, kdc).with_client(client()?),
    )?;
    ap_req(&ticket, &vector(pac_vectors::SERVER_KEY_AES256)?)
}

/// The acceptor given the KDC key verifies all four signatures of the PAC in the ticket.
#[test]
fn the_acceptor_verifies_every_signature_with_the_kdc_key() -> Result<(), Box<dyn Error>> {
    // Given a ticket with a builder-signed PAC and an acceptor that has the KDC key.
    let (server, kdc) = (server_key()?, kdc_key()?);
    let request = signed_request(&server, &kdc)?;
    let keytab = service_keytab(&vector(pac_vectors::SERVER_KEY_AES256)?)?;
    let mut validator = Validator::new(&keytab)
        .with_now(now()?)
        .with_pac_kdc_key(kdc_key()?)
        .with_pac_policy(VerificationPolicy::kdc());
    // When it validates the AP-REQ.
    let accepted = validator.validate_ap_req(&request)?;
    // Then the PAC is exposed as verified with every check passed.
    let checks = accepted.pac().ok_or("PAC")?.checks();
    assert!(checks.server() && checks.kdc() && checks.ticket() && checks.full() && checks.client());
    Ok(())
}

/// A PAC forged with the service key alone (a silver ticket) passes an acceptor that cannot check
/// the KDC signature, and the result says so; an acceptor with the KDC key refuses it.
#[test]
fn a_pac_forged_with_the_service_key_fails_where_the_kdc_key_is_known() -> Result<(), Box<dyn Error>>
{
    // Given a PAC whose KDC-keyed signatures were made with an attacker's key.
    let attacker = EncryptionKey::new(18, vec![0x99; 32]);
    let request = signed_request(&server_key()?, &attacker)?;
    let keytab = service_keytab(&vector(pac_vectors::SERVER_KEY_AES256)?)?;
    // When an acceptor without the KDC key validates it.
    let blind = Validator::new(&keytab)
        .with_now(now()?)
        .validate_ap_req(&request)?;
    // Then it is accepted, and only the server signature and the client are reported verified.
    let checks = blind.pac().ok_or("PAC")?.checks();
    assert!(checks.server() && checks.client() && !checks.kdc() && !checks.ticket());
    // And an acceptor that has the KDC key refuses it.
    let informed = Validator::new(&keytab)
        .with_now(now()?)
        .with_pac_kdc_key(kdc_key()?)
        .validate_ap_req(&request);
    assert!(matches!(
        informed,
        Err(ServiceError::Pac(PacError::KdcChecksumVerificationFailed))
    ));
    Ok(())
}

/// A policy that requires the KDC signature fails closed when the acceptor has no KDC key.
#[test]
fn a_required_kdc_signature_without_a_kdc_key_refuses_the_ticket() -> Result<(), Box<dyn Error>> {
    // Given a signed ticket and an acceptor whose policy requires the KDC signature.
    let request = signed_request(&server_key()?, &kdc_key()?)?;
    let keytab = service_keytab(&vector(pac_vectors::SERVER_KEY_AES256)?)?;
    let result = Validator::new(&keytab)
        .with_now(now()?)
        .with_pac_policy(VerificationPolicy::kdc())
        .validate_ap_req(&request);
    // Then the ticket is refused for the missing key, not accepted unverified.
    assert!(matches!(
        result,
        Err(ServiceError::Pac(PacError::MissingVerificationKey(_)))
    ));
    Ok(())
}

/// A policy that requires a PAC refuses a ticket without one; the default accepts it.
#[test]
fn a_ticket_without_a_pac_follows_the_policy() -> Result<(), Box<dyn Error>> {
    // Given a ticket without authorization data.
    let ticket = enc_ticket("pacuser", AUTH_TIME, None)?;
    let request = ap_req(&ticket, &vector(pac_vectors::SERVER_KEY_AES256)?)?;
    let keytab = service_keytab(&vector(pac_vectors::SERVER_KEY_AES256)?)?;
    // When the default and the PAC-requiring policy validate it.
    let lenient = Validator::new(&keytab)
        .with_now(now()?)
        .validate_ap_req(&request)?;
    let strict = Validator::new(&keytab)
        .with_now(now()?)
        .with_pac_policy(VerificationPolicy::acceptor().with_pac_required(true))
        .validate_ap_req(&request);
    // Then the default accepts it without a PAC and the strict policy refuses it.
    assert!(lenient.pac().is_none());
    assert!(matches!(
        strict,
        Err(ServiceError::Pac(PacError::RequiredPacAbsent))
    ));
    Ok(())
}

/// A PAC whose server signature is wrong is never exposed: the validator returns no result.
#[test]
fn a_pac_with_a_bad_server_signature_is_not_exposed() -> Result<(), Box<dyn Error>> {
    // Given a ticket whose PAC is signed under another service key.
    let wrong = EncryptionKey::new(18, vec![0x77; 32]);
    let ticket_pac = {
        let kdc = kdc_key()?;
        let mut ticket = enc_ticket("pacuser", AUTH_TIME, None)?;
        Builder::new().sign_ticket(
            &mut ticket,
            &Signing::new(&wrong, &kdc).with_client(client()?),
        )?;
        ticket
    };
    let request = ap_req(&ticket_pac, &vector(pac_vectors::SERVER_KEY_AES256)?)?;
    let keytab = service_keytab(&vector(pac_vectors::SERVER_KEY_AES256)?)?;
    let mut validator = Validator::new(&keytab).with_now(now()?);
    // When the acceptor validates it.
    let result = validator.validate_ap_req(&request);
    // Then the ticket is refused and leaves no replay record.
    assert!(matches!(
        result,
        Err(ServiceError::Pac(
            PacError::ServerChecksumVerificationFailed
        ))
    ));
    assert_eq!(validator.replay_cache_mut().len(), 0);
    Ok(())
}

/// A PAC that names another client than the ticket is refused whatever its signatures say.
#[test]
fn a_pac_of_another_client_is_refused() -> Result<(), Box<dyn Error>> {
    // Given a correctly signed PAC for `pacuser` inside a ticket for `otheruser`.
    let pac = vector(pac_vectors::SERVICE_PAC_AES256)?;
    let ticket = enc_ticket("otheruser", AUTH_TIME, Some(authorization_data(pac)?))?;
    let request = ap_req(&ticket, &vector(pac_vectors::SERVER_KEY_AES256)?)?;
    let keytab = service_keytab(&vector(pac_vectors::SERVER_KEY_AES256)?)?;
    // When the acceptor validates it.
    let result = Validator::new(&keytab)
        .with_now(now()?)
        .validate_ap_req(&request);
    // Then it is refused for the client mismatch.
    assert!(matches!(result, Err(ServiceError::PacClientMismatch)));
    Ok(())
}
