//! Verification of the independently generated PAC vectors under explicit policies.

use core::error::Error;

use rskrb5_ng::{
    error::Pac as PacError,
    keytab::EncryptionKey,
    pac::{
        INFO_TYPE_KERB_VALIDATION_INFO, Pac, SignatureRequirement, TicketKind, Verification,
        VerificationPolicy,
    },
};

use super::{client, client_at, kdc_key, pac_ticket, pac_vectors, server_key, vector};

/// Parse the vector `hex_text`.
fn parse(hex_text: &str) -> Result<Pac, Box<dyn Error>> {
    Ok(Pac::parse_and_process(&vector(hex_text)?)?)
}

/// The bytes the ticket signature of the service vectors covers.
fn ticket_input() -> Result<Vec<u8>, Box<dyn Error>> {
    vector(pac_vectors::TICKET_INPUT)
}

/// Every signature of a service-ticket PAC verifies when the policy requires them all and both keys
/// and the ticket bytes are supplied (checksum type 16, aes256-cts-hmac-sha1-96).
#[test]
fn a_service_pac_verifies_all_four_signatures_and_the_client() -> Result<(), Box<dyn Error>> {
    // Given the independently generated MIT-shaped service PAC and its keys.
    let pac = parse(pac_vectors::SERVICE_PAC_AES256)?;
    let (server, kdc, input) = (server_key()?, kdc_key()?, ticket_input()?);
    // When it is verified under the policy that requires every signature.
    let request = Verification::new(VerificationPolicy::kdc())
        .with_server_key(&server)
        .with_kdc_key(&kdc)
        .with_ticket_signature_input(&input)
        .with_client(client()?);
    let verified = pac.verify_ext(&request)?;
    // Then every check passed.
    let checks = verified.checks();
    assert!(checks.server() && checks.kdc() && checks.ticket() && checks.full() && checks.client());
    assert_eq!(verified.client_info().ok_or("client info")?.name, "pacuser");
    Ok(())
}

/// The aes128-cts-hmac-sha1-96 vector (checksum type 15) verifies the same way.
#[test]
fn an_aes128_service_pac_verifies() -> Result<(), Box<dyn Error>> {
    // Given the aes128 vector and its keys.
    let pac = parse(pac_vectors::SERVICE_PAC_AES128)?;
    let server = EncryptionKey::new(17, vector(pac_vectors::SERVER_KEY_AES128)?);
    let kdc = EncryptionKey::new(17, vector(pac_vectors::KDC_KEY_AES128)?);
    let input = ticket_input()?;
    // When it is verified with every signature required.
    let request = Verification::new(VerificationPolicy::kdc())
        .with_server_key(&server)
        .with_kdc_key(&kdc)
        .with_ticket_signature_input(&input)
        .with_client(client()?);
    // Then it verifies.
    assert!(pac.verify_ext(&request)?.checks().full());
    Ok(())
}

/// A PAC for a ticket-granting ticket has no ticket signature and no full checksum, and none is
/// expected of it.
#[test]
fn a_tgs_pac_needs_only_the_server_and_kdc_signatures() -> Result<(), Box<dyn Error>> {
    // Given a PAC with server and KDC signatures only, for a `krbtgt` ticket.
    let pac = parse(pac_vectors::TGS_PAC_AES256)?;
    let (server, kdc) = (server_key()?, kdc_key()?);
    let kind = TicketKind::of_server(&["krbtgt", "TEST.PAC"]);
    // When it is verified under the all-required policy.
    let request = Verification::new(VerificationPolicy::kdc())
        .with_server_key(&server)
        .with_kdc_key(&kdc)
        .with_ticket_kind(kind)
        .with_client(client()?);
    let verified = pac.verify_ext(&request)?;
    // Then the two signatures verified and the other two were not expected.
    assert_eq!(kind, TicketKind::NoTicketSignature);
    assert!(verified.checks().server() && verified.checks().kdc());
    assert!(!verified.checks().ticket() && !verified.checks().full());
    Ok(())
}

/// Tickets for `kadmin/changepw` carry neither a ticket signature nor a full checksum (MIT
/// `k5_pac_should_have_ticket_signature`); other two-part names do.
#[test]
fn ticket_kinds_follow_the_server_principal() {
    assert_eq!(
        TicketKind::of_server(&["kadmin", "changepw"]),
        TicketKind::NoTicketSignature
    );
    assert_eq!(
        TicketKind::of_server(&["HTTP", "host"]),
        TicketKind::Service
    );
    assert_eq!(TicketKind::of_server(&["krbtgt"]), TicketKind::Service);
    assert_eq!(
        TicketKind::of_server(&["kadmin", "admin"]),
        TicketKind::Service
    );
}

/// A wrong service key fails the server signature.
#[test]
fn a_wrong_service_key_is_rejected() -> Result<(), Box<dyn Error>> {
    // Given the service PAC and a service key that is the KDC key.
    let pac = parse(pac_vectors::SERVICE_PAC_AES256)?;
    let wrong = kdc_key()?;
    // When the server signature is verified under it.
    let request = Verification::new(VerificationPolicy::acceptor())
        .with_server_key(&wrong)
        .with_client(client()?);
    // Then verification fails with the server checksum error.
    assert!(matches!(
        pac.verify_ext(&request),
        Err(PacError::ServerChecksumVerificationFailed)
    ));
    Ok(())
}

/// A wrong KDC key fails the KDC signature.
#[test]
fn a_wrong_kdc_key_is_rejected() -> Result<(), Box<dyn Error>> {
    // Given the service PAC and a KDC key that is the service key.
    let pac = parse(pac_vectors::SERVICE_PAC_AES256)?;
    let (server, wrong) = (server_key()?, server_key()?);
    // When the KDC signature is verified under it.
    let request = Verification::new(VerificationPolicy::acceptor())
        .with_server_key(&server)
        .with_kdc_key(&wrong)
        .with_client(client()?);
    // Then verification fails with the KDC checksum error.
    assert!(matches!(
        pac.verify_ext(&request),
        Err(PacError::KdcChecksumVerificationFailed)
    ));
    Ok(())
}

/// A PAC whose server signature is valid but whose full checksum was made under another key is
/// refused by a policy that requires the full checksum (the plan's QA failure scenario).
#[test]
fn a_valid_server_checksum_with_a_wrong_full_checksum_is_refused() -> Result<(), Box<dyn Error>> {
    // Given the PAC with a valid server and KDC signature and a foreign full checksum.
    let (server, kdc, input) = (server_key()?, kdc_key()?, ticket_input()?);
    let request =
        Verification::new(VerificationPolicy::acceptor().with_full(SignatureRequirement::Required))
            .with_server_key(&server)
            .with_kdc_key(&kdc)
            .with_ticket_signature_input(&input)
            .with_client(client()?);
    // When it is verified under a policy that requires the full checksum.
    let refused = parse(pac_vectors::WRONG_FULL_PAC_AES256)?.verify_ext(&request);
    // Then it is refused, although the server signature verifies on its own.
    assert!(matches!(
        refused,
        Err(PacError::FullChecksumVerificationFailed)
    ));
    let server_only = parse(pac_vectors::WRONG_FULL_PAC_AES256)?.verify(&server);
    assert!(server_only.is_ok(), "the server signature alone is valid");
    Ok(())
}

/// A ticket signature over other bytes than the ticket it claims to cover is refused.
#[test]
fn a_wrong_ticket_signature_is_rejected() -> Result<(), Box<dyn Error>> {
    // Given the PAC whose ticket signature covers other bytes, and the real ticket bytes.
    let pac = parse(pac_vectors::WRONG_TICKET_PAC_AES256)?;
    let (server, kdc, input) = (server_key()?, kdc_key()?, ticket_input()?);
    // When the ticket signature is verified.
    let request = Verification::new(VerificationPolicy::kdc())
        .with_server_key(&server)
        .with_kdc_key(&kdc)
        .with_ticket_signature_input(&input)
        .with_client(client()?);
    // Then it is refused.
    assert!(matches!(
        pac.verify_ext(&request),
        Err(PacError::TicketChecksumVerificationFailed)
    ));
    Ok(())
}

/// A client name or authentication time other than the PAC's is refused (MIT
/// `krb5_pac_verify_ext` principal and authtime check).
#[test]
fn a_wrong_client_or_authtime_is_rejected() -> Result<(), Box<dyn Error>> {
    let server = server_key()?;
    for wrong in [
        client_at("otheruser", pac_ticket::AUTH_TIME)?,
        client_at("pacuser", pac_ticket::AUTH_TIME + 1)?,
        client_at("pacuser", pac_ticket::AUTH_TIME - 1)?,
        client_at("PACUSER", pac_ticket::AUTH_TIME)?,
    ] {
        // Given the service PAC and a client that differs in name or time.
        let pac = parse(pac_vectors::SERVICE_PAC_AES256)?;
        // When the client info is validated.
        let request = Verification::new(VerificationPolicy::acceptor())
            .with_server_key(&server)
            .with_client(wrong);
        // Then it is refused.
        assert!(matches!(
            pac.verify_ext(&request),
            Err(PacError::ClientInfoMismatch)
        ));
    }
    Ok(())
}

/// A policy that requires a signature without the key to check it fails closed.
#[test]
fn a_required_signature_without_its_key_fails_closed() -> Result<(), Box<dyn Error>> {
    // Given the service PAC, only the service key, and a policy that requires the KDC signature.
    let pac = parse(pac_vectors::SERVICE_PAC_AES256)?;
    let server = server_key()?;
    let request =
        Verification::new(VerificationPolicy::acceptor().with_kdc(SignatureRequirement::Required))
            .with_server_key(&server)
            .with_client(client()?);
    // When it is verified.
    // Then it fails with the missing key, not with a pass.
    assert!(matches!(
        pac.verify_ext(&request),
        Err(PacError::MissingVerificationKey("KDCChecksum"))
    ));
    Ok(())
}

/// Without the KDC key the acceptor default verifies the server signature only and says so.
#[test]
fn without_the_kdc_key_only_the_server_signature_is_verified() -> Result<(), Box<dyn Error>> {
    // Given the service PAC and only the service key.
    let pac = parse(pac_vectors::SERVICE_PAC_AES256)?;
    let server = server_key()?;
    let request = Verification::new(VerificationPolicy::default())
        .with_server_key(&server)
        .with_client(client()?);
    // When it is verified under the acceptor default.
    let verified = pac.verify_ext(&request)?;
    // Then the PAC is verified, and the KDC, ticket and full signatures are reported unverified.
    let checks = verified.checks();
    assert!(checks.server() && checks.client());
    assert!(!checks.kdc() && !checks.ticket() && !checks.full());
    Ok(())
}

/// A required buffer that is absent is reported by name.
#[test]
fn a_required_buffer_that_is_absent_is_refused() -> Result<(), Box<dyn Error>> {
    // Given the MIT-shaped PAC, which has no `KERB_VALIDATION_INFO`.
    let pac = parse(pac_vectors::SERVICE_PAC_AES256)?;
    let server = server_key()?;
    // When the policy requires it.
    let request = Verification::new(
        VerificationPolicy::acceptor().require_buffer(INFO_TYPE_KERB_VALIDATION_INFO),
    )
    .with_server_key(&server)
    .with_client(client()?);
    // Then verification fails naming the buffer.
    assert!(matches!(
        pac.verify_ext(&request),
        Err(PacError::MissingRequiredBuffer("KerbValidationInfo"))
    ));
    Ok(())
}

/// A policy that binds the client without a client binding fails closed.
#[test]
fn a_client_binding_policy_without_a_client_is_refused() -> Result<(), Box<dyn Error>> {
    // Given the service PAC, the service key and no client.
    let pac = parse(pac_vectors::SERVICE_PAC_AES256)?;
    let server = server_key()?;
    let request = Verification::new(VerificationPolicy::acceptor()).with_server_key(&server);
    // When it is verified.
    // Then it fails with the missing client binding.
    assert!(matches!(
        pac.verify_ext(&request),
        Err(PacError::MissingClientBinding)
    ));
    Ok(())
}

/// Dropping the client binding from the policy skips the client check (MIT `NULL` principal).
#[test]
fn a_policy_without_client_binding_skips_the_client_check() -> Result<(), Box<dyn Error>> {
    // Given the service PAC and a policy that does not bind the client.
    let pac = parse(pac_vectors::SERVICE_PAC_AES256)?;
    let server = server_key()?;
    let request = Verification::new(VerificationPolicy::acceptor().with_client_binding(false))
        .with_server_key(&server);
    // When it is verified.
    let verified = pac.verify_ext(&request)?;
    // Then it verifies and reports the client unchecked.
    assert!(!verified.checks().client());
    Ok(())
}
