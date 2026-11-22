//! Building and signing PACs: the builder reproduces the independent vector byte for byte.

use core::error::Error;

use rskrb5_ng::{
    error::Pac as PacError,
    pac::{
        Builder, INFO_TYPE_PAC_ATTRIBUTES_INFO, INFO_TYPE_PAC_CLIENT_INFO,
        INFO_TYPE_PAC_FULL_SIGNATURE_DATA, INFO_TYPE_PAC_REQUESTOR,
        INFO_TYPE_PAC_TICKET_SIGNATURE_DATA, Pac, Signing, TicketKind, Verification,
        VerificationPolicy, find_pac_in_authorization_data, ticket_signature_input,
    },
};

use super::{client, client_at, kdc_key, pac_ticket, pac_vectors, server_key, vector};

/// The attributes buffer the generator wrote: two flag bits, `PAC_WAS_REQUESTED` set.
const ATTRIBUTES: [u8; 8] = [2, 0, 0, 0, 1, 0, 0, 0];

/// The requestor SID the generator wrote: `S-1-5-21-1-2-3-1104`.
fn requestor() -> Vec<u8> {
    let mut sid = vec![1, 5, 0, 0, 0, 0, 0, 5];
    for sub in [21_u32, 1, 2, 3, 1104] {
        sid.extend_from_slice(&sub.to_le_bytes());
    }
    sid
}

/// The builder with the buffers of the service vector, except client info and signatures.
fn builder() -> Result<Builder, Box<dyn Error>> {
    let mut builder = Builder::new();
    builder.add_buffer(INFO_TYPE_PAC_ATTRIBUTES_INFO, &ATTRIBUTES)?;
    builder.add_buffer(INFO_TYPE_PAC_REQUESTOR, &requestor())?;
    Ok(builder)
}

/// Signing adds the client info of the binding when the PAC has none.
#[test]
fn signing_adds_the_client_info() -> Result<(), Box<dyn Error>> {
    // Given the attributes and requestor buffers, the vector keys and ticket bytes.
    let (server, kdc, input) = (
        server_key()?,
        kdc_key()?,
        vector(pac_vectors::TICKET_INPUT)?,
    );
    // When the builder signs them for `pacuser`.
    let signed = builder()?.sign(
        &Signing::new(&server, &kdc)
            .with_client(client()?)
            .with_ticket_signature_input(&input),
    )?;
    // Then the client info names the client and its authentication time.
    let info = signed.client_info().ok_or("client info")?;
    assert_eq!(info.name, "pacuser");
    assert_eq!(
        info.client_id.ticks(),
        (pac_ticket::AUTH_TIME + 11_644_473_600) * 10_000_000
    );
    Ok(())
}

/// A PAC whose buffers are added in the generator's order is the generator's PAC exactly.
#[test]
fn a_builder_in_the_generators_order_signs_the_identical_bytes() -> Result<(), Box<dyn Error>> {
    // Given the client info added first, as the generator does.
    let (server, kdc, input) = (
        server_key()?,
        kdc_key()?,
        vector(pac_vectors::TICKET_INPUT)?,
    );
    let mut first = Builder::new();
    let name: Vec<u8> = "pacuser"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    let ticks = (pac_ticket::AUTH_TIME + 11_644_473_600) * 10_000_000;
    let mut info = ticks.to_le_bytes().to_vec();
    info.extend_from_slice(&u16::try_from(name.len())?.to_le_bytes());
    info.extend_from_slice(&name);
    first.add_buffer(INFO_TYPE_PAC_CLIENT_INFO, &info)?;
    first.add_buffer(INFO_TYPE_PAC_ATTRIBUTES_INFO, &ATTRIBUTES)?;
    first.add_buffer(INFO_TYPE_PAC_REQUESTOR, &requestor())?;
    // When it signs with the client binding (which only validates the existing info).
    let signed = first.sign(
        &Signing::new(&server, &kdc)
            .with_client(client()?)
            .with_ticket_signature_input(&input),
    )?;
    // Then every byte equals the independent generator's output.
    assert_eq!(
        signed.data(),
        vector(pac_vectors::SERVICE_PAC_AES256)?.as_slice()
    );
    Ok(())
}

/// A signed PAC verifies under the policy that requires every signature.
#[test]
fn a_signed_pac_verifies_under_the_kdc_policy() -> Result<(), Box<dyn Error>> {
    // Given a PAC signed with the vector keys.
    let (server, kdc, input) = (
        server_key()?,
        kdc_key()?,
        vector(pac_vectors::TICKET_INPUT)?,
    );
    let signed = builder()?.sign(
        &Signing::new(&server, &kdc)
            .with_client(client()?)
            .with_ticket_signature_input(&input),
    )?;
    // When it is verified with every signature required.
    let request = Verification::new(VerificationPolicy::kdc())
        .with_server_key(&server)
        .with_kdc_key(&kdc)
        .with_ticket_signature_input(&input)
        .with_client(client()?);
    let verified = signed.verify_ext(&request)?;
    // Then all five checks passed.
    let checks = verified.checks();
    assert!(checks.server() && checks.kdc() && checks.ticket() && checks.full() && checks.client());
    Ok(())
}

/// A PAC for a ticket-granting ticket is signed without ticket signature and full checksum.
#[test]
fn a_tgs_pac_has_only_the_server_and_kdc_signatures() -> Result<(), Box<dyn Error>> {
    // Given the builder signing for a ticket-granting ticket.
    let (server, kdc) = (server_key()?, kdc_key()?);
    let signed = builder()?.sign(
        &Signing::new(&server, &kdc)
            .with_client(client()?)
            .with_ticket_kind(TicketKind::NoTicketSignature),
    )?;
    // When its buffers are listed.
    let types = signed.buffer_types();
    // Then there is neither a ticket signature nor a full checksum.
    assert!(!types.contains(&INFO_TYPE_PAC_TICKET_SIGNATURE_DATA));
    assert!(!types.contains(&INFO_TYPE_PAC_FULL_SIGNATURE_DATA));
    assert!(signed.server_checksum().is_some() && signed.kdc_checksum().is_some());
    Ok(())
}

/// A service ticket's PAC cannot be signed without the bytes its ticket signature covers.
#[test]
fn a_service_pac_needs_the_ticket_signature_input() -> Result<(), Box<dyn Error>> {
    // Given a signing request without them.
    let (server, kdc) = (server_key()?, kdc_key()?);
    // When a service PAC is signed.
    let result = builder()?.sign(&Signing::new(&server, &kdc).with_client(client()?));
    // Then signing fails closed.
    assert!(matches!(result, Err(PacError::MissingVerificationKey(_))));
    Ok(())
}

/// Buffers are unique, removable and listed in table order; the table is bounded.
#[test]
fn buffers_are_unique_removable_and_bounded() -> Result<(), Box<dyn Error>> {
    // Given a builder with one buffer.
    let mut builder = Builder::new();
    builder.add_buffer(100, b"a")?;
    // When a type is added twice, removed, or the 4096th+1 buffer is added.
    let duplicate = builder.add_buffer(100, b"b");
    builder.add_buffer(101, b"c")?;
    assert!(builder.remove_buffer(100));
    assert!(!builder.remove_buffer(100));
    let mut full = Builder::new();
    for ul_type in 0..4096 {
        full.add_buffer(ul_type, &[])?;
    }
    let overflow = full.add_buffer(5000, &[]);
    // Then duplicates and overflow are refused and the rest follows.
    assert!(matches!(duplicate, Err(PacError::DuplicateBuffer(100))));
    assert!(matches!(overflow, Err(PacError::BufferCountLimit(4097))));
    assert_eq!(builder.buffer_types(), vec![101]);
    assert_eq!(builder.buffer(101), Some(b"c".as_slice()));
    Ok(())
}

/// Re-signing a parsed PAC keeps its content and replaces the signatures.
#[test]
fn a_parsed_pac_can_be_resigned_under_other_keys() -> Result<(), Box<dyn Error>> {
    // Given the vector and new keys.
    let original = Pac::parse_and_process(&vector(pac_vectors::SERVICE_PAC_AES256)?)?;
    let (new_server, new_kdc) = (kdc_key()?, server_key()?);
    let input = vector(pac_vectors::TICKET_INPUT)?;
    // When it is rebuilt and signed with the swapped keys.
    let resigned = Builder::from_pac(&original)?.sign(
        &Signing::new(&new_server, &new_kdc)
            .with_client(client()?)
            .with_ticket_signature_input(&input),
    )?;
    // Then the content is kept and only the new keys verify.
    assert_eq!(resigned.client_info(), original.client_info());
    assert_eq!(resigned.requestor_sid(), original.requestor_sid());
    let request = Verification::new(VerificationPolicy::kdc())
        .with_server_key(&new_server)
        .with_kdc_key(&new_kdc)
        .with_ticket_signature_input(&input)
        .with_client(client()?);
    assert!(resigned.clone().verify_ext(&request)?.checks().full());
    let old = Verification::new(VerificationPolicy::acceptor())
        .with_server_key(&new_kdc)
        .with_client(client()?);
    assert!(matches!(
        resigned.verify_ext(&old),
        Err(PacError::ServerChecksumVerificationFailed)
    ));
    Ok(())
}

/// Signing checks the client info of a PAC that already has one.
#[test]
fn signing_refuses_another_client_than_the_pac_names() -> Result<(), Box<dyn Error>> {
    // Given a builder that holds the vector's client info and a different client.
    let original = Pac::parse_and_process(&vector(pac_vectors::SERVICE_PAC_AES256)?)?;
    let (server, kdc, input) = (
        server_key()?,
        kdc_key()?,
        vector(pac_vectors::TICKET_INPUT)?,
    );
    let other = client_at("otheruser", pac_ticket::AUTH_TIME)?;
    // When it signs for the other client.
    let result = Builder::from_pac(&original)?.sign(
        &Signing::new(&server, &kdc)
            .with_client(other)
            .with_ticket_signature_input(&input),
    );
    // Then signing is refused.
    assert!(matches!(result, Err(PacError::ClientInfoMismatch)));
    Ok(())
}

/// `sign_ticket` puts the signed PAC into the ticket; the ticket signature then binds the PAC to
/// that ticket, and a later change of the ticket breaks it.
#[test]
fn sign_ticket_binds_the_pac_to_the_ticket() -> Result<(), Box<dyn Error>> {
    // Given a ticket without authorization data and the keys.
    let (server, kdc) = (server_key()?, kdc_key()?);
    let mut ticket = pac_ticket::enc_ticket("pacuser", pac_ticket::AUTH_TIME, None)?;
    // When the builder signs the PAC into it.
    builder()?.sign_ticket(
        &mut ticket,
        &Signing::new(&server, &kdc).with_client(client()?),
    )?;
    // Then the PAC found in the ticket verifies, ticket signature included.
    let found = find_pac_in_authorization_data(
        ticket
            .authorization_data
            .as_ref()
            .ok_or("authorization data")?,
    )?
    .ok_or("PAC in the ticket")?;
    let input = ticket_signature_input(&ticket)?;
    let request = Verification::new(VerificationPolicy::kdc())
        .with_server_key(&server)
        .with_kdc_key(&kdc)
        .with_ticket_signature_input(&input)
        .with_client(client()?);
    assert!(found.clone().verify_ext(&request)?.checks().ticket());
    // And a ticket with another end time no longer matches the signature.
    let mut altered = ticket.clone();
    altered.end_time = pac_ticket::enc_ticket("pacuser", pac_ticket::AUTH_TIME + 1, None)?.end_time;
    let altered_input = ticket_signature_input(&altered)?;
    let altered_request = Verification::new(VerificationPolicy::kdc())
        .with_server_key(&server)
        .with_kdc_key(&kdc)
        .with_ticket_signature_input(&altered_input)
        .with_client(client()?);
    assert!(matches!(
        found.verify_ext(&altered_request),
        Err(PacError::TicketChecksumVerificationFailed)
    ));
    Ok(())
}

/// A ticket without a PAC has no ticket-signature input.
#[test]
fn a_ticket_without_a_pac_has_no_signature_input() -> Result<(), Box<dyn Error>> {
    // Given a ticket with no authorization data.
    let ticket = pac_ticket::enc_ticket("pacuser", pac_ticket::AUTH_TIME, None)?;
    // When the signature input is computed.
    // Then it fails as a missing PAC.
    assert!(matches!(
        ticket_signature_input(&ticket),
        Err(PacError::RequiredPacAbsent)
    ));
    Ok(())
}
