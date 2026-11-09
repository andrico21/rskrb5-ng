//! Ticket PAC verification.

use super::{EncryptionKey, Error, Pac, pac, principal_from_parts, validate_authorization_data};
use crate::error::Pac as PacError;

/// Validate every ticket restriction before extracting and verifying its first PAC.
///
/// # Errors
///
/// Returns authorization-policy errors, [`Error::Pac`] for PAC parsing/checksum
/// failures, or [`Error::PacClientMismatch`] when client metadata differs from the ticket.
pub(super) fn verified_ticket_pac(
    ticket: &rasn_kerberos::EncTicketPart,
    key: &EncryptionKey,
) -> Result<Option<Pac>, Error> {
    let data = ticket.authorization_data.as_ref();
    validate_authorization_data(data, true)?;
    let Some(elements) = data else {
        return Ok(None);
    };
    let pac = pac::find_pac_in_authorization_data(elements)?;
    if let Some(value) = &pac {
        value.verify(key)?;
        let info = value
            .client_info()
            .ok_or(PacError::MissingRequiredBuffer("ClientInfo"))?;
        let client = principal_from_parts(&ticket.crealm, &ticket.cname)?;
        let auth_ticks = ticket
            .auth_time
            .0
            .timestamp()
            .checked_add(11_644_473_600)
            .and_then(|seconds| u64::try_from(seconds).ok())
            .and_then(|seconds| seconds.checked_mul(10_000_000))
            .ok_or(Error::PacClientMismatch)?;
        if info.name != realm_less_name(&client.components) || info.client_id.ticks() != auth_ticks
        {
            return Err(Error::PacClientMismatch);
        }
    }
    Ok(pac)
}

/// Escape component delimiters so distinct principals cannot share a PAC client name.
fn realm_less_name(components: &[String]) -> String {
    let mut name = String::new();
    for (index, component) in components.iter().enumerate() {
        if index != 0 {
            name.push('/');
        }
        for character in component.chars() {
            match character {
                '/' | '@' | '\\' => {
                    name.push('\\');
                    name.push(character);
                }
                '\n' => name.push_str("\\n"),
                '\t' => name.push_str("\\t"),
                '\u{8}' => name.push_str("\\b"),
                '\0' => name.push_str("\\0"),
                other => name.push(other),
            }
        }
    }
    name
}
