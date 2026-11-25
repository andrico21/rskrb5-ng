//! Ticket PAC verification.

use super::{
    AuthorizationContext, EncryptionKey, Error, VerificationPolicy, Verified,
    encryption_key_from_rasn, pac, principal_from_parts, system_time_from_kerberos_time,
    validate_authorization_data,
};
use crate::{authdata::ConditionEvaluator, error::Pac as PacError};

/// What a ticket's PAC is verified against: the validator's policy and keys, and the ticket's server.
pub(super) struct PacCheck<'check> {
    /// What the PAC must pass.
    policy: &'check VerificationPolicy,
    /// The KDC key of the validator, when it has one.
    kdc_key: Option<&'check EncryptionKey>,
    /// The components of the ticket's server principal.
    server: &'check [String],
    /// What the application knows about AD-AND-OR conditions.
    conditions: Option<&'check dyn ConditionEvaluator>,
}

impl<'check> PacCheck<'check> {
    /// Bundle the validator's PAC settings with the ticket's server.
    pub(super) const fn new(
        policy: &'check VerificationPolicy,
        kdc_key: Option<&'check EncryptionKey>,
        server: &'check [String],
    ) -> Self {
        Self {
            policy,
            kdc_key,
            server,
            conditions: None,
        }
    }

    /// Evaluate AD-AND-OR elements of the ticket with `conditions`.
    pub(super) fn with_conditions(
        mut self,
        conditions: Option<&'check dyn ConditionEvaluator>,
    ) -> Self {
        self.conditions = conditions;
        self
    }
}

/// Validate every ticket restriction before extracting and verifying its first PAC; return the
/// PAC and the authentication indicators of the ticket's verified AD-CAMMACs.
///
/// The PAC must pass the validator's policy: the server signature under `key`, the KDC, ticket and
/// full signatures when the validator holds the KDC key, and the client info against the ticket's
/// client name and authentication time.
///
/// # Errors
///
/// Returns authorization-policy errors, [`Error::Pac`] for PAC parsing, signature or
/// required-buffer failures, or [`Error::PacClientMismatch`] when client metadata differs from the
/// ticket.
pub(super) fn verified_ticket_pac(
    ticket: &rasn_kerberos::EncTicketPart,
    key: &EncryptionKey,
    check: &PacCheck<'_>,
) -> Result<(Option<Verified>, Vec<String>), Error> {
    let data = ticket.authorization_data.as_ref();
    let session = encryption_key_from_rasn(&ticket.key);
    let context = AuthorizationContext::new()
        .with_session_key(&session)
        .with_service_key(key)
        .with_conditions(check.conditions);
    let indicators = validate_authorization_data(data, true, context)?;
    Ok((verified_pac(ticket, key, check)?, indicators))
}

/// Extract and verify the first PAC of the ticket's authorization data.
///
/// # Errors
///
/// Returns the PAC errors of [`verified_ticket_pac`].
fn verified_pac(
    ticket: &rasn_kerberos::EncTicketPart,
    key: &EncryptionKey,
    check: &PacCheck<'_>,
) -> Result<Option<Verified>, Error> {
    let found = match ticket.authorization_data.as_ref() {
        Some(elements) => pac::find_pac_in_authorization_data(elements)?,
        None => None,
    };
    let Some(parsed) = found else {
        return if check.policy.pac_required() {
            Err(PacError::RequiredPacAbsent.into())
        } else {
            Ok(None)
        };
    };
    let client = principal_from_parts(&ticket.crealm, &ticket.cname)?;
    let binding = pac::ClientBinding::new(
        realm_less_name(&client.components),
        system_time_from_kerberos_time(&ticket.auth_time)
            .map_err(|_unrepresentable| Error::PacClientMismatch)?,
    );
    let input = match (check.kdc_key, parsed.ticket_checksum()) {
        (Some(_), Some(_)) => Some(pac::ticket_signature_input(ticket)?),
        _ => None,
    };
    let mut request = pac::Verification::new(check.policy.clone())
        .with_server_key(key)
        .with_client(binding)
        .with_ticket_kind(pac::TicketKind::of_server(check.server));
    if let Some(kdc_key) = check.kdc_key {
        request = request.with_kdc_key(kdc_key);
    }
    if let Some(covered) = &input {
        request = request.with_ticket_signature_input(covered);
    }
    match parsed.verify_ext(&request) {
        Ok(verified) => Ok(Some(verified)),
        Err(PacError::ClientInfoMismatch) => Err(Error::PacClientMismatch),
        Err(other) => Err(other.into()),
    }
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
