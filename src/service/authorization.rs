//! AD-KDC-ISSUED and AD-AND-OR in ticket and authenticator authorization data.

use super::{AuthorizationBudget, AuthorizationScope, Error, validate_authorization_elements};
use crate::{
    authdata::{decode_and_or, decode_kdc_issued, evaluate_and_or, verify_kdc_issued},
    iana::authorization_data_type::{AND_OR, KDC_ISSUED},
};

/// Interpret an AD-KDC-ISSUED element.
///
/// Only ticket authorization data may carry it: the checksum is keyed with the
/// session key, which the client also holds, so in an authenticator it proves
/// nothing. Its elements are checked at the criticality of the enclosing scope.
///
/// # Errors
///
/// Returns [`Error::UnsupportedAuthorizationData`] outside a ticket or for an
/// element that cannot be decoded, [`Error::AuthorizationData`] for a checksum
/// that does not verify, and the errors of the nested elements.
pub(super) fn kdc_issued(
    entry: &rasn_kerberos::AuthorizationDataValue,
    scope: AuthorizationScope,
    budget: &mut AuthorizationBudget<'_>,
) -> Result<(), Error> {
    let key = budget
        .context
        .session_key
        .filter(|_key| scope.ticket)
        .ok_or(Error::UnsupportedAuthorizationData { kind: KDC_ISSUED })?;
    if scope.depth >= 8 {
        return Err(Error::AuthorizationDataLimit);
    }
    let issued = decode_kdc_issued(entry.data.as_ref())
        .map_err(|_malformed| Error::UnsupportedAuthorizationData { kind: KDC_ISSUED })?;
    verify_kdc_issued(&issued, key)?;
    validate_authorization_elements(
        &issued.elements,
        AuthorizationScope {
            depth: scope.depth.saturating_add(1),
            ..scope
        },
        budget,
    )
}

/// Interpret an AD-AND-OR element: only an acceptor that has an evaluator
/// implements it (RFC 4120 section 5.2.6.2: servers that do not implement it
/// reject the ticket).
///
/// # Errors
///
/// Returns [`Error::UnsupportedAuthorizationData`] without an evaluator,
/// [`Error::AuthorizationData`] for a malformed element or an impossible count
/// and [`Error::AuthorizationConditionUnsatisfied`] when too few conditions hold.
pub(super) fn and_or(
    entry: &rasn_kerberos::AuthorizationDataValue,
    budget: &AuthorizationBudget<'_>,
) -> Result<(), Error> {
    let evaluator = budget
        .context
        .conditions
        .ok_or(Error::UnsupportedAuthorizationData { kind: AND_OR })?;
    let element = decode_and_or(entry.data.as_ref())?;
    if evaluate_and_or(&element, evaluator)? {
        Ok(())
    } else {
        Err(Error::AuthorizationConditionUnsatisfied)
    }
}
