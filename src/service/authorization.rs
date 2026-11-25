//! AD-KDC-ISSUED, AD-AND-OR and AD-CAMMAC in ticket and authenticator authorization data.

use super::{AuthorizationBudget, AuthorizationScope, Error, validate_authorization_elements};
use crate::{
    authdata::{
        decode_and_or, decode_auth_indicators, decode_cammac, decode_kdc_issued, evaluate_and_or,
        verify_cammac, verify_kdc_issued,
    },
    iana::authorization_data_type::{AND_OR, CAMMAC, KDC_ISSUED},
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

/// Interpret an AD-CAMMAC element (RFC 7751): verify its service verifier
/// under the key that decrypted the ticket, then interpret its elements at the
/// criticality of the enclosing scope, where its authentication indicators
/// count (MIT `get_cammac_authdata`, `authdata.c:586-606`).
///
/// Only ticket authorization data may carry it: the service verifier
/// authenticates the elements, not the ticket they arrive in, so a CAMMAC
/// copied into an authenticator would still verify.
///
/// # Errors
///
/// Returns [`Error::UnsupportedAuthorizationData`] outside a ticket,
/// [`Error::AuthorizationDataLimit`] past the nesting bound, and
/// [`Error::AuthorizationData`] for a malformed element or a verifier that is
/// absent or does not verify (MIT skips a CAMMAC whose verifier does not
/// verify, `authdata.c:555-558`; this acceptor refuses the ticket), and the
/// errors of the nested elements.
pub(super) fn cammac(
    entry: &rasn_kerberos::AuthorizationDataValue,
    scope: AuthorizationScope,
    budget: &mut AuthorizationBudget<'_>,
) -> Result<(), Error> {
    let key = budget
        .context
        .service_key
        .filter(|_key| scope.ticket)
        .ok_or(Error::UnsupportedAuthorizationData { kind: CAMMAC })?;
    if scope.depth >= 8 {
        return Err(Error::AuthorizationDataLimit);
    }
    let container = decode_cammac(entry.data.as_ref())?;
    verify_cammac(&container, key)?;
    validate_authorization_elements(
        &container.elements,
        AuthorizationScope {
            depth: scope.depth.saturating_add(1),
            cammac: true,
            ..scope
        },
        budget,
    )
}

/// Collect the authentication indicators of an AD-AUTHENTICATION-INDICATOR
/// element inside a verified AD-CAMMAC.
///
/// # Errors
///
/// Returns [`Error::AuthorizationData`] for a malformed indicator list.
pub(super) fn indicators(
    entry: &rasn_kerberos::AuthorizationDataValue,
    budget: &mut AuthorizationBudget<'_>,
) -> Result<(), Error> {
    budget
        .indicators
        .extend(decode_auth_indicators(entry.data.as_ref())?);
    Ok(())
}
