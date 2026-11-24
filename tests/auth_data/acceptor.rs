//! The acceptor and AD-KDC-ISSUED / AD-AND-OR.

use alloc::sync::Arc;
use core::time::Duration;
use std::time::UNIX_EPOCH;

use rasn_kerberos::AuthorizationDataValue;
use rskrb5_ng::{
    authdata::{ConditionEvaluator, build_kdc_issued},
    error::Service as Error,
    keytab::Keytab,
    service::Validator,
};

use super::support::{ap_req, element, keytab, session_key, wrapping};
use crate::context::{Context as _, TestError};

/// The validation time of the fixture.
const NOW: u64 = 1_893_553_447;

/// A validator for the fixture at [`NOW`].
fn validator(keytab: &Keytab) -> Result<Validator<'_>, TestError> {
    let now = UNIX_EPOCH
        .checked_add(Duration::from_secs(NOW))
        .context("time is representable")?;
    Ok(Validator::new(keytab).with_now(now))
}

/// Satisfies exactly the conditions of type -1.
#[derive(Debug)]
struct OnlyMinusOne;

impl ConditionEvaluator for OnlyMinusOne {
    fn evaluate(&self, element: &AuthorizationDataValue) -> Option<bool> {
        (element.r#type == -1).then_some(true)
    }
}

/// Pins that a KDC-issued element in a ticket is accepted when its checksum verifies, and its optional contents stay optional.
#[test]
fn a_verified_kdc_issued_element_in_a_ticket_is_accepted() -> Result<(), TestError> {
    let keytab = keytab()?;
    let issued = build_kdc_issued(vec![element(-233_i32, b"")], &session_key())?;
    let data = wrapping(1_i32, &wrapping(4_i32, &issued)?)?;

    let accepted = validator(&keytab)?
        .validate_ap_req(&ap_req(Some(data), None)?)
        .context("the verified KDC-issued element is accepted inside AD-IF-RELEVANT")?;

    assert_eq!(accepted.client().name(), "testuser1");
    Ok(())
}

/// Pins that a mandatory unknown element inside a KDC-issued container is still refused.
#[test]
fn a_critical_element_inside_kdc_issued_is_refused() -> Result<(), TestError> {
    let keytab = keytab()?;
    let issued = build_kdc_issued(vec![element(-233_i32, b"")], &session_key())?;
    let data = wrapping(4_i32, &issued)?;

    let refused = validator(&keytab)?.validate_ap_req(&ap_req(Some(data), None)?);

    assert!(
        matches!(
            refused,
            Err(Error::UnsupportedAuthorizationData { kind: -233_i32 })
        ),
        "{refused:?}"
    );
    Ok(())
}

/// Pins that a KDC-issued element with a wrong checksum, and one in the client-controlled authenticator, are refused.
#[test]
fn kdc_issued_elements_that_cannot_be_trusted_are_refused() -> Result<(), TestError> {
    let keytab = keytab()?;
    let mut forged = build_kdc_issued(vec![element(-233_i32, b"")], &session_key())?;
    forged.elements.push(element(-234_i32, b""));
    let refused = validator(&keytab)?.validate_ap_req(&ap_req(
        Some(wrapping(1_i32, &wrapping(4_i32, &forged)?)?),
        None,
    )?);
    assert!(
        matches!(refused, Err(Error::AuthorizationData(_))),
        "{refused:?}"
    );

    let issued = build_kdc_issued(vec![element(-233_i32, b"")], &session_key())?;
    let in_authenticator = wrapping(1_i32, &wrapping(4_i32, &issued)?)?;
    let in_client_data =
        validator(&keytab)?.validate_ap_req(&ap_req(None, Some(in_authenticator))?);
    assert!(
        matches!(
            in_client_data,
            Err(Error::UnsupportedAuthorizationData { kind: 4_i32 })
        ),
        "{in_client_data:?}"
    );
    Ok(())
}

/// Pins that AD-AND-OR stays refused without an evaluator, is accepted when the conditions are met and refused when they are not.
#[test]
fn and_or_needs_an_evaluator_and_its_conditions() -> Result<(), TestError> {
    let keytab = keytab()?;
    let and_or = |count: i32| rasn_kerberos::AdAndOr {
        condition_count: count,
        elements: vec![element(-1_i32, b""), element(-2_i32, b"")],
    };

    let without =
        validator(&keytab)?.validate_ap_req(&ap_req(Some(wrapping(5_i32, &and_or(1_i32))?), None)?);
    assert!(
        matches!(
            without,
            Err(Error::UnsupportedAuthorizationData { kind: 5_i32 })
        ),
        "{without:?}"
    );

    let accepted = validator(&keytab)?
        .with_authorization_conditions(Arc::new(OnlyMinusOne))
        .validate_ap_req(&ap_req(Some(wrapping(5_i32, &and_or(1_i32))?), None)?)
        .context("one satisfied condition of the or form")?;
    assert_eq!(accepted.client().name(), "testuser1");

    let unmet = validator(&keytab)?
        .with_authorization_conditions(Arc::new(OnlyMinusOne))
        .validate_ap_req(&ap_req(Some(wrapping(5_i32, &and_or(2_i32))?), None)?);
    assert!(
        matches!(unmet, Err(Error::AuthorizationConditionUnsatisfied)),
        "{unmet:?}"
    );
    Ok(())
}
