//! The public AD-KDC-ISSUED and AD-AND-OR helpers.

use rasn::der;
use rasn_kerberos::AuthorizationDataValue;
use rskrb5_ng::{
    authdata::{
        ConditionEvaluator, build_kdc_issued, decode_and_or, decode_kdc_issued, evaluate_and_or,
        verify_kdc_issued,
    },
    error::AuthData as Error,
    keytab::EncryptionKey,
};

use super::support::{element, session_key};
use crate::context::TestError;

/// Pins that a KDC-issued element round-trips and verifies under the session key only.
#[test]
fn kdc_issued_verifies_under_the_session_key_only() -> Result<(), TestError> {
    let key = session_key();
    let issued = build_kdc_issued(vec![element(-233_i32, b"restriction")], &key)?;

    verify_kdc_issued(&issued, &key)?;
    let decoded = decode_kdc_issued(&der::encode(&issued)?)?;
    verify_kdc_issued(&decoded, &key)?;

    let other = EncryptionKey::new(18_i32, vec![0x55; 32]);
    assert!(matches!(
        verify_kdc_issued(&issued, &other),
        Err(Error::ChecksumMismatch)
    ));
    Ok(())
}

/// Pins that a changed element, and an unkeyed or foreign checksum type, are refused.
#[test]
fn kdc_issued_refuses_tampering_and_unkeyed_checksums() -> Result<(), TestError> {
    let key = session_key();
    let mut issued = build_kdc_issued(vec![element(-233_i32, b"restriction")], &key)?;
    issued.elements.push(element(-234_i32, b"added"));
    assert!(matches!(
        verify_kdc_issued(&issued, &key),
        Err(Error::ChecksumMismatch)
    ));

    let mut unkeyed = build_kdc_issued(vec![element(-233_i32, b"x")], &key)?;
    unkeyed.ad_checksum.r#type = 7_i32;
    assert!(matches!(
        verify_kdc_issued(&unkeyed, &key),
        Err(Error::Policy(_))
    ));
    let mut unknown = build_kdc_issued(vec![element(-233_i32, b"x")], &key)?;
    unknown.ad_checksum.r#type = 9999_i32;
    assert!(matches!(
        verify_kdc_issued(&unknown, &key),
        Err(Error::UnsupportedChecksumType(9999_i32))
    ));
    let mut foreign = build_kdc_issued(vec![element(-233_i32, b"x")], &key)?;
    foreign.ad_checksum.r#type = 19_i32;
    assert!(matches!(
        verify_kdc_issued(&foreign, &key),
        Err(Error::KeyChecksumTypeMismatch {
            key_etype: 18_i32,
            checksum_type: 19_i32
        })
    ));
    assert!(matches!(
        decode_kdc_issued(&[0x30, 0x00]),
        Err(Error::Decode {
            target: "AD-KDC-ISSUED",
            message: _
        })
    ));
    Ok(())
}

/// An evaluator that understands only the types in `satisfied` and `violated`.
#[derive(Debug)]
struct Known {
    /// Types whose condition holds.
    satisfied: Vec<i32>,
    /// Types whose condition does not hold.
    violated: Vec<i32>,
}

impl ConditionEvaluator for Known {
    fn evaluate(&self, element: &AuthorizationDataValue) -> Option<bool> {
        if self.satisfied.contains(&element.r#type) {
            Some(true)
        } else if self.violated.contains(&element.r#type) {
            Some(false)
        } else {
            None
        }
    }
}

/// Pins the "or" and "and" forms of AD-AND-OR, and that an element the evaluator does not understand never counts.
#[test]
fn and_or_counts_the_satisfied_conditions() -> Result<(), TestError> {
    let elements = vec![
        element(-1_i32, b""),
        element(-2_i32, b""),
        element(-3_i32, b""),
    ];
    let encode = |count: i32| -> Result<Vec<u8>, TestError> {
        Ok(der::encode(&rasn_kerberos::AdAndOr {
            condition_count: count,
            elements: elements.clone(),
        })?)
    };
    let evaluator = Known {
        satisfied: vec![-1_i32],
        violated: vec![-2_i32],
    };

    assert!(evaluate_and_or(
        &decode_and_or(&encode(1_i32)?)?,
        &evaluator
    )?);
    assert!(!evaluate_and_or(
        &decode_and_or(&encode(2_i32)?)?,
        &evaluator
    )?);
    assert!(!evaluate_and_or(
        &decode_and_or(&encode(3_i32)?)?,
        &evaluator
    )?);
    Ok(())
}

/// Pins that an impossible condition count fails closed instead of being satisfied.
#[test]
fn and_or_refuses_impossible_counts() -> Result<(), TestError> {
    let evaluator = Known {
        satisfied: vec![-1_i32],
        violated: Vec::new(),
    };
    for count in [0_i32, -1_i32, 2_i32] {
        let wire = der::encode(&rasn_kerberos::AdAndOr {
            condition_count: count,
            elements: vec![element(-1_i32, b"")],
        })?;
        let outcome = evaluate_and_or(&decode_and_or(&wire)?, &evaluator);
        assert!(
            matches!(outcome, Err(Error::InvalidConditionCount { count: found, elements: 1_usize }) if found == count),
            "{count}: {outcome:?}"
        );
    }
    Ok(())
}
