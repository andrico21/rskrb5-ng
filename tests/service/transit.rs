//! Same-realm transit-policy regression tests.

use core::sync::atomic::{AtomicBool, Ordering};

use super::{
    Arc, Error, TestError, TransitValidator, Validator, http_keytab, timestamp, transit_ap_req,
};

/// Equal endpoint realms do not authorize a nonempty unchecked path.
#[test]
fn transit_rejects_same_realm_unchecked_path() -> Result<(), TestError> {
    // Given the original same-realm UNTRUSTED fixture.
    let keytab = http_keytab()?;
    let bytes = transit_ap_req("TEST.GOKRB5", 1, b"UNTRUSTED", false)?;
    let mut validator = Validator::new(&keytab).with_now(timestamp(1_893_553_447)?);
    // When no policy approves the path.
    let result = validator.validate_ap_req(&bytes);
    // Then rejection precedes replay admission.
    assert!(matches!(result, Err(Error::TransitPolicyRejected)));
    assert_eq!(validator.replay_cache_mut().len(), 0);
    Ok(())
}

/// Local empty paths remain acceptable without a caller policy.
#[test]
fn transit_accepts_local_empty_path() -> Result<(), TestError> {
    // Given a genuinely local ticket.
    let keytab = http_keytab()?;
    let bytes = transit_ap_req("TEST.GOKRB5", 1, b"", false)?;
    let mut validator = Validator::new(&keytab).with_now(timestamp(1_893_553_447)?);
    // When the ticket is validated without a transit policy.
    let accepted = validator.validate_ap_req(&bytes)?;
    // Then the local client is accepted.
    assert_eq!(accepted.client().realm, "TEST.GOKRB5");
    Ok(())
}

/// KDC-checked paths remain acceptable for equal and different endpoint realms.
#[test]
fn transit_accepts_kdc_checked_paths() -> Result<(), TestError> {
    for client_realm in ["TEST.GOKRB5", "FOREIGN.DUMMY"] {
        // Given a path checked by the KDC.
        let keytab = http_keytab()?;
        let bytes = transit_ap_req(client_realm, 1, b"UNTRUSTED", true)?;
        let mut validator = Validator::new(&keytab).with_now(timestamp(1_893_553_447)?);
        // When no caller policy is configured.
        let accepted = validator.validate_ap_req(&bytes)?;
        // Then the KDC decision suffices.
        assert_eq!(accepted.client().realm, client_realm);
    }
    Ok(())
}

/// Same-realm acceptance requires invoking the approving caller policy.
#[test]
fn transit_invokes_same_realm_approving_policy() -> Result<(), TestError> {
    // Given an unchecked same-realm path and an instrumented approval policy.
    let keytab = http_keytab()?;
    let bytes = transit_ap_req("TEST.GOKRB5", 1, b"UNTRUSTED", false)?;
    let policy = Arc::new(ObservedPolicy {
        called: AtomicBool::new(false),
        approve: true,
    });
    let mut validator = Validator::new(&keytab)
        .with_now(timestamp(1_893_553_447)?)
        .with_transit_validator(Arc::<ObservedPolicy>::clone(&policy));
    // When the path is validated.
    let accepted = validator.validate_ap_req(&bytes)?;
    // Then acceptance follows an explicit policy decision on this path.
    assert_eq!(accepted.client().realm, "TEST.GOKRB5");
    assert!(policy.called.load(Ordering::Relaxed));
    Ok(())
}

/// A configured policy cannot be bypassed merely because the endpoints match.
#[test]
fn transit_honors_same_realm_policy_rejection() -> Result<(), TestError> {
    // Given an unchecked path and a rejecting policy.
    let keytab = http_keytab()?;
    let bytes = transit_ap_req("TEST.GOKRB5", 1, b"UNTRUSTED", false)?;
    let policy = Arc::new(ObservedPolicy {
        called: AtomicBool::new(false),
        approve: false,
    });
    let mut validator = Validator::new(&keytab)
        .with_now(timestamp(1_893_553_447)?)
        .with_transit_validator(Arc::<ObservedPolicy>::clone(&policy));
    // When the same-realm ticket is presented.
    let result = validator.validate_ap_req(&bytes);
    // Then the policy denial is enforced before replay admission.
    assert!(matches!(result, Err(Error::TransitPolicyRejected)));
    assert!(policy.called.load(Ordering::Relaxed));
    assert_eq!(validator.replay_cache_mut().len(), 0);
    Ok(())
}

/// Records whether validation consults the exact endpoint/path policy.
#[derive(Debug)]
struct ObservedPolicy {
    called: AtomicBool,
    approve: bool,
}

impl TransitValidator for ObservedPolicy {
    fn accepts(
        &self,
        client_realm: &str,
        service_realm: &str,
        transited: &rasn_kerberos::TransitedEncoding,
    ) -> bool {
        self.called.store(true, Ordering::Relaxed);
        self.approve
            && client_realm == "TEST.GOKRB5"
            && service_realm == "TEST.GOKRB5"
            && transited.r#type == 1
            && transited.contents.as_ref() == b"UNTRUSTED"
    }
}
