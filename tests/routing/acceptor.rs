//! Acceptor transit validation (FU-SVC-08).
//!
//! The multi-pair `TransitPolicy` and the profile-driven `CapathsTransit` (MIT 1.22.2
//! `krb5_check_transited_list`, `chk_trans.c:308-356`), used by the
//! acceptor's validation of the ticket plaintext only it can decrypt.

use alloc::sync::Arc;
use std::{env, fs, process};

use rskrb5_ng::{
    config::Config,
    error::Service as ServiceError,
    service::{CapathsTransit, TransitPolicy, TransitValidator, Validator},
};

use crate::{
    TestError,
    forge::{self, SERVICE_REALM, Transit},
};

/// The profile of the acceptor: FAR.TEST reaches SVC.TEST through MID.TEST,
/// and NEAR.TEST is a direct neighbour.
const CAPATHS: &str = "[capaths]
 FAR.TEST = {
  SVC.TEST = MID.TEST
 }
 NEAR.TEST = {
  SVC.TEST = .
 }
";

/// Validate a forged ticket with a transit validator, returning the client realm.
fn validate(
    validator: Option<Arc<dyn TransitValidator>>,
    transit: &Transit<'_>,
) -> Result<Result<String, ServiceError>, TestError> {
    let keytab = forge::keytab("service-password")?;
    let bytes = forge::ap_req(&keytab, transit)?;
    let mut acceptor = Validator::new(&keytab).with_now(forge::now()?);
    if let Some(policy) = validator {
        acceptor = acceptor.with_transit_validator(policy);
    }
    Ok(acceptor
        .validate_ap_req(&bytes)
        .map(|accepted| accepted.client().realm.clone()))
}

/// An unchecked ticket from `client_realm` with the given transited encoding.
const fn unchecked<'contents>(
    client_realm: &'contents str,
    contents: &'contents [u8],
) -> Transit<'contents> {
    Transit {
        client_realm,
        kind: 1,
        contents,
        checked: false,
    }
}

/// One `TransitPolicy` trusts several endpoint pairs, each with its own paths,
/// and no pair borrows another's paths.
#[test]
fn multi_pair_policy_trusts_each_listed_pair_only() -> Result<(), TestError> {
    // Given a policy for a direct pair and a path pair.
    let policy: Arc<dyn TransitValidator> = Arc::new(
        TransitPolicy::new()
            .and_direct("NEAR.TEST", SERVICE_REALM)
            .and_domain_x500_paths("FAR.TEST", SERVICE_REALM, [b"MID.TEST"]),
    );
    // When tickets of both pairs and crossed paths are validated.
    let near = validate(Some(Arc::clone(&policy)), &unchecked("NEAR.TEST", b""))?;
    let far = validate(
        Some(Arc::clone(&policy)),
        &unchecked("FAR.TEST", b"MID.TEST"),
    )?;
    let near_via_mid = validate(
        Some(Arc::clone(&policy)),
        &unchecked("NEAR.TEST", b"MID.TEST"),
    )?;
    let far_direct = validate(Some(Arc::clone(&policy)), &unchecked("FAR.TEST", b""))?;
    let stranger = validate(Some(policy), &unchecked("OTHER.TEST", b""))?;
    // Then each pair is trusted only with its own paths.
    assert_eq!(near?, "NEAR.TEST");
    assert_eq!(far?, "FAR.TEST");
    for (case, result) in [
        ("near via mid", near_via_mid),
        ("far direct", far_direct),
        ("unlisted pair", stranger),
    ] {
        assert!(
            matches!(result, Err(ServiceError::TransitPolicyRejected)),
            "{case}: {result:?}"
        );
    }
    // And an empty policy trusts nothing.
    let empty = validate(
        Some(Arc::new(TransitPolicy::new())),
        &unchecked("NEAR.TEST", b""),
    )?;
    assert!(
        matches!(empty, Err(ServiceError::TransitPolicyRejected)),
        "{empty:?}"
    );
    Ok(())
}

/// The capaths validator accepts a transited path the profile declares.
#[test]
fn capaths_transit_accepts_a_configured_path() -> Result<(), TestError> {
    // Given the acceptor's profile.
    let validator: Arc<dyn TransitValidator> =
        Arc::new(CapathsTransit::from_config(&Config::parse(CAPATHS)?));
    // When the configured path and a direct neighbour's ticket are validated.
    let far = validate(
        Some(Arc::clone(&validator)),
        &unchecked("FAR.TEST", b"MID.TEST"),
    )?;
    let near = validate(Some(validator), &unchecked("NEAR.TEST", b""))?;
    // Then both are accepted.
    assert_eq!(far?, "FAR.TEST");
    assert_eq!(near?, "NEAR.TEST");
    Ok(())
}

/// QA failure scenario of todo 17: a transited path not in `[capaths]` is
/// rejected by the capaths validator, as are an unknown encoding, a malformed
/// encoding and a same-realm ticket with a nonempty path.
#[test]
fn capaths_transit_rejects_a_path_not_in_capaths() -> Result<(), TestError> {
    // Given the acceptor's profile.
    let validator: Arc<dyn TransitValidator> =
        Arc::new(CapathsTransit::from_config(&Config::parse(CAPATHS)?));
    for (case, transit) in [
        ("an off-path realm", unchecked("FAR.TEST", b"EVIL.TEST")),
        (
            "an extra realm",
            unchecked("FAR.TEST", b"MID.TEST,EVIL.TEST"),
        ),
        ("the server realm", unchecked("FAR.TEST", b"SVC.TEST")),
        ("a trailing escape", unchecked("FAR.TEST", b"MID.TEST\\")),
        ("a same-realm path", unchecked(SERVICE_REALM, b"MID.TEST")),
        (
            "an unknown encoding",
            Transit {
                client_realm: "FAR.TEST",
                kind: 99,
                contents: b"MID.TEST",
                checked: false,
            },
        ),
    ] {
        // When the ticket is validated.
        let result = validate(Some(Arc::clone(&validator)), &transit)?;
        // Then the transit check rejects it.
        assert!(
            matches!(result, Err(ServiceError::TransitPolicyRejected)),
            "{case}: {result:?}"
        );
    }
    Ok(())
}

/// The capaths validator falls back to the realm hierarchy for an unlisted
/// pair, as MIT does, unless it is restricted to configured pairs.
#[test]
fn capaths_transit_hierarchy_fallback_is_restrictable() -> Result<(), TestError> {
    // Given a ticket from A.EXAMPLE.TEST through EXAMPLE.TEST to SVC.TEST.
    let transit = unchecked("A.EXAMPLE.TEST", b"EXAMPLE.TEST");
    let config = Config::parse(CAPATHS)?;
    // When it is validated with the default and the configured-only validator.
    let walked = validate(
        Some(Arc::new(CapathsTransit::from_config(&config))),
        &transit,
    )?;
    let configured = validate(
        Some(Arc::new(
            CapathsTransit::from_config(&config).configured_only(),
        )),
        &transit,
    )?;
    // Then the hierarchy admits it and the restricted validator does not.
    assert_eq!(walked?, "A.EXAMPLE.TEST");
    assert!(
        matches!(configured, Err(ServiceError::TransitPolicyRejected)),
        "{configured:?}"
    );
    Ok(())
}

/// The profile-driven acceptor constructor uses the profile's `[capaths]` for
/// the pairs it lists and nothing else; without `[capaths]` it keeps the
/// default refusal of unchecked cross-realm tickets.
#[test]
fn configured_acceptor_uses_the_profile_capaths() -> Result<(), TestError> {
    // Given a service keytab file named by the profile.
    let path = env::temp_dir().join(format!("rskrb5-routing-acceptor-{}.keytab", process::id()));
    forge::keytab("service-password")?.save(&path)?;
    let named = format!(
        "[libdefaults]\n default_keytab_name = FILE:{}\n",
        path.display()
    );
    let with_capaths = Config::parse(&format!("{named}{CAPATHS}"))?;
    let without = Config::parse(&named)?;
    let keytab = forge::keytab("service-password")?;
    let far = forge::ap_req(&keytab, &unchecked("FAR.TEST", b"MID.TEST"))?;
    let hierarchy = forge::ap_req(&keytab, &unchecked("A.EXAMPLE.TEST", b"EXAMPLE.TEST"))?;
    // When the tickets are validated by acceptors built from the profiles.
    let accepted = Validator::from_default_keytab_name(&with_capaths)?
        .with_now(forge::now()?)
        .validate_ap_req(&far);
    let unlisted = Validator::from_default_keytab_name(&with_capaths)?
        .with_now(forge::now()?)
        .validate_ap_req(&hierarchy);
    let refused = Validator::from_default_keytab_name(&without)?
        .with_now(forge::now()?)
        .validate_ap_req(&far);
    fs::remove_file(&path)?;
    // Then only the listed pair's path is accepted.
    assert_eq!(accepted?.client().realm, "FAR.TEST");
    assert!(
        matches!(unlisted, Err(ServiceError::TransitPolicyRejected)),
        "{unlisted:?}"
    );
    assert!(
        matches!(refused, Err(ServiceError::TransitPolicyRejected)),
        "{refused:?}"
    );
    Ok(())
}
