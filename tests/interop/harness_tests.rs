//! Harness regressions.
//!
//! A test that needs a changed environment re-runs itself in a child test
//! process (`support/env.rs`); the parent asserts the child's outcome and output.

use core::error::Error;
use std::{ffi::OsStr, io};

use super::{
    Fixture, assert_negotiated_enctype, assert_negotiated_mechanism, assert_negotiated_padata,
    assert_ticket_flag, require,
};
use crate::{child_env, closed_port::reserve_closed_tcp_port};

/// Env-file key of the fixture endpoint the child processes check.
const ENDPOINT_KEY: &str = "INTEROP_HARNESS_TEST_KDC";

/// The fixture the child processes require.
const FIXTURE: Fixture = Fixture::new("mit-kdc", ENDPOINT_KEY);

/// Runs `test_path` in a child with `INTEROP`, the two required switches and
/// the fixture endpoint set exactly as given (`None` removes a variable).
fn child(
    test_path: &str,
    interop: Option<&str>,
    required: (Option<&str>, Option<&str>),
    endpoint: Option<&str>,
) -> Result<(), String> {
    child_env::try_run_in_child(
        test_path,
        &[
            ("INTEROP", interop.map(OsStr::new)),
            ("INTEROP_REQUIRED", required.0.map(OsStr::new)),
            ("INTEGRATION_REQUIRED", required.1.map(OsStr::new)),
            (ENDPOINT_KEY, endpoint.map(OsStr::new)),
        ],
    )
}

/// A closed loopback endpoint from the reserved range.
fn closed_endpoint() -> io::Result<String> {
    Ok(format!("127.0.0.1:{}", reserve_closed_tcp_port()?))
}

/// In a child: the scenario's `require` result is the test result.
fn require_in_child() -> Result<(), Box<dyn Error>> {
    if require("harness-selftest", &[FIXTURE])? {
        return Err("the child ran a scenario against an unreachable fixture".into());
    }
    Ok(())
}

/// With `INTEROP_REQUIRED=1` an unreachable fixture fails the scenario, naming
/// the fixture, the endpoint and the container.
#[test]
fn required_unreachable_fixture_fails_naming_it() -> Result<(), Box<dyn Error>> {
    const PATH: &str = "harness::tests::required_unreachable_fixture_fails_naming_it";
    if child_env::in_child(PATH) {
        return require_in_child();
    }
    let endpoint = closed_endpoint()?;
    let report = child(PATH, Some("1"), (Some("1"), None), Some(&endpoint))
        .err()
        .ok_or("required mode passed with an unreachable fixture")?;
    let named = format!(
        "required interop fixture unreachable: mit-kdc at {endpoint} (container rskrb5-interop-mit-kdc)"
    );
    assert!(
        report.contains(&named),
        "the failure does not name the fixture: {report}"
    );
    assert!(
        report.contains("1 failed"),
        "the child did not fail one test: {report}"
    );
    Ok(())
}

/// Plan 1's `INTEGRATION_REQUIRED=1` makes the interop suite required too.
#[test]
fn integration_required_implies_interop_required() -> Result<(), Box<dyn Error>> {
    const PATH: &str = "harness::tests::integration_required_implies_interop_required";
    if child_env::in_child(PATH) {
        return require_in_child();
    }
    let endpoint = closed_endpoint()?;
    let report = child(PATH, Some("1"), (None, Some("1")), Some(&endpoint))
        .err()
        .ok_or("INTEGRATION_REQUIRED=1 let an unreachable fixture pass")?;
    assert!(
        report.contains("required interop fixture unreachable: mit-kdc"),
        "the failure does not name the fixture: {report}"
    );
    Ok(())
}

/// In required mode an unset endpoint key fails, naming the key.
#[test]
fn required_unset_endpoint_key_fails_naming_it() -> Result<(), Box<dyn Error>> {
    const PATH: &str = "harness::tests::required_unset_endpoint_key_fails_naming_it";
    if child_env::in_child(PATH) {
        return require_in_child();
    }
    let report = child(PATH, Some("1"), (Some("1"), None), None)
        .err()
        .ok_or("required mode passed without the fixture endpoint")?;
    assert!(
        report.contains("required interop fixture unreachable: mit-kdc")
            && report.contains(ENDPOINT_KEY),
        "the failure does not name the fixture and its key: {report}"
    );
    Ok(())
}

/// Without required mode an unreachable fixture is a visible skip.
#[test]
fn optional_unreachable_fixture_skips_visibly() -> Result<(), Box<dyn Error>> {
    const PATH: &str = "harness::tests::optional_unreachable_fixture_skips_visibly";
    if child_env::in_child(PATH) {
        return require_in_child();
    }
    let endpoint = closed_endpoint()?;
    child_env::run_in_child(
        PATH,
        &[
            ("INTEROP", Some(OsStr::new("1"))),
            ("INTEROP_REQUIRED", None),
            ("INTEGRATION_REQUIRED", None),
            (ENDPOINT_KEY, Some(OsStr::new(&endpoint))),
        ],
    );
    Ok(())
}

/// Without `INTEROP=1` nothing runs and nothing fails, even in required mode.
#[test]
fn disabled_suite_skips() -> Result<(), Box<dyn Error>> {
    const PATH: &str = "harness::tests::disabled_suite_skips";
    if child_env::in_child(PATH) {
        return require_in_child();
    }
    child(PATH, None, (Some("1"), Some("1")), None).map_err(Into::into)
}

/// A different enctype than the required one is an error.
#[test]
fn enctype_fallback_is_not_negotiated() {
    assert!(
        assert_negotiated_enctype("TGT session key", 20, 18).is_err(),
        "an AES-SHA1 fallback passed for AES-SHA2"
    );
    assert!(
        assert_negotiated_enctype("TGT session key", 20, 20).is_ok(),
        "the required enctype was refused"
    );
}

/// A different GSS mechanism than the required one is an error.
#[test]
fn mechanism_fallback_is_not_negotiated() {
    let krb5 = [1, 2, 840, 113_554, 1, 2, 2];
    let ms_legacy = [1, 2, 840, 48_018, 1, 2, 2];
    assert!(
        assert_negotiated_mechanism(&krb5, &ms_legacy).is_err(),
        "the Microsoft legacy OID passed for krb5"
    );
    assert!(
        assert_negotiated_mechanism(&krb5, &krb5).is_ok(),
        "the required mechanism was refused"
    );
}

/// A missing pre-authentication type is an error.
#[test]
fn padata_fallback_is_not_negotiated() {
    assert!(
        assert_negotiated_padata("KDC_ERR_PREAUTH_REQUIRED", 2, &[19_i32, 136_i32]).is_err(),
        "a reply without PA-ENC-TIMESTAMP passed"
    );
    assert!(
        assert_negotiated_padata("KDC_ERR_PREAUTH_REQUIRED", 2, &[19_i32, 2_i32]).is_ok(),
        "an offered PA-ENC-TIMESTAMP was refused"
    );
}

/// A clear ticket flag is an error; bit numbers follow RFC 4120 (bit 0 first).
#[test]
fn clear_ticket_flag_is_not_negotiated() {
    let pre_authent = [0x00, 0x20, 0x00, 0x00];
    assert!(
        assert_ticket_flag("pre-authent", 10, [0x40, 0x00, 0x00, 0x00]).is_err(),
        "a ticket without PRE-AUTHENT passed"
    );
    assert!(
        assert_ticket_flag("pre-authent", 10, pre_authent).is_ok(),
        "a PRE-AUTHENT ticket was refused"
    );
    assert!(
        assert_ticket_flag("renewable", 8, pre_authent).is_err(),
        "a ticket without RENEWABLE passed"
    );
}
