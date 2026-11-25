//! The expected-service and PAC-extraction settings of the validator (gokrb5
//! `service.SName` and `service.DecodePAC`, GO-service-1).

use super::{
    Error, PacError, Principal, TestError, VALID_AP_REQ, Validator, alias_ap_req, ap_req_with_pac,
    ap_req_with_pac_bytes, authdata_ap_req, authorization_element, decode_hex, http_keytab,
    http_keytab_with_alias, pac, pac_ad_win2k, syshttp_keytab, timestamp,
};
use crate::context::Context as _;

/// The validation time of the fixtures.
const NOW: u64 = 1_893_553_447;

/// `HTTP/<host>@TEST.GOKRB5`.
fn http(host: &str) -> Principal {
    Principal::new(
        "TEST.GOKRB5".to_owned(),
        3,
        vec!["HTTP".to_owned(), host.to_owned()],
    )
}

/// Whether `result` is the wrong-principal refusal.
fn wrong_principal<T>(result: Result<T, Error>) -> bool {
    matches!(result, Err(Error::WrongPrincipal { .. }))
}

/// The fixture PAC with its server signature flipped.
fn forged_pac() -> Result<Vec<u8>, TestError> {
    let mut bytes = decode_hex(pac_ad_win2k::PAC_AD_WIN2K)?;
    let parsed = pac::Pac::parse(&bytes).context("PAC header parses")?;
    let server = parsed
        .buffer(pac::INFO_TYPE_PAC_SERVER_SIGNATURE_DATA)
        .context("server checksum buffer exists")?;
    let offset = usize::try_from(server.offset)?
        .checked_add(4)
        .context("offset fits")?;
    *bytes.get_mut(offset).context("signature byte")? ^= 0x01;
    Ok(bytes)
}

/// A keytab holding a key for another service does not make its tickets acceptable to a validator
/// that expects one service.
#[test]
fn expected_service_rejects_another_keytab_principal() -> Result<(), TestError> {
    // Given a keytab with the host and an alias service under one key,
    let keytab = http_keytab_with_alias()?;
    let validator = || -> Result<Validator<'_>, TestError> {
        Ok(Validator::new(&keytab).with_now(timestamp(NOW)?))
    };
    // a validator that expects the alias refuses the host's ticket,
    assert!(wrong_principal(
        validator()?
            .with_expected_service(http("alias.test.gokrb5"))
            .validate_ap_req(&decode_hex(VALID_AP_REQ)?)
    ));
    // one that expects the host refuses the alias's ticket,
    assert!(wrong_principal(
        validator()?
            .with_expected_service(http("host.test.gokrb5"))
            .validate_ap_req(&alias_ap_req()?)
    ));
    // and the host's own ticket is accepted as the host.
    let accepted = validator()?
        .with_expected_service(http("host.test.gokrb5"))
        .validate_ap_req(&decode_hex(VALID_AP_REQ)?)?;
    assert_eq!(accepted.service().components, ["HTTP", "host.test.gokrb5"]);
    // The realm is part of the expected identity.
    let mut other_realm = http("host.test.gokrb5");
    other_realm.realm = "OTHER.GOKRB5".to_owned();
    assert!(wrong_principal(
        validator()?
            .with_expected_service(other_realm)
            .validate_ap_req(&decode_hex(VALID_AP_REQ)?)
    ));
    Ok(())
}

/// The keytab-principal override chooses the key; the expected service is checked against the
/// identity of that key, so the override neither satisfies nor blocks it.
#[test]
fn keytab_override_does_not_override_expected_service() -> Result<(), TestError> {
    // Given an override to the alias, a ticket the alias's key decrypts is not the host's.
    let keytab = http_keytab_with_alias()?;
    assert!(wrong_principal(
        Validator::new(&keytab)
            .with_now(timestamp(NOW)?)
            .with_keytab_principal(["HTTP", "alias.test.gokrb5"])
            .with_expected_service(http("host.test.gokrb5"))
            .validate_ap_req(&decode_hex(VALID_AP_REQ)?)
    ));
    // Given an override to the host, an alias sname decrypted by the host's key is the host's.
    let host_only = http_keytab()?;
    let accepted = Validator::new(&host_only)
        .with_now(timestamp(NOW)?)
        .with_keytab_principal(["HTTP", "host.test.gokrb5"])
        .with_expected_service(http("host.test.gokrb5"))
        .validate_ap_req(&alias_ap_req()?)?;
    assert_eq!(accepted.service().components, ["HTTP", "host.test.gokrb5"]);
    Ok(())
}

/// By default the PAC is verified and exposed, and a forged one is refused.
#[test]
fn pac_decode_default_verifies() -> Result<(), TestError> {
    let keytab = syshttp_keytab()?;
    let accepted = Validator::new(&keytab)
        .with_now(timestamp(NOW)?)
        .validate_ap_req(&ap_req_with_pac()?)?;
    assert!(
        accepted
            .pac()
            .context("the verified PAC")?
            .checks()
            .server()
    );
    assert!(matches!(
        Validator::new(&keytab)
            .with_now(timestamp(NOW)?)
            .validate_ap_req(&ap_req_with_pac_bytes(forged_pac()?)?),
        Err(Error::Pac(PacError::ServerChecksumVerificationFailed))
    ));
    Ok(())
}

/// Turning PAC extraction off keeps every check: the PAC policy, the PAC-required policy and
/// the refusal of unknown critical authorization data.
#[test]
fn pac_disable_cannot_bypass_required_policy() -> Result<(), TestError> {
    let keytab = syshttp_keytab()?;
    let validator = || -> Result<Validator<'_>, TestError> {
        Ok(Validator::new(&keytab)
            .with_now(timestamp(NOW)?)
            .with_pac_extraction(false))
    };
    // A good PAC is accepted but not handed out.
    assert!(
        validator()?
            .validate_ap_req(&ap_req_with_pac()?)?
            .pac()
            .is_none()
    );
    // A forged PAC is still refused.
    assert!(matches!(
        validator()?.validate_ap_req(&ap_req_with_pac_bytes(forged_pac()?)?),
        Err(Error::Pac(PacError::ServerChecksumVerificationFailed))
    ));
    // A required PAC is still required.
    let http = http_keytab()?;
    assert!(matches!(
        Validator::new(&http)
            .with_now(timestamp(NOW)?)
            .with_pac_extraction(false)
            .with_pac_policy(pac::VerificationPolicy::acceptor().with_pac_required(true))
            .validate_ap_req(&decode_hex(VALID_AP_REQ)?),
        Err(Error::Pac(PacError::RequiredPacAbsent))
    ));
    // Unknown critical authorization data is still refused.
    let critical = authdata_ap_req(Some(authorization_element(-233, Vec::new())), None)?;
    assert!(matches!(
        Validator::new(&http)
            .with_now(timestamp(NOW)?)
            .with_pac_extraction(false)
            .validate_ap_req(&critical),
        Err(Error::UnsupportedAuthorizationData { kind: -233_i32 })
    ));
    Ok(())
}
