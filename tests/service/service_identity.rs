//! Accepted service key identity regressions.

use super::{TestError, Validator, alias_ap_req, http_keytab, http_keytab_with_alias, timestamp};

/// A configured key identity is returned instead of a rewritten cleartext sname.
#[test]
fn service_identity_reports_override_for_alias_ticket() -> Result<(), TestError> {
    // Given an alias sname that has no keytab entry and a configured real identity.
    let keytab = http_keytab()?;
    let bytes = alias_ap_req()?;
    let mut validator = Validator::new(&keytab)
        .with_now(timestamp(1_893_553_447)?)
        .with_keytab_principal(["HTTP", "host.test.gokrb5"]);
    // When the real service key decrypts the ticket.
    let accepted = validator.validate_ap_req(&bytes)?;
    // Then consumers receive the identity selected for decryption, not the alias.
    assert_eq!(accepted.service().realm, "TEST.GOKRB5");
    assert_eq!(accepted.service().components, ["HTTP", "host.test.gokrb5"]);
    Ok(())
}

/// Without an override, an explicitly provisioned alias is the selected key identity.
#[test]
fn service_identity_reports_selected_keytab_alias() -> Result<(), TestError> {
    // Given two service identities provisioned with the same key material.
    let keytab = http_keytab_with_alias()?;
    let bytes = alias_ap_req()?;
    let mut validator = Validator::new(&keytab).with_now(timestamp(1_893_553_447)?);
    // When the alias selects its own matching keytab entry.
    let accepted = validator.validate_ap_req(&bytes)?;
    // Then shared key material does not invent a canonical principal.
    assert_eq!(accepted.service().realm, "TEST.GOKRB5");
    assert_eq!(accepted.service().components, ["HTTP", "alias.test.gokrb5"]);
    Ok(())
}
