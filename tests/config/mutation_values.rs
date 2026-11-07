//! Typed configuration admission boundary contracts.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::{error::Error, time::Duration};

    use rskrb5_ng::{
        config::{
            Config, ConfigDiagnostic,
            hostname::Canonicalization,
            section_values::{Location, Value},
        },
        error::Config as ConfigError,
    };

    /// Disabled removed-protocol selectors remain recognized without enabling them.
    #[test]
    fn disabled_protocol_names_are_recognized() -> Result<(), Box<dyn Error>> {
        for key in ["v4_custom", "krb4_custom", "pkinit_win2k"] {
            let config = Config::parse(&format!("[libdefaults]\n {key} = false"))?;
            assert!(
                !config
                    .diagnostics()
                    .iter()
                    .any(|entry| matches!(entry, ConfigDiagnostic::UnknownRelation { path: _ })),
                "disabled selector unrecognized: {key}"
            );
        }
        Ok(())
    }

    /// RSA key exchange is rejected while a DH selector stays available for later implementation.
    #[test]
    fn protocol_exchange_rejects_rsa_but_not_dh() -> Result<(), Box<dyn Error>> {
        for key in ["pkinit_kex", "pkinit_key_exchange"] {
            let error = Config::parse(&format!("[libdefaults]\n {key} = rsa-only"))
                .err()
                .ok_or("RSA accepted")?;
            assert!(
                matches!(error, ConfigError::Policy(_)),
                "wrong RSA error: {error}"
            );
            drop(Config::parse(&format!("[libdefaults]\n {key} = dh"))?);
        }
        let error = Config::parse("[libdefaults]\n v4_custom = true")
            .err()
            .ok_or("v4 enabled")?;
        assert!(
            matches!(error, ConfigError::Policy(_)),
            "wrong v4 error: {error}"
        );
        Ok(())
    }

    /// Trust anchors reject identity-only stores and empty file locations.
    #[test]
    fn trust_locations_reject_identity_stores() -> Result<(), Box<dyn Error>> {
        for location in ["FILE:", "PKCS12:identity.p12", "PKCS11:module"] {
            let error = Config::parse(&format!(
                "[realms]\n R = {{\n pkinit_anchors = {location}\n }}"
            ))
            .err()
            .ok_or("invalid anchor accepted")?;
            assert!(
                matches!(error, ConfigError::InvalidRealmsSection(_)),
                "wrong location error: {error}"
            );
        }
        drop(Config::parse(
            "[realms]\n R = {\n pkinit_identity = PKCS11:\n }",
        )?);
        Ok(())
    }

    /// Nested maps route only their own namespace and reject whitespace-bearing module names.
    #[test]
    fn section_values_keep_namespace_and_validate_names() -> Result<(), Box<dyn Error>> {
        for text in [
            "[capaths]\n R = {\n S = \"two realms\"\n }",
            "[plugins]\n interface = {\n disable = \"two modules\"\n }",
        ] {
            let error = Config::parse(text)
                .err()
                .ok_or("whitespace name accepted")?;
            assert!(
                matches!(
                    error,
                    ConfigError::InvalidLine {
                        section: _,
                        line: _,
                        text: _
                    }
                ),
                "wrong name error: {error}"
            );
        }
        let config = Config::parse(
            "[realms]\n R = {\n other = {\n Alice = local\n }\n pkinit_anchors = FILE:/first\n pkinit_anchors = FILE:/second\n }\n[plugins]\n interface = {\n unknown = value\n }",
        )?;
        assert!(
            config
                .realm("R")
                .ok_or("realm missing")?
                .auth_to_local_names
                .is_empty(),
            "unrelated nested map treated as local names"
        );
        assert!(config.plugins.is_empty(), "unknown plugin key admitted");
        let realm = config.realm("R").ok_or("realm missing")?;
        assert_eq!(
            realm.relations.get("pkinit_anchors"),
            Some(&Value::Locations(vec![
                Location::File("/first".to_owned()),
                Location::File("/second".to_owned())
            ]))
        );
        Ok(())
    }

    /// Hour-minute intervals preserve minute scaling when seconds are omitted.
    #[test]
    fn clockskew_accepts_hour_minute_form() -> Result<(), Box<dyn Error>> {
        let config = Config::parse("[libdefaults]\n clockskew = 2:30")?;
        assert_eq!(config.libdefaults.clockskew, Duration::from_mins(150));
        assert!(
            !Canonicalization::Never.is_enabled(),
            "never canonicalization enabled"
        );
        Ok(())
    }

    /// `USERID` never falls through to the Windows branch on Linux without a real UID.
    #[cfg(target_os = "linux")]
    #[test]
    fn linux_userid_requires_numeric_identity() -> Result<(), Box<dyn Error>> {
        use rskrb5_ng::config::parameters::{ExpansionContext, Failure, expand};
        let mut context = ExpansionContext::default();
        context.windows_sid = Some("S-1-5-21-99");
        let error = expand("%{USERID}", &context)
            .err()
            .ok_or("SID substituted on Linux")?;
        assert_eq!(error, Failure::Unavailable("USERID"));
        Ok(())
    }

    /// Scalar PKINIT identity selects the first location, unlike repeated trust anchors.
    #[test]
    fn scalar_identity_does_not_accumulate_locations() -> Result<(), Box<dyn Error>> {
        let config = Config::parse(
            "[realms]\n R = {\n pkinit_identity = FILE:/first\n pkinit_identity = FILE:/second\n }",
        )?;
        assert_eq!(
            config
                .realm("R")
                .ok_or("realm missing")?
                .relations
                .get("pkinit_identity"),
            Some(&Value::Locations(vec![Location::File("/first".to_owned())]))
        );
        Ok(())
    }
}
