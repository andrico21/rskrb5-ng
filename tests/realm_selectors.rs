//! Realm selectors obey permanent rejection independently of construction path.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::error::Error;

    use rskrb5_ng::{
        Config,
        config::{Toggle, section_values::Value},
        error::{Config as ConfigError, Policy, RejectedFeature},
    };

    /// Typed and flattened realm selections fail before configured discovery.
    #[test]
    fn realm_selectors_reject_on_every_path() -> Result<(), Box<dyn Error>> {
        for (name, expected) in [
            ("pkinit_draft9", RejectedFeature::Draft9Pkinit),
            ("pkinit_rsa_only", RejectedFeature::RsaPkinit),
            ("krb4_convert", RejectedFeature::V4Conversion),
            ("krb4_get_tickets", RejectedFeature::KerberosV4),
            (
                "kpasswd_unprotected",
                RejectedFeature::UnprotectedPasswordChange,
            ),
        ] {
            let base = Config::parse("[realms]\nR = {\nkdc = host\n}")?;
            for value in [
                Value::Boolean(Toggle::Enabled),
                Value::Text("true".to_owned()),
                Value::Choice("true".to_owned()),
            ] {
                let mut config = base.clone();
                drop(
                    config
                        .realms
                        .first_mut()
                        .ok_or("realm")?
                        .relations
                        .insert(name.to_owned(), value),
                );
                let error = config
                    .configured_kdcs("R")
                    .err()
                    .ok_or("typed selector accepted")?;
                assert!(
                    matches!(error, ConfigError::Policy(Policy::RejectedFeature { feature, reason: _ }) if feature == expected)
                );
                #[cfg(feature = "serde")]
                {
                    let json = serde_json::to_value(&config)?;
                    let serde_error = serde_json::from_value::<Config>(json)
                        .err()
                        .ok_or("serde selector accepted")?;
                    assert!(serde_error.to_string().contains(&expected.to_string()));
                }
            }
            #[cfg(feature = "serde")]
            {
                let mut config = base.clone();
                drop(
                    config
                        .realms
                        .first_mut()
                        .ok_or("realm")?
                        .protocol_relations
                        .insert(name.to_owned(), "true".to_owned()),
                );
                let error = config
                    .configured_kdcs("R")
                    .err()
                    .ok_or("flattened selector accepted")?;
                assert!(
                    matches!(error, ConfigError::Policy(Policy::RejectedFeature { feature, reason: _ }) if feature == expected)
                );
            }
            for value in [Value::List(Vec::new()), Value::Locations(Vec::new())] {
                let mut malformed = base.clone();
                drop(
                    malformed
                        .realms
                        .first_mut()
                        .ok_or("realm")?
                        .relations
                        .insert(name.to_owned(), value),
                );
                assert!(
                    matches!(malformed.configured_kdcs("R"), Err(ConfigError::InvalidBoolean(key)) if key == name)
                );
            }
            let mut disabled = base;
            drop(
                disabled
                    .realms
                    .first_mut()
                    .ok_or("realm")?
                    .relations
                    .insert(name.to_owned(), Value::Boolean(Toggle::Disabled)),
            );
            assert_eq!(disabled.configured_kdcs("R")?, ["host:88"]);
        }
        Ok(())
    }
}
