//! Restrictive settings must fail before any request or discovery effect.

#[cfg(test)]
#[cfg(all(feature = "tokio", feature = "serde"))]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::{error::Error, time::Duration};
    use std::time::UNIX_EPOCH;

    use rskrb5_ng::{
        Config, Principal,
        client::{
            Tokio, build_tgt_as_req,
            options::AsReq,
            transport::{KdcProtocol, Tokio as Transport},
        },
        config::{
            Toggle,
            section_values::{Plugins, Value},
        },
        error::{Client, Config as ConfigError},
        keytab::Keytab,
    };
    use tokio::runtime::Builder;

    /// Serde and programmatic defaults cannot silently weaken unavailable restrictions.
    #[test]
    fn restrictive_defaults_fail_before_requests() -> Result<(), Box<dyn Error>> {
        for field in [
            "no_addresses",
            "request_timeout",
            "verify_ap_req_nofail",
            "client_aware_channel_bindings",
            "default_rcache_name",
        ] {
            let mut config = Config::new();
            match field {
                "no_addresses" => config.libdefaults.no_addresses = Toggle::Disabled,
                "request_timeout" => config.libdefaults.request_timeout = Duration::from_secs(1),
                "verify_ap_req_nofail" => config.libdefaults.verify_ap_req_nofail = Toggle::Enabled,
                "client_aware_channel_bindings" => {
                    config.libdefaults.client_aware_channel_bindings = Toggle::Enabled;
                }
                _ => config.libdefaults.default_rcache_name = "FILE:/cache".to_owned(),
            }
            assert!(
                serde_json::from_value::<Config>(serde_json::to_value(&config)?).is_err(),
                "serde accepted {field}"
            );
            let options = AsReq::from_libdefaults(UNIX_EPOCH, 42, &config.libdefaults);
            assert!(
                matches!(
                    build_tgt_as_req(Principal::user("R", "alice"), options),
                    Err(Client::Crypto(_))
                ),
                "request accepted {field}"
            );
        }
        Ok(())
    }

    /// Wrong public value variants cannot bypass restrictive realm admission.
    #[test]
    fn realm_restriction_rejects_wrong_value_variants() -> Result<(), Box<dyn Error>> {
        for value in [
            Value::Text("true".to_owned()),
            Value::Choice("true".to_owned()),
            Value::List(vec!["true".to_owned()]),
            Value::Locations(Vec::new()),
            Value::Boolean(Toggle::Enabled),
            Value::Boolean(Toggle::Disabled),
        ] {
            let accepted = value == Value::Boolean(Toggle::Disabled);
            let mut config = Config::parse("[realms]\nR = {\nkdc = 127.0.0.1:1\n}\n")?;
            drop(
                config
                    .realms
                    .first_mut()
                    .ok_or("realm")?
                    .relations
                    .insert("disable_encrypted_timestamp".to_owned(), value),
            );
            assert_eq!(config.configured_kdcs("R").is_ok(), accepted);
            assert_eq!(
                serde_json::from_value::<Config>(serde_json::to_value(&config)?).is_ok(),
                accepted
            );
        }
        Ok(())
    }

    /// Realm and plugin restrictions reject independently of defaults and credentials.
    #[test]
    fn restrictive_scopes_fail_before_login() -> Result<(), Box<dyn Error>> {
        let runtime = Builder::new_current_thread().enable_all().build()?;
        for scope in ["realm", "disable", "enable_only"] {
            let mut config = Config::parse("[realms]\nR = {\nkdc = 127.0.0.1:1\n}\n")?;
            if scope == "realm" {
                drop(config.realms.first_mut().ok_or("realm")?.relations.insert(
                    "disable_encrypted_timestamp".to_owned(),
                    Value::Boolean(Toggle::Enabled),
                ));
            } else {
                let mut plugins = Plugins::default();
                if scope == "disable" {
                    plugins.disable.push("encrypted_timestamp".to_owned());
                } else {
                    plugins.enable_only.push("other".to_owned());
                }
                drop(config.plugins.insert("clpreauth".to_owned(), plugins));
            }
            assert!(
                serde_json::from_value::<Config>(serde_json::to_value(&config)?).is_err(),
                "serde accepted {scope}"
            );
            let transport = Transport::new();
            let principal = Principal::user("R", "alice");
            let options = AsReq::new(UNIX_EPOCH, 42);
            let expected = if scope == "realm" {
                "disable_encrypted_timestamp"
            } else {
                scope
            };
            for result in [
                runtime.block_on(transport.login_tgt_with_password_config(
                    &config,
                    KdcProtocol::Tcp,
                    principal.clone(),
                    b"password",
                    options.clone(),
                )),
                runtime.block_on(transport.login_tgt_with_keytab_config(
                    &config,
                    KdcProtocol::Tcp,
                    principal,
                    &Keytab::new(),
                    options,
                )),
            ] {
                assert!(
                    matches!(result, Err(Client::Config(ConfigError::NotYetEffective { relation, package: _ })) if relation == expected),
                    "transport ignored {scope}"
                );
            }
            let mut client = Tokio::with_password(
                config,
                KdcProtocol::Tcp,
                Principal::user("R", "alice"),
                b"password".to_vec(),
            );
            assert!(
                matches!(runtime.block_on(client.login()), Err(Client::Config(_))),
                "login accepted {scope}"
            );
        }
        Ok(())
    }
}
