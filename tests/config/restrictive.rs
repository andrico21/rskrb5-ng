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
    use core::{
        error::Error,
        pin::pin,
        task::{Context, Poll, Waker},
        time::Duration,
    };
    use std::time::UNIX_EPOCH;

    use rskrb5_ng::{
        Config, Principal,
        client::{
            Tokio, build_tgt_as_req,
            options::AsReq,
            pa_enc_timestamp_with_confounder,
            transport::{KdcProtocol, Tokio as Transport},
        },
        config::{
            Toggle,
            section_values::{Plugins, Value},
        },
        error::{Client, Config as ConfigError},
        keytab::{EncryptionKey, Keytab},
    };
    use tokio::runtime::Builder;

    /// Serde and programmatic defaults cannot silently weaken unavailable restrictions.
    #[test]
    fn restrictive_defaults_fail_before_requests() -> Result<(), Box<dyn Error>> {
        let runtime = Builder::new_current_thread().enable_all().build()?;
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
                    options,
                    Err(Client::Config(ConfigError::NotYetEffective {
                        relation: _,
                        package: _
                    }))
                ),
                "request accepted {field}"
            );
            let (relation, package) = match field {
                "no_addresses" => ("noaddresses", "plan 2 WP-04"),
                "request_timeout" => ("request_timeout", "plan 2 WP-10"),
                "verify_ap_req_nofail" => ("verify_ap_req_nofail", "plan 2 WP-11"),
                "client_aware_channel_bindings" => {
                    ("client_aware_channel_bindings", "plan 2 WP-12")
                }
                _ => ("default_rcache_name", "plan 2 WP-20"),
            };
            assert!(
                matches!(
                    config.configured_kdcs("R"),
                    Err(ConfigError::NotYetEffective { relation: named, package: owner })
                        if named == relation && owner == package
                ),
                "admission ignored {field}"
            );
            assert!(
                matches!(
                    runtime.block_on(Transport::new().discover_kdcs(&config, "R", KdcProtocol::Tcp)),
                    Err(Client::Config(ConfigError::NotYetEffective { relation: named, package: owner }))
                        if named == relation && owner == package
                ),
                "discovery ignored {field}"
            );
        }
        Ok(())
    }

    /// Wrong public value variants cannot bypass restrictive realm admission.
    #[test]
    fn realm_restriction_rejects_wrong_value_variants() -> Result<(), Box<dyn Error>> {
        let runtime = Builder::new_current_thread().enable_all().build()?;
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
            let discovery =
                runtime.block_on(Transport::new().discover_kdcs(&config, "R", KdcProtocol::Tcp));
            match config
                .realms
                .first()
                .ok_or("realm")?
                .relations
                .get("disable_encrypted_timestamp")
            {
                Some(Value::Boolean(Toggle::Disabled)) => assert_eq!(discovery?.len(), 1),
                Some(Value::Boolean(Toggle::Enabled)) => assert!(matches!(
                    discovery,
                    Err(Client::Config(ConfigError::NotYetEffective { relation, package }))
                        if relation == "disable_encrypted_timestamp" && package == "plan 2 WP-07"
                )),
                Some(Value::Text(_) | Value::Choice(_) | Value::List(_) | Value::Locations(_)) => {
                    assert!(
                        matches!(discovery, Err(Client::Config(ConfigError::InvalidBoolean(name)))
                        if name == "disable_encrypted_timestamp")
                    );
                }
                None | Some(_) => return Err("unexpected restriction variant".into()),
            }
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
            let reply_key = EncryptionKey::new(18, vec![0x42; 32]);
            let checked_options =
                options
                    .clone()
                    .with_padata(vec![pa_enc_timestamp_with_confounder(
                        &reply_key,
                        UNIX_EPOCH,
                        0,
                        &[0x22; 16],
                        None,
                    )?]);
            let checked = build_tgt_as_req(principal.clone(), checked_options)?;
            let expected = if scope == "realm" {
                "disable_encrypted_timestamp"
            } else {
                scope
            };
            let package = if scope == "realm" {
                "plan 2 WP-07"
            } else {
                "plan 2 WP-16"
            };
            for result in [
                runtime.block_on(transport.exchange_as_req_with_config(
                    &config,
                    KdcProtocol::Tcp,
                    &checked,
                    &reply_key,
                )),
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
                    matches!(result, Err(Client::Config(ConfigError::NotYetEffective { relation, package: owner })) if relation == expected && owner == package),
                    "transport ignored {scope}"
                );
            }
            let mut dns_config = config.clone();
            dns_config.realms.first_mut().ok_or("realm")?.kdc.clear();
            dns_config.libdefaults.dns_lookup_kdc = Toggle::Enabled;
            let _runtime_guard = runtime.enter();
            for candidate in [&config, &dns_config] {
                let mut discovery = pin!(transport.discover_kdcs(candidate, "R", KdcProtocol::Tcp));
                assert!(
                    matches!(
                        discovery.as_mut().poll(&mut Context::from_waker(Waker::noop())),
                        Poll::Ready(Err(Client::Config(ConfigError::NotYetEffective { relation, package: owner })))
                            if relation == expected && owner == package
                    ),
                    "discovery must refuse {scope} before endpoint/DNS handling"
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
