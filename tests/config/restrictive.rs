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
    use core::error::Error;
    use std::time::UNIX_EPOCH;

    use rskrb5_ng::{
        Config, Principal,
        client::{
            build_tgt_as_req,
            options::AsReq,
            pa_enc_timestamp_with_confounder,
            transport::{KdcProtocol, Tokio as Transport},
        },
        config::{
            Toggle,
            section_values::{Plugins, Value},
        },
        error::{Client, Config as ConfigError},
        keytab::EncryptionKey,
    };
    use tokio::runtime::Builder;

    /// `noaddresses = false` needs request addresses: it round-trips through serde
    /// and fails closed at request construction without `extra_addresses`.
    #[test]
    fn noaddresses() -> Result<(), Box<dyn Error>> {
        let mut config = Config::new();
        config.libdefaults.no_addresses = Toggle::Disabled;
        let restored: Config = serde_json::from_value(serde_json::to_value(&config)?)?;
        assert!(!restored.libdefaults.no_addresses.is_enabled());
        assert!(matches!(
            AsReq::from_libdefaults(UNIX_EPOCH, 42, &config.libdefaults),
            Err(Client::NoRequestAddresses)
        ));
        config.libdefaults.extra_addresses = vec!["192.0.2.9".parse()?];
        let options = AsReq::from_libdefaults(UNIX_EPOCH, 42, &config.libdefaults)?;
        assert_eq!(options.addresses(), config.libdefaults.extra_addresses);
        Ok(())
    }

    /// Serde and programmatic defaults cannot silently weaken unavailable restrictions.
    #[test]
    fn restrictive_defaults_fail_before_requests() -> Result<(), Box<dyn Error>> {
        let runtime = Builder::new_current_thread().enable_all().build()?;
        let mut config = Config::new();
        config.libdefaults.default_rcache_name = "FILE:/cache".to_owned();
        assert!(
            serde_json::from_value::<Config>(serde_json::to_value(&config)?).is_err(),
            "serde accepted default_rcache_name"
        );
        let options = AsReq::from_libdefaults(UNIX_EPOCH, 42, &config.libdefaults);
        assert!(
            matches!(
                options,
                Err(Client::Config(ConfigError::InvalidReplayCacheName(_)))
            ),
            "request accepted default_rcache_name"
        );
        assert!(
            matches!(
                config.configured_kdcs("R"),
                Err(ConfigError::InvalidReplayCacheName(_))
            ),
            "admission ignored default_rcache_name"
        );
        assert!(
            matches!(
                runtime.block_on(Transport::new().discover_kdcs(&config, "R", KdcProtocol::Tcp)),
                Err(Client::Config(ConfigError::InvalidReplayCacheName(_)))
            ),
            "discovery ignored default_rcache_name"
        );
        // `client_aware_channel_bindings` is effective (gss::InitiatorOptions::from_config):
        // serde and request construction accept it.
        let mut aware = Config::new();
        aware.libdefaults.client_aware_channel_bindings = Toggle::Enabled;
        drop(serde_json::from_value::<Config>(serde_json::to_value(
            &aware,
        )?)?);
        drop(AsReq::from_libdefaults(UNIX_EPOCH, 42, &aware.libdefaults)?);
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
            let accepted = matches!(value, Value::Boolean(_));
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
                // Both Boolean values are effective since plan 2 todo 9: the exchange
                // engine honours `true`, and neither value blocks discovery.
                Some(Value::Boolean(Toggle::Disabled | Toggle::Enabled)) => {
                    assert_eq!(discovery?.len(), 1);
                }
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

    /// A `[plugins] clpreauth` control that excludes the encrypted timestamp is
    /// admitted by every construction path, and a caller-built request that
    /// carries one is refused before any I/O.
    #[test]
    fn excluded_timestamp_request_fails_before_login() -> Result<(), Box<dyn Error>> {
        let runtime = Builder::new_current_thread().enable_all().build()?;
        for scope in ["disable", "enable_only"] {
            let mut config = Config::parse("[realms]\nR = {\nkdc = 127.0.0.1:1\n}\n")?;
            let mut plugins = Plugins::default();
            if scope == "disable" {
                plugins.disable.push("encrypted_timestamp".to_owned());
            } else {
                plugins.enable_only.push("other".to_owned());
            }
            drop(config.plugins.insert("clpreauth".to_owned(), plugins));
            assert!(
                serde_json::from_value::<Config>(serde_json::to_value(&config)?).is_ok(),
                "serde refused {scope}"
            );
            let transport = Transport::new();
            let principal = Principal::user("R", "alice");
            let reply_key = EncryptionKey::new(18, vec![0x42; 32]);
            let checked_options =
                AsReq::new(UNIX_EPOCH, 42).with_padata(vec![pa_enc_timestamp_with_confounder(
                    &reply_key,
                    UNIX_EPOCH,
                    0,
                    &[0x22; 16],
                    None,
                )?]);
            let checked = build_tgt_as_req(principal, checked_options)?;
            let result = runtime.block_on(transport.exchange_as_req_with_config(
                &config,
                KdcProtocol::Tcp,
                &checked,
                &reply_key,
            ));
            assert!(
                matches!(result, Err(Client::EncryptedTimestampDisabled { realm }) if realm == "R"),
                "transport ignored {scope}"
            );
        }
        Ok(())
    }
}
