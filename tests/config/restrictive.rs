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
        client::{Tokio, build_tgt_as_req, options::AsReq, transport::KdcProtocol},
        config::{
            Toggle,
            section_values::{Plugins, Value},
        },
        error::Client,
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
