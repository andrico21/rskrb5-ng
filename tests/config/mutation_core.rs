//! Configuration builder and serialized wire-value contracts.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::error::Error;

    use rskrb5_ng::config::{Config, LibDefaults, Toggle, hostname::Canonicalization};

    /// Builder methods retain selected values rather than resetting to defaults.
    #[test]
    fn libdefaults_builders_preserve_selected_values() -> Result<(), Box<dyn Error>> {
        let address = "192.0.2.7".parse()?;
        let defaults = LibDefaults::new()
            .with_default_ccache_name("FILE:/cache".to_owned())
            .with_default_client_keytab_name("FILE:/client".to_owned())
            .with_default_keytab_name("FILE:/server".to_owned())
            .with_dns_canonicalize_hostname(Toggle::Disabled)
            .with_extra_addresses(vec![address])
            .with_k5login_directory("/login".to_owned())
            .with_preferred_preauth_types(vec![2_i32, 16_i32]);
        assert_eq!(defaults.default_ccache_name, "FILE:/cache");
        assert_eq!(defaults.default_client_keytab_name, "FILE:/client");
        assert_eq!(defaults.default_keytab_name, "FILE:/server");
        assert_eq!(defaults.dns_canonicalize_hostname, Canonicalization::Never);
        assert_eq!(defaults.extra_addresses, vec![address]);
        assert_eq!(defaults.k5login_directory, "/login");
        assert_eq!(defaults.preferred_preauth_types, vec![2_i32, 16_i32]);
        assert_eq!(defaults.realm_try_domains, -1_i32);
        Ok(())
    }

    /// Serialized address lists preserve both IP families and distinguish empty lists.
    #[cfg(feature = "serde")]
    #[test]
    fn config_json_preserves_extra_addresses() -> Result<(), Box<dyn Error>> {
        let populated = Config::parse("[libdefaults]\n extra_addresses = 192.0.2.7,2001:db8::7")?;
        let json: serde_json::Value = serde_json::from_str(&populated.json()?)?;
        assert_eq!(
            json.pointer("/LibDefaults/ExtraAddresses"),
            Some(&serde_json::json!(["192.0.2.7", "2001:db8::7"]))
        );
        let empty: serde_json::Value = serde_json::from_str(&Config::new().json()?)?;
        assert_eq!(
            empty.pointer("/LibDefaults/ExtraAddresses"),
            Some(&serde_json::Value::Null)
        );
        Ok(())
    }

    /// Realm lookup and endpoint defaults retain the selected realm and source order.
    #[test]
    fn config_parser_preserves_realms_and_endpoint_lists() -> Result<(), Box<dyn Error>> {
        let config = Config::parse(
            "[realms]\n First = {\n kdc = first\n kdc = second\n admin_server = admin\n }\n Second = {\n kdc = third\n }",
        )?;
        assert_eq!(
            config.realm("First").ok_or("first realm missing")?.kdc,
            vec!["first:88", "second:88"]
        );
        assert_eq!(
            config.realm("Second").ok_or("second realm missing")?.kdc,
            vec!["third:88"]
        );
        assert!(config.realm("absent").is_none(), "absent realm returned");
        Ok(())
    }

    /// JSON bit strings use RFC4648 standard base64 with padding.
    #[cfg(feature = "serde")]
    #[test]
    fn config_json_encodes_option_bits_as_base64() -> Result<(), Box<dyn Error>> {
        let config = Config::parse("[libdefaults]\n kdc_default_options = 0x12345678")?;
        let json: serde_json::Value = serde_json::from_str(&config.json()?)?;
        assert_eq!(
            json.pointer("/LibDefaults/KDCDefaultOptions/Bytes"),
            Some(&serde_json::json!("EjRWeA=="))
        );
        Ok(())
    }

    /// Include keywords require token boundaries rather than matching ordinary section names.
    #[test]
    fn include_prefix_is_not_a_directive() -> Result<(), Box<dyn Error>> {
        let config = Config::parse("[appdefaults]\n include_suffix = ordinary")?;
        assert_eq!(
            config.appdefault("app", "R", "include_suffix"),
            Some("ordinary")
        );
        Ok(())
    }
}
