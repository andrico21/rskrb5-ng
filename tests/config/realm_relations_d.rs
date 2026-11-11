//! One table-driven test per realm catalogue relation.

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
        config::{Config, ConfigDiagnostic, ParseMode, section_values::Value},
        error::Config as ConfigError,
    };

    /// Exercise typed admission and the actual diagnostic/error boundary.
    fn deferred(name: &str, kind: &str, inputs: &[&str]) -> Result<(), Box<dyn Error>> {
        for input in inputs {
            let text = format!("[realms]\n EXAMPLE = {{\n {name} = {input}\n }}\n");
            let config = Config::parse(&text)?;
            let realm = config.realm("EXAMPLE").ok_or("realm missing")?;
            let value = realm.relations.get(name).ok_or("relation missing")?;
            match (kind, value) {
                ("bool", Value::Boolean(flag)) => assert_eq!(flag.is_enabled(), *input == "true"),
                ("choice", Value::Choice(choice)) => assert_eq!(choice, input),
                ("locations", Value::Locations(locations)) => assert_eq!(locations.len(), 1),
                ("list", Value::List(values)) => assert_eq!(values, &[*input]),
                ("text", Value::Text(scalar)) => assert_eq!(scalar, input),
                _ => return Err(format!("wrong value kind {name}").into()),
            }
            assert!(config.diagnostics().iter().any(|item| matches!(item, ConfigDiagnostic::NotYetEffective { relation, package: _ } if *relation == name)));
            drop(
                Config::parse_with_mode(&text, ParseMode::Strict)
                    .err()
                    .ok_or("strict accepted deferred relation")?,
            );
        }
        Ok(())
    }

    /// Named tests keep independent relation failures visible.
    macro_rules! cases {
        ($($name:ident, $kind:literal, [$($value:literal),+];)+) => {$ (
            /// The named relation has typed values and a deferred-consumer diagnostic.
            #[test]
            fn $name() -> Result<(), Box<dyn Error>> { deferred(stringify!($name), $kind, &[$($value),+]) }
        )+};
    }
    cases! {
        auth_to_local, "list", ["DEFAULT", "RULE:[1:$1](.*)s/a/b/"];
        default_domain, "text", ["example.test", "other.test"];
        disable_encrypted_timestamp, "bool", ["false", "off"];
        http_anchors, "locations", ["FILE:/ca", "DIR:/ca", "ENV:CA_BUNDLE"];
        master_kdc, "list", ["master.example", "other.example:88"];
        primary_kdc, "list", ["primary.example", "other.example:88"];
        sitename, "text", ["Site-A", "Site-B"];
        pkinit_anchors, "locations", ["FILE:/ca", "DIR:/ca"];
        pkinit_cert_match, "list", ["<SUBJECT>.*", "&&<EKU>msScLogin,clientAuth<KU>digitalSignature"];
        pkinit_eku_checking, "choice", ["kpKDC", "kpServerAuth", "none"];
        pkinit_dh_min_bits, "choice", ["1024", "2048", "4096", "P-256", "P-384", "P-521"];
        pkinit_identities, "locations", ["FILE:/cert,/key", "PKCS12:/identity", "PKCS11:module_name=never-load", "ENV:IDENTITY"];
        pkinit_kdc_hostname, "list", ["kdc.example", "other.example"];
        pkinit_pool, "locations", ["FILE:/pool", "DIR:/pool"];
        pkinit_require_crl_checking, "bool", ["true", "false"];
        pkinit_revoke, "locations", ["FILE:/crl", "DIR:/crl"];
        pkinit_identity, "locations", ["FILE:/cert,/key", "PKCS12:/server"];
        pkinit_allow_upn, "bool", ["true", "false"];
        pkinit_indicator, "list", ["strong", "pkinit"];
        pkinit_require_freshness, "bool", ["true", "false"];
    }

    /// Existing endpoint consumers preserve ordered repeated values.
    fn endpoint(name: &str) -> Result<(), Box<dyn Error>> {
        for host in ["first.example", "second.example"] {
            let config =
                Config::parse(&format!("[realms]\n EXAMPLE = {{\n {name} = {host}\n }}\n"))?;
            let realm = config.realm("EXAMPLE").ok_or("realm missing")?;
            match name {
                "kdc" => assert_eq!(config.configured_kdcs("EXAMPLE")?, [format!("{host}:88")]),
                "kpasswd_server" => {
                    assert_eq!(config.configured_kpasswd_servers("EXAMPLE")?, [host]);
                }
                "admin_server" => {
                    assert_eq!(realm.admin_server, [host]);
                    assert_eq!(
                        config.configured_kpasswd_servers("EXAMPLE")?,
                        [format!("{host}:464")]
                    );
                }
                _ => return Err("invalid endpoint case".into()),
            }
        }
        Ok(())
    }
    /// KDC endpoints reach configured discovery.
    #[test]
    fn kdc() -> Result<(), Box<dyn Error>> {
        endpoint("kdc")
    }
    /// Password endpoints reach configured discovery.
    #[test]
    fn kpasswd_server() -> Result<(), Box<dyn Error>> {
        endpoint("kpasswd_server")
    }
    /// Administrative endpoints reach password fallback.
    #[test]
    fn admin_server() -> Result<(), Box<dyn Error>> {
        endpoint("admin_server")
    }

    /// Local mapping keys preserve case and first-wins selection.
    #[test]
    fn auth_to_local_names() -> Result<(), Box<dyn Error>> {
        for name in [
            "Alice",
            "ALICE",
            "module",
            "include",
            "includedir",
            "krb4_get_tickets",
            "v4_realm",
            "pkinit_draft9",
            "pkinit_rsa_only",
            "kpasswd_unprotected",
            "kpasswd_protocol",
        ] {
            for (separator, input, expected) in [
                ("=", "local", "local"),
                (" = ", "local", "local"),
                ("\t=\t", "local", "local"),
                ("   = ", "\"\"", ""),
                (" \t = ", "\"{\"", "{"),
                ("   = ", "\"a=b\"", "a=b"),
                ("\t=\t", "\" padded \"", " padded "),
            ] {
                let config = Config::parse(&format!(
                    "[realms]\n EXAMPLE = {{\n auth_to_local_names = {{\n {name}{separator}{input}\n {name}{separator}ignored\n }}\n }}\n"
                ))?;
                assert_eq!(
                    config
                        .realm("EXAMPLE")
                        .ok_or("realm")?
                        .auth_to_local_names
                        .get(name)
                        .map(String::as_str),
                    Some(expected)
                );
                assert_eq!(
                    config.diagnostics(),
                    &[ConfigDiagnostic::NotYetEffective {
                        relation: "auth_to_local_names",
                        package: "plan 2 WP-17",
                    }]
                );
            }
        }
        for name in [
            "krb4_get_tickets",
            "v4_realm",
            "pkinit_draft9",
            "pkinit_rsa_only",
            "kpasswd_unprotected",
            "kpasswd_protocol",
        ] {
            for text in [
                format!("[libdefaults]\n{name} = true"),
                format!("[realms]\nR = {{\n{name} = true\n}}"),
                format!("[plugins]\nR = {{\nauth_to_local_names = {{\n{name} = true\n}}\n}}"),
                format!(
                    "[realms]\nR = {{\nother = {{\nauth_to_local_names = {{\n{name} = true\n}}\n}}\n}}"
                ),
                format!("[realms]*\nR = {{\nkdc = host\n}}\n[realms]\nR = {{\n{name} = true\n}}"),
            ] {
                for mode in [ParseMode::Compatible, ParseMode::Strict] {
                    assert!(
                        matches!(
                            Config::parse_with_mode(&text, mode),
                            Err(ConfigError::Policy(_))
                        ),
                        "selector admitted: {text}"
                    );
                }
            }
        }
        Ok(())
    }

    /// Removed protocol selectors are rejected before any ignored scope can hide them.
    macro_rules! rejected {
        ($($name:ident, $value:literal;)+) => {$ (
            /// The named removed mechanism never reaches a consumer.
            #[test]
            fn $name() -> Result<(), Box<dyn Error>> {
                for mode in [ParseMode::Compatible, ParseMode::Strict] {
                    drop(Config::parse_with_mode(&format!("[realms]\n EXAMPLE = {{\n {} = {}\n }}\n", stringify!($name), $value), mode).err().ok_or("removed feature accepted")?);
                }
                Ok(())
            }
        )+};
    }
    rejected! {
        v4_instance_convert, "{\n host = legacy\n }";
        v4_realm, "LEGACY";
        pkinit_win2k, "true";
        pkinit_draft9, "true";
    }
}
