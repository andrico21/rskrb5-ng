//! Profile composition for application defaults, capaths and plugin interfaces.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::error::Error;

    use rskrb5_ng::config::{Config, ConfigDiagnostic, ParseMode, section_values::Route};

    /// MIT's four appdefault levels are selected independently with exact case.
    #[test]
    fn appdefaults() -> Result<(), Box<dyn Error>> {
        let config = Config::parse(
            "[appdefaults]\n option = global\n R = {\n option = realm\n }\n App = {\n option = app\n R = {\n option = specific\n flag = on\n }\n }\n",
        )?;
        for (app, realm, expected) in [
            ("App", "R", "specific"),
            ("App", "OTHER", "app"),
            ("other", "R", "realm"),
            ("app", "r", "global"),
        ] {
            assert_eq!(config.appdefault(app, realm, "option"), Some(expected));
        }
        assert_eq!(config.appdefault_boolean("App", "R", "flag")?, Some(true));
        assert_eq!(config.appdefault("App", "R", "absent"), None);
        drop(
            config
                .appdefault_boolean("App", "R", "option")
                .err()
                .ok_or("nonboolean accepted")?,
        );
        Ok(())
    }

    /// Capaths preserve case, direct edges, intermediate order and relation finals.
    #[test]
    fn capaths() -> Result<(), Box<dyn Error>> {
        for ending in ["", "\n[capaths]\n Client = {\n Server = ignored\n }\n"] {
            let config = Config::parse(&format!(
                "[capaths]\n Client = {{\n Server = First\n Server* = Second\n Direct = .\n }}\n{ending}"
            ))?;
            assert_eq!(
                config.capath("Client", "Server"),
                Some(&Route::Via(vec!["First".to_owned(), "Second".to_owned()]))
            );
            assert_eq!(config.capath("Client", "Direct"), Some(&Route::Direct));
            assert_eq!(config.capath("client", "Server"), None);
            assert!(config.diagnostics().iter().any(|item| matches!(
                item,
                ConfigDiagnostic::NotYetEffective {
                    relation: "capaths",
                    package: "plan 2 WP-11"
                }
            )));
        }
        drop(
            Config::parse("[capaths]\n A = {\n B = .\n B = C\n }\n")
                .err()
                .ok_or("mixed direct route accepted")?,
        );
        Ok(())
    }

    /// Exact and dotted/bare suffix mappings retain established MIT behavior.
    #[test]
    fn domain_realm() -> Result<(), Box<dyn Error>> {
        let config = Config::parse(
            "[domain_realm]\n exact.example = EXACT\n .example = CHILD\n example = APEX\n",
        )?;
        for (host, expected) in [
            ("EXACT.EXAMPLE", "EXACT"),
            ("other.example", "CHILD"),
            ("example", "APEX"),
        ] {
            assert_eq!(config.resolve_realm(host), Some(expected));
        }
        Ok(())
    }

    /// Plugin values accumulate as individual names, never whitespace token lists.
    fn plugin(key: &str) -> Result<(), Box<dyn Error>> {
        for interface in ["ccselect", "certauth"] {
            let text = format!(
                "[plugins]\n {interface} = {{\n {key} = first\n {key}* = second\n {key} = ignored\n }}\n"
            );
            let config = Config::parse(&text)?;
            let selected = config.plugins.get(interface).ok_or("plugin interface")?;
            let names = if key == "disable" {
                &selected.disable
            } else {
                &selected.enable_only
            };
            assert_eq!(names, &["first", "second"]);
            drop(
                Config::parse_with_mode(&text, ParseMode::Strict)
                    .err()
                    .ok_or("strict plugin ignored")?,
            );
        }
        Ok(())
    }
    /// Disabled plugins retain ordered profile names.
    #[test]
    fn disable() -> Result<(), Box<dyn Error>> {
        plugin("disable")
    }
    /// Enabled-only plugins retain ordered profile names.
    #[test]
    fn enable_only() -> Result<(), Box<dyn Error>> {
        plugin("enable_only")
    }
    /// Dynamic modules are refused regardless of mode.
    #[test]
    fn module() -> Result<(), Box<dyn Error>> {
        for mode in [ParseMode::Compatible, ParseMode::Strict] {
            drop(
                Config::parse_with_mode(
                    "[plugins]\n clpreauth = {\n module = name:/never-load\n }\n",
                    mode,
                )
                .err()
                .ok_or("module accepted")?,
            );
        }
        Ok(())
    }

    /// Empty and populated server-only sections construct production diagnostics.
    #[test]
    fn server_sections() -> Result<(), Box<dyn Error>> {
        for section in ["kdcdefaults", "dbmodules", "logging"] {
            for body in ["", "option = value"] {
                let config = Config::parse(&format!("[{section}]\n {body}\n"))?;
                assert!(config.diagnostics().iter().any(|item| matches!(item, ConfigDiagnostic::ServerOnly { section: name } if *name == section)));
            }
        }
        Ok(())
    }

    /// Repeated app blocks and finals preserve first values at each precedence level.
    #[test]
    fn appdefault_composition() -> Result<(), Box<dyn Error>> {
        for section in ["[appdefaults]", "[appdefaults]*"] {
            let config = Config::parse(&format!(
                "{section}\n App = {{\n R = {{\n option* = first\n }}\n }}\n[appdefaults]\n App = {{\n R = {{\n option = second\n }}\n }}\n"
            ))?;
            assert_eq!(config.appdefault("App", "R", "option"), Some("first"));
        }
        Ok(())
    }

    /// Primary metadata selects its own list before the legacy master fallback.
    #[test]
    fn primary_kdc_precedence() -> Result<(), Box<dyn Error>> {
        for (extra, expected) in [("", "master"), ("primary_kdc = primary", "primary")] {
            let config = Config::parse(&format!(
                "[realms]\n R = {{\n master_kdc = master\n {extra}\n }}\n"
            ))?;
            assert_eq!(config.realm("R").ok_or("realm")?.primary_kdc, [expected]);
        }
        Ok(())
    }

    /// Plugin controls cannot silently disable the existing timestamp mechanism.
    #[test]
    fn restrictive_preauth_plugins() -> Result<(), Box<dyn Error>> {
        use rskrb5_ng::error::Config as Failure;
        for assignment in ["disable = encrypted_timestamp", "enable_only = pkinit"] {
            let failure =
                Config::parse(&format!("[plugins]\n clpreauth = {{\n {assignment}\n }}\n"))
                    .err()
                    .ok_or("preauth policy ignored")?;
            assert!(matches!(
                failure,
                Failure::NotYetEffective {
                    relation: _,
                    package: "plan 2 WP-16"
                }
            ));
        }
        Ok(())
    }

    /// The timestamp-plugin refusal is decided at its own entry, before later plugin entries.
    #[test]
    fn restrictive_preauth_plugin_named_before_later_entries() -> Result<(), Box<dyn Error>> {
        use rskrb5_ng::error::Config as Failure;
        for (assignment, relation) in [
            ("disable = encrypted_timestamp", "disable"),
            ("enable_only = pkinit", "enable_only"),
        ] {
            // Given a clpreauth restriction and a later-sorted malformed plugin entry.
            let input = format!(
                "[plugins]\n clpreauth = {{\n {assignment}\n }}\n interface = {{\n disable = \"two modules\"\n }}\n"
            );
            // When the profile is parsed.
            let failure = Config::parse(&input)
                .err()
                .ok_or("preauth policy ignored")?;
            // Then the restriction is refused, not the later malformed entry.
            assert!(
                matches!(
                    failure,
                    Failure::NotYetEffective {
                        relation: named,
                        package: "plan 2 WP-16"
                    } if named == relation
                ),
                "{failure:?}"
            );
        }
        Ok(())
    }

    /// Nonempty typed subtrees round-trip through serde without losing path keys.
    #[cfg(feature = "serde")]
    #[test]
    fn section_serde_roundtrip() -> Result<(), Box<dyn Error>> {
        for section in [
            "[appdefaults]\n App = {\n R = {\n value = original\n }\n }\n",
            "[capaths]\n A = {\n B = C\n }\n",
        ] {
            let config = Config::parse(section)?;
            let encoded = serde_json::to_string(&config)?;
            let decoded: Config = serde_json::from_str(&encoded)?;
            assert_eq!(decoded.applications, config.applications);
            assert_eq!(decoded.capaths, config.capaths);
        }
        Ok(())
    }
}
