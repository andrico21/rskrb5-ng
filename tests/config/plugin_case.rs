//! `[plugins]` interface and control names are case-sensitive like MIT's `strcmp`.

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
        config::{Config, ConfigDiagnostic, ParseMode},
        error::Config as Failure,
    };

    /// A wrongly cased interface name is an interface without a consumer, not `clpreauth`.
    #[test]
    fn upper_interface_is_not_clpreauth() -> Result<(), Box<dyn Error>> {
        // Given MIT-ignored spellings of the client preauthentication interface.
        for (interface, text) in [
            (
                "CLPREAUTH",
                "[plugins]\nCLPREAUTH = {\n disable = encrypted_timestamp\n}\n",
            ),
            (
                "ClPreAuth",
                "[plugins]\nClPreAuth = {\n enable_only = pkinit\n}\n",
            ),
        ] {
            // When the profile is parsed.
            let config = Config::parse(text)?;
            // Then no client restriction applies and the name is stored as written.
            assert!(!config.plugins.contains_key("clpreauth"), "{text}");
            assert!(config.plugins.contains_key(interface), "{text}");
        }
        Ok(())
    }

    /// Strict mode treats the wrongly cased interface like any interface other than `clpreauth`.
    #[test]
    fn upper_interface_strict_matches_other_interfaces() -> Result<(), Box<dyn Error>> {
        for interface in ["CLPREAUTH", "ccselect"] {
            let text = format!("[plugins]\n{interface} = {{\n disable = encrypted_timestamp\n}}\n");
            let failure = Config::parse_with_mode(&text, ParseMode::Strict)
                .err()
                .ok_or("strict accepted a plugin control")?;
            assert!(
                matches!(
                    failure,
                    Failure::NotYetEffective {
                        relation: "disable",
                        package: _
                    }
                ),
                "{interface}: {failure:?}"
            );
        }
        Ok(())
    }

    /// The correctly spelled interface keeps its fail-closed rule in both modes.
    #[test]
    fn lower_interface_still_fails_closed() -> Result<(), Box<dyn Error>> {
        for mode in [ParseMode::Compatible, ParseMode::Strict] {
            let failure = Config::parse_with_mode(
                "[plugins]\nclpreauth = {\n disable = encrypted_timestamp\n}\n",
                mode,
            )
            .err()
            .ok_or("clpreauth restriction ignored")?;
            assert!(
                matches!(
                    failure,
                    Failure::NotYetEffective {
                        relation: "disable",
                        package: _
                    }
                ),
                "{failure:?}"
            );
        }
        Ok(())
    }

    /// A wrongly cased control name is an unknown relation and applies nothing.
    #[test]
    fn upper_control_is_unknown_relation() -> Result<(), Box<dyn Error>> {
        for (interface, control) in [
            ("kdcpreauth", "DISABLE"),
            ("kdcpreauth", "Enable_Only"),
            ("clpreauth", "ENABLE_ONLY"),
        ] {
            let text = format!("[plugins]\n{interface} = {{\n {control} = pkinit\n}}\n");
            // Compatible mode records the unknown path and applies nothing.
            let config = Config::parse(&text)?;
            assert!(config.plugins.is_empty(), "{text}");
            assert!(
                config
                    .diagnostics()
                    .contains(&ConfigDiagnostic::UnknownRelation {
                        path: vec![
                            "plugins".to_owned(),
                            interface.to_owned(),
                            control.to_owned()
                        ]
                    }),
                "{text}"
            );
            // Strict mode rejects the unknown path.
            let failure = Config::parse_with_mode(&text, ParseMode::Strict)
                .err()
                .ok_or("strict accepted an unknown control")?;
            assert!(
                matches!(failure, Failure::UnknownRelation { path: _ }),
                "{text}: {failure:?}"
            );
        }
        Ok(())
    }

    /// MIT never reads `MODULE`, so it is not a dynamic-module descriptor under `[plugins]`.
    #[test]
    fn upper_module_is_unknown_relation() -> Result<(), Box<dyn Error>> {
        let text = "[plugins]\nclpreauth = {\n MODULE = x:/never/load.so\n}\n";
        let config = Config::parse(text)?;
        assert!(config.plugins.is_empty(), "{text}");
        assert!(
            config
                .diagnostics()
                .contains(&ConfigDiagnostic::UnknownRelation {
                    path: vec![
                        "plugins".to_owned(),
                        "clpreauth".to_owned(),
                        "MODULE".to_owned()
                    ]
                })
        );
        Ok(())
    }

    /// The reader's include pre-scan applies the same rule as the parser.
    #[test]
    fn reader_upper_module_is_unknown_relation() -> Result<(), Box<dyn Error>> {
        let text = "[plugins]\nclpreauth = {\n MODULE = x:/never/load.so\n}\n";
        let config = Config::from_reader(text.as_bytes())?;
        assert!(config.plugins.is_empty(), "{text}");
        assert!(
            config
                .diagnostics()
                .iter()
                .any(|item| matches!(item, ConfigDiagnostic::UnknownRelation { path: _ }))
        );
        // The exact spelling is still a refused dynamic module.
        let failure = Config::from_reader(text.to_ascii_lowercase().as_bytes())
            .err()
            .ok_or("dynamic module accepted")?;
        assert!(matches!(failure, Failure::UnsupportedDynamicModule));
        Ok(())
    }

    /// The header stays case-insensitive: `[Plugins]` is the plugins section.
    #[test]
    fn mixed_case_header_is_plugins_section() -> Result<(), Box<dyn Error>> {
        for header in ["[Plugins]", "[PLUGINS]"] {
            let failure = Config::parse(&format!(
                "{header}\nclpreauth = {{\n disable = encrypted_timestamp\n}}\n"
            ))
            .err()
            .ok_or("header case hid the restriction")?;
            assert!(
                matches!(
                    failure,
                    Failure::NotYetEffective {
                        relation: "disable",
                        package: _
                    }
                ),
                "{header}: {failure:?}"
            );
        }
        Ok(())
    }

    /// The other sections keep their key case rules, and `module` stays refused there in any case.
    #[test]
    fn other_sections_unchanged() -> Result<(), Box<dyn Error>> {
        let folded =
            Config::parse("[libdefaults]\n CLOCKSKEW = 77\n[realms]\n R = {\n KDC = h\n }\n")?;
        assert_eq!(folded.libdefaults.clockskew.as_secs(), 77);
        assert_eq!(folded.realm("R").ok_or("realm")?.kdc, ["h:88"]);
        let kept =
            Config::parse("[appdefaults]\n Option = value\n[capaths]\n A = {\n B = C\n }\n")?;
        assert_eq!(kept.appdefault("x", "y", "Option"), Some("value"));
        assert_eq!(kept.appdefault("x", "y", "option"), None);
        for text in [
            "[libdefaults]\nMODULE = /never/load.so\n",
            "[realms]\nR = {\nMODULE = /never/load.so\n}\n",
            "[unknown]\nModule = /never/load.so\n",
            // No spaces around `=` and no `=` at all: each spelling reaches a different guard.
            "[libdefaults]\nMODULE=/never/load.so\n",
            "[libdefaults]\nMODULE=\n",
            "[unknown]\nModule=/never/load.so\n",
            "[libdefaults]\nMODULE foo\n",
            "[libdefaults]\nModule\n",
            "[realms]\nR = {\nMODULE foo\n}\n",
        ] {
            let failure = Config::parse(text).err().ok_or("dynamic module accepted")?;
            assert!(
                matches!(failure, Failure::UnsupportedDynamicModule),
                "{text}"
            );
            // The reader runs the same include pre-scan and the same relation guard.
            let read_failure = Config::from_reader(text.as_bytes())
                .err()
                .ok_or("dynamic module accepted by the reader")?;
            assert!(
                matches!(read_failure, Failure::UnsupportedDynamicModule),
                "reader: {text}"
            );
        }
        Ok(())
    }
}
