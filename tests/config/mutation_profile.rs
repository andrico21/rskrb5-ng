//! Profile diagnostics and grammar regression contracts.

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
        error::Config as ConfigError,
    };

    /// Dynamic namespaces retain their exact recognized and unknown leaf shapes.
    #[test]
    fn profile_leaf_diagnostics_distinguish_namespaces() -> Result<(), Box<dyn Error>> {
        for (text, path, unknown) in [
            (
                "[libdefaults]\n no_addresses = true",
                vec!["libdefaults", "no_addresses"],
                false,
            ),
            (
                "[libdefaults]\n safe_checksum_type = 15",
                vec!["libdefaults", "safe_checksum_type"],
                false,
            ),
            (
                "[realms]\n R = {\n kdc = host\n }",
                vec!["realms", "R", "kdc"],
                false,
            ),
            (
                "[realms]\n R = {\n pkinit_identity = FILE:/identity\n }",
                vec!["realms", "R", "pkinit_identity"],
                false,
            ),
            (
                "[realms]\n R = {\n auth_to_local_names = {\n Alice = local\n }\n }",
                vec!["realms", "R", "auth_to_local_names", "Alice"],
                false,
            ),
            (
                "[domain_realm]\n host = R",
                vec!["domain_realm", "host"],
                false,
            ),
            (
                "[capaths]\n R = {\n S = .\n }",
                vec!["capaths", "R", "S"],
                false,
            ),
            (
                "[appdefaults]\n app = {\n option = value\n }",
                vec!["appdefaults", "app", "option"],
                false,
            ),
            (
                "[plugins]\n interface = {\n disable = module\n }",
                vec!["plugins", "interface", "disable"],
                false,
            ),
            (
                "[realms]\n R = {\n module_typo = value\n }",
                vec!["realms", "R", "module_typo"],
                true,
            ),
            (
                "[plugins]\n interface = {\n kdc = host\n }",
                vec!["plugins", "interface", "kdc"],
                true,
            ),
            (
                "[libdefaults]\n auth_to_local_names = {\n Alice = local\n }",
                vec!["libdefaults", "auth_to_local_names", "Alice"],
                true,
            ),
            (
                "[plugins]\n interface = {\n auth_to_local_names = {\n Alice = local\n }\n }",
                vec!["plugins", "interface", "auth_to_local_names", "Alice"],
                true,
            ),
            (
                "[realms]\n R = {\n other = {\n Alice = local\n }\n }",
                vec!["realms", "R", "other", "alice"],
                true,
            ),
        ] {
            let config = Config::parse(text)?;
            let expected = ConfigDiagnostic::UnknownRelation {
                path: path.into_iter().map(str::to_owned).collect(),
            };
            assert_eq!(config.diagnostics().contains(&expected), unknown, "{text}");
        }
        Ok(())
    }

    /// Empty subsection warnings distinguish application scopes from realm maps.
    #[test]
    fn empty_profile_scopes_preserve_namespace_rules() -> Result<(), Box<dyn Error>> {
        for (section, child, unknown) in [
            ("appdefaults", "option", false),
            ("realms", "auth_to_local_names", false),
            ("realms", "option", true),
            ("plugins", "auth_to_local_names", true),
            ("plugins", "option", true),
        ] {
            let text = format!("[{section}]\n R = {{\n {child} = {{\n }}\n }}");
            let config = Config::parse(&text)?;
            let expected = ConfigDiagnostic::UnknownRelation {
                path: vec![
                    section.to_owned(),
                    if section == "realms" { "R" } else { "r" }.to_owned(),
                    child.to_owned(),
                ],
            };
            assert_eq!(config.diagnostics().contains(&expected), unknown, "{text}");
        }
        Ok(())
    }

    /// Explicit local-name maps select the deferred consumer even without leaves.
    #[test]
    fn local_name_map_scopes_select_deferred_consumer() -> Result<(), Box<dyn Error>> {
        for contents in ["", "Alice = local", "Alice = local\nBob = other"] {
            let text = format!("[realms]\nR = {{\nauth_to_local_names = {{\n{contents}\n}}\n}}");
            let config = Config::parse(&text)?;
            assert_eq!(
                config.diagnostics(),
                &[ConfigDiagnostic::NotYetEffective {
                    relation: "auth_to_local_names",
                    package: "plan 2 WP-17",
                }]
            );
            assert!(matches!(
                Config::parse_with_mode(&text, ParseMode::Strict),
                Err(ConfigError::NotYetEffective {
                    relation: "auth_to_local_names",
                    package: "plan 2 WP-17"
                })
            ));
        }
        for text in [
            "[realms]\nR = {\n}",
            "[realms]*\nR = {\n}\n[realms]\nR = {\nauth_to_local_names = {\n}\n}",
        ] {
            assert!(
                Config::parse_with_mode(text, ParseMode::Strict)?
                    .diagnostics()
                    .is_empty(),
                "omitted or discarded map selected a consumer"
            );
        }
        Ok(())
    }

    /// Headers and assignments reject independently malformed components.
    #[test]
    fn profile_syntax_rejects_malformed_components() -> Result<(), Box<dyn Error>> {
        for text in [
            "[]",
            "[libdefaults]garbage",
            "default_realm = R",
            "[libdefaults]\n = value",
            "[realms]\n R = {",
            "[realms]\n R = {\n[libdefaults]",
        ] {
            let error = Config::parse(text)
                .err()
                .ok_or("malformed profile accepted")?;
            assert!(
                matches!(
                    error,
                    ConfigError::InvalidLine {
                        section: _,
                        line: _,
                        text: _
                    } | ConfigError::InvalidRealmsSection(_)
                ),
                "wrong syntax error: {error}"
            );
        }
        Ok(())
    }

    /// Realm names remain case-sensitive and finalized scopes reject later contributions.
    #[test]
    fn profile_preserves_case_order_and_finality() -> Result<(), Box<dyn Error>> {
        let config = Config::parse(
            "[realms]\n Mixed = {\n kdc = first\n }\n Mixed = {\n kdc = second\n }\n Other = {\n kdc = third\n }\n[libdefaults]*\n default_realm = Mixed\n[libdefaults]\n default_realm = Other\n[domain_realm]\n host = Mixed",
        )?;
        assert_eq!(
            config
                .realms
                .iter()
                .map(|realm| realm.name.as_str())
                .collect::<Vec<_>>(),
            vec!["Mixed", "Other"]
        );
        assert_eq!(
            config.realm("Mixed").ok_or("mixed realm missing")?.kdc,
            vec!["first:88", "second:88"]
        );
        assert_eq!(config.libdefaults.default_realm, "Mixed");
        assert_eq!(config.resolve_realm("host"), Some("Mixed"));
        Ok(())
    }

    /// Quoted comment characters and adjacent hashes are values, not comments.
    #[test]
    fn profile_comments_respect_quotes_and_whitespace() -> Result<(), Box<dyn Error>> {
        for (value, expected) in [
            ("\"R#; value\" # comment", "R#; value"),
            ("R#part", "R#part"),
            ("R;part", "R;part"),
            ("R ; comment", "R"),
        ] {
            let config = Config::parse(&format!("[libdefaults]\r\n default_realm = {value}\r\n"))?;
            assert_eq!(config.libdefaults.default_realm, expected);
        }
        Ok(())
    }

    /// Ordinary realm relations retain lowercased keys without lowercasing realm names.
    #[test]
    fn realm_relation_keys_are_case_insensitive() -> Result<(), Box<dyn Error>> {
        let config =
            Config::parse("[realms]\n Mixed = {\n KDC = host\n }\n[domain_realm]\n host = Mixed")?;
        assert_eq!(
            config.realm("Mixed").ok_or("realm missing")?.kdc,
            vec!["host:88"]
        );
        Ok(())
    }

    /// Unknown scopes accept eight nested edges and reject the ninth.
    #[test]
    fn profile_nesting_limit_is_inclusive() -> Result<(), Box<dyn Error>> {
        for depth in [8_usize, 9] {
            let text = format!(
                "[unknown]\n{}leaf = value\n{}",
                "group = {\n".repeat(depth),
                "}\n".repeat(depth)
            );
            let result = Config::parse(&text);
            if depth == 8 {
                assert_eq!(result?.diagnostics().len(), 1);
            } else {
                let error = result.err().ok_or("excess nesting accepted")?;
                assert!(
                    matches!(error, ConfigError::IncludeTooDeep { depth: 9, limit: 8 }),
                    "wrong nesting error: {error}"
                );
            }
        }
        Ok(())
    }

    /// Application-defined names cannot activate unrelated libdefaults classification.
    #[test]
    fn domain_mapping_names_do_not_select_libdefaults() -> Result<(), Box<dyn Error>> {
        let config = Config::parse("[domain_realm]\n rdns = EXAMPLE")?;
        assert_eq!(config.resolve_realm("rdns"), Some("EXAMPLE"));
        assert!(
            config.diagnostics().is_empty(),
            "domain key classified as libdefaults"
        );
        Ok(())
    }

    /// Unexpected leaf depths cannot borrow dynamic namespace permissions.
    #[test]
    fn unknown_leaf_shapes_are_not_plugin_or_domain_maps() -> Result<(), Box<dyn Error>> {
        for (text, path) in [
            (
                "[realms]\n default_realm = R",
                vec!["realms", "default_realm"],
            ),
            (
                "[domain_realm]\n group = {\n disable = value\n }",
                vec!["domain_realm", "group", "disable"],
            ),
        ] {
            let config = Config::parse(text)?;
            assert!(
                config
                    .diagnostics()
                    .contains(&ConfigDiagnostic::UnknownRelation {
                        path: path.into_iter().map(str::to_owned).collect()
                    }),
                "unexpected leaf shape accepted: {text}"
            );
        }
        Ok(())
    }
}
