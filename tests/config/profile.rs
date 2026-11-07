//! Profile composition regression cases.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::{
        error::Error,
        sync::atomic::{AtomicU64, Ordering},
    };
    use std::{
        env, fs,
        path::{Path, PathBuf},
        process,
    };

    use rskrb5_ng::{Config, config::ParseMode, error::Config as ConfigError};

    /// Process-local sequence avoids clock-resolution assumptions.
    static NEXT: AtomicU64 = AtomicU64::new(0);

    /// Escape decoding cannot hide permanently rejected selectors in discarded scopes.
    #[test]
    fn discarded_escaped_protocols_are_rejected() {
        for mode in [ParseMode::Compatible, ParseMode::Strict] {
            for input in [
                "[libdefaults]*\n[libdefaults]\npkinit_key_exchange = \"r\\sa\"\n",
                "[unknown]\nkpasswd_protocol = \"clear\\text\"\n",
            ] {
                assert!(matches!(
                    Config::parse_with_mode(input, mode),
                    Err(ConfigError::Policy(_))
                ));
            }
        }
    }

    /// MIT permits an opening brace on the line after an empty assignment.
    #[test]
    fn next_line_braces_preserve_scopes() -> Result<(), Box<dyn Error>> {
        let config = Config::parse(
            "[realms]\nR* =\n{\nkdc = first\n}\nR = {\nkdc = second\n}\n[appdefaults]\napp =\n{\noption = value\n}\n[plugins]\npreauth =\n{\nenable_only = custom\n}\n",
        )?;
        assert_eq!(config.configured_kdcs("R")?, ["first:88"]);
        assert_eq!(config.appdefault("app", "R", "option"), Some("value"));
        assert!(
            Config::parse("[realms]\nR =\nkdc = first\n").is_err(),
            "missing brace rejected"
        );
        Ok(())
    }

    /// Quoted endpoint stars are literal; only profile syntax determines finality.
    #[test]
    fn quoted_endpoint_stars_remain_literal() -> Result<(), Box<dyn Error>> {
        for key in ["kdc", "admin_server", "master_kdc", "kpasswd_server"] {
            let config = Config::parse(&format!(
                "[realms]\nR = {{\n{key} = \"first*\"\n{key} = second\n}}\n"
            ))?;
            let realm = config.realms.first().ok_or("realm")?;
            let (values, expected) = match key {
                "kdc" => (&realm.kdc, vec!["first*:88", "second:88"]),
                "admin_server" => (&realm.admin_server, vec!["first*", "second"]),
                "master_kdc" => (&realm.master_kdc, vec!["first*", "second"]),
                _ => (&realm.kpasswd_server, vec!["first*", "second"]),
            };
            assert_eq!(values, &expected);
        }
        Ok(())
    }

    /// MIT quoted strings preserve significant edge whitespace after escape decoding.
    #[test]
    fn quoted_values_preserve_edge_whitespace() -> Result<(), Box<dyn Error>> {
        let config = Config::parse(
            "[appdefaults]\n option = \"  padded  \"\n[libdefaults]\n default_keytab_name = \"\\tFILE:/key\\n\"\n default_realm =  EXAMPLE  \n",
        )?;
        assert_eq!(
            config.appdefault("app", "REALM", "option"),
            Some("  padded  ")
        );
        assert_eq!(config.libdefaults.default_keytab_name, "\tFILE:/key\n");
        assert_eq!(config.libdefaults.default_realm, "EXAMPLE");
        Ok(())
    }

    /// Alias spellings share first-value and final-marker identity across files.
    #[test]
    fn address_aliases_share_profile_order() -> Result<(), Box<dyn Error>> {
        for (first, second) in [
            ("no_addresses", "noaddresses"),
            ("noaddresses", "no_addresses"),
        ] {
            for marker in ["", "*"] {
                let accepted = format!("[libdefaults]\n{first}{marker} = true\n{second} = false\n");
                assert!(
                    Config::parse(&accepted)?
                        .libdefaults
                        .no_addresses
                        .is_enabled()
                );
                let refused = format!("[libdefaults]\n{first}{marker} = false\n{second} = true\n");
                assert!(matches!(
                    Config::parse(&refused),
                    Err(ConfigError::NotYetEffective {
                        relation: _,
                        package: _
                    })
                ));
                let dir = Fixture::new()?;
                let one = dir.path().join("one");
                let two = dir.path().join("two");
                fs::write(&one, format!("[libdefaults]\n{first}{marker} = true\n"))?;
                fs::write(&two, format!("[libdefaults]\n{second} = false\n"))?;
                assert!(
                    Config::load_paths(&[one, two])?
                        .libdefaults
                        .no_addresses
                        .is_enabled()
                );
            }
        }
        Ok(())
    }

    /// Fixture directory owned by one test invocation.
    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> Result<Self, Box<dyn Error>> {
            let path = env::temp_dir().join(format!(
                "profile-{}-{}",
                process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&path)?;
            Ok(Self(path))
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap_or_default();
        }
    }

    /// Scalar lists and booleans select the first relation, not the last.
    #[test]
    fn first_values_win_within_file() -> Result<(), Box<dyn Error>> {
        // Given repeated scalar, boolean and list-valued scalar relations.
        let input = "[libdefaults]\n default_realm = FIRST\n default_realm = SECOND\n forwardable = false\n forwardable = true\n permitted_enctypes = aes128-cts\n permitted_enctypes = aes256-cts\n[domain_realm]\n .example = FIRST\n .example = SECOND\n";
        // When composing a single source.
        let config = Config::parse(input)?;
        // Then first relations determine the typed configuration.
        assert_eq!(config.libdefaults.default_realm, "FIRST");
        assert!(!config.libdefaults.forwardable.is_enabled());
        assert_eq!(config.libdefaults.permitted_enctype_ids(), [17_i32]);
        assert_eq!(config.resolve_realm("host.example"), Some("FIRST"));
        Ok(())
    }

    /// Final sections and both subsection spellings stop subsequent routes.
    #[test]
    fn section_and_subsection_finals_stop_routes() -> Result<(), Box<dyn Error>> {
        // Given all three MIT scope-final spellings.
        for first in [
            "[realms]*\n A = {\n kdc = first\n }\n",
            "[realms]\n A* = {\n kdc = first\n }\n",
            "[realms]\n A = {\n kdc = first\n }*\n",
        ] {
            // When later content repeats the finalized scope.
            let config = Config::parse(&format!("{first}[realms]\n A = {{\n kdc = later\n }}\n"))?;
            // Then no later route is admitted.
            assert_eq!(config.configured_kdcs("A")?, ["first:88"]);
        }
        Ok(())
    }

    /// Relation finals retain earlier values and the marked value only.
    #[test]
    fn relation_final_accumulates_until_marker() -> Result<(), Box<dyn Error>> {
        // Given an ordered multi-valued endpoint relation.
        let input = "[realms]\n A = {\n kdc = first\n kdc* = final\n kdc = later\n }\n";
        // When reading the final-marked relation.
        let config = Config::parse(input)?;
        // Then the marker does not replace previous values.
        assert_eq!(config.configured_kdcs("A")?, ["first:88", "final:88"]);
        Ok(())
    }

    /// Comment delimiters embedded in values and quotes are preserved.
    #[test]
    fn comments_preserve_rule_semicolon_and_quoted_markers() -> Result<(), Box<dyn Error>> {
        // Given a RULE-shaped scalar and a quoted value.
        let input = " ; comment\n[libdefaults]\n default_realm = RULE:[2:$1;$2] # inline\n default_keytab_name = \"FILE:/a # b; c\" ; inline\n";
        // When stripping comments outside quotes only after whitespace.
        let config = Config::parse(input)?;
        // Then punctuation remains part of each value.
        assert_eq!(config.libdefaults.default_realm, "RULE:[2:$1;$2]");
        assert_eq!(config.libdefaults.default_keytab_name, "FILE:/a # b; c");
        Ok(())
    }

    /// An included file cannot steal its parent's current section.
    #[test]
    fn includes_resume_parent_state() -> Result<(), Box<dyn Error>> {
        // Given a child that ends in a different section.
        let dir = Fixture::new()?;
        let child = dir.path().join("child.conf");
        fs::write(&child, "[domain_realm]\n .example = CHILD\n")?;
        let input = format!(
            "[libdefaults]\ninclude {}\ndefault_realm = PARENT\n",
            child.display()
        );
        // When including the independent source.
        let config = Config::parse(&input)?;
        // Then the parent resumes libdefaults.
        assert_eq!(config.libdefaults.default_realm, "PARENT");
        assert_eq!(config.resolve_realm("host.example"), Some("CHILD"));
        Ok(())
    }

    /// Unbalanced unknown sections cannot suppress include directives.
    #[test]
    fn stray_braces_are_rejected_per_file() -> Result<(), Box<dyn Error>> {
        // Given malformed unknown scopes followed by a valid file.
        let dir = Fixture::new()?;
        let first = dir.path().join("first.conf");
        let second = dir.path().join("second.conf");
        fs::write(&second, "[libdefaults]\n default_realm = SECOND\n")?;
        for malformed in ["[unknown]\n}\n", "[unknown]\n group = {\n"] {
            fs::write(&first, format!("{malformed}include {}\n", second.display()))?;
            // When loading independent files.
            let failure = Config::load_paths([&first, &second])
                .err()
                .ok_or("unbalanced source accepted")?;
            // Then a typed syntax error rejects the source, not a missing fragment.
            assert!(matches!(
                failure,
                ConfigError::InvalidLine {
                    section: _,
                    line: _,
                    text: _
                } | ConfigError::InvalidRealmsSection(_)
            ));
        }
        Ok(())
    }

    /// Literal braces in relation values are not structural braces.
    #[test]
    fn literal_braces_do_not_suppress_includes() -> Result<(), Box<dyn Error>> {
        // Given unmatched literal braces inside values.
        let dir = Fixture::new()?;
        let child = dir.path().join("child.conf");
        fs::write(&child, "[libdefaults]\n default_realm = CHILD\n")?;
        let input = format!(
            "[unknown]\n value = literal{{\ninclude {}\n",
            child.display()
        );
        // When loading a directive after the literal value.
        let config = Config::parse(&input)?;
        // Then the include still contributes its setting.
        assert_eq!(config.libdefaults.default_realm, "CHILD");
        Ok(())
    }

    /// Directory path-list entries use the same filename filter and byte order.
    #[test]
    fn directory_sources_filter_and_accumulate_in_order() -> Result<(), Box<dyn Error>> {
        // Given eligible and ineligible directory entries in reverse creation order.
        let dir = Fixture::new()?;
        for name in ["z.conf", "b-name", "A_name", "odd.name.conf"] {
            fs::write(
                dir.path().join(name),
                format!("[realms]\n A = {{\n kdc = {name}\n }}\n"),
            )?;
        }
        for name in [".hidden.conf", "bad.bak", "bad~", "bad.name"] {
            fs::write(
                dir.path().join(name),
                "[libdefaults]\n forwardable = invalid\n",
            )?;
        }
        // When a directory is a top-level source.
        let config = Config::load_paths([dir.path()])?;
        // Then accepted names contribute in byte order.
        assert_eq!(
            config.configured_kdcs("A")?,
            ["A_name:88", "b-name:88", "odd.name.conf:88", "z.conf:88"]
        );
        Ok(())
    }

    /// The total byte cap also applies before parsing caller-provided root text.
    #[test]
    fn root_text_byte_budget_is_enforced() -> Result<(), Box<dyn Error>> {
        // Given a root larger than the total four-MiB limit.
        let input = format!("#{}", "x".repeat(4 * 1024 * 1024));
        // When parsing without any include.
        let failure = Config::parse(&input)
            .err()
            .ok_or("oversize root accepted")?;
        // Then the shared typed budget error is returned.
        assert!(matches!(
            failure,
            ConfigError::IncludeTooLarge {
                bytes: 0x0040_0001,
                limit: 0x0040_0000
            }
        ));
        Ok(())
    }
}
