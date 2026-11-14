//! Section headers and relation names match case-sensitively like MIT's `strcmp`.

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
        config::{Config, ConfigDiagnostic, ParseMode, Toggle},
        error::Config as Failure,
    };

    /// Compatible mode reports `wanted` once and Strict mode fails with its error.
    fn ignored(text: &str, wanted: &ConfigDiagnostic) -> Result<Config, Box<dyn Error>> {
        let config = Config::parse_with_mode(text, ParseMode::Compatible)?;
        assert!(
            config.diagnostics().contains(wanted),
            "{text}: {:?}",
            config.diagnostics()
        );
        let failure = Config::parse_with_mode(text, ParseMode::Strict)
            .err()
            .ok_or("strict accepted a wrongly cased name")?;
        let matched = match (wanted, &failure) {
            (
                ConfigDiagnostic::UnknownSection { section: want },
                Failure::UnknownSection { section },
            ) => want == section,
            (
                ConfigDiagnostic::UnknownRelation { path: want },
                Failure::UnknownRelation { path },
            ) => want == path,
            _ => false,
        };
        assert!(matched, "{text}: {failure:?}");
        Ok(config)
    }

    /// `[LIBDEFAULTS] allow_rc4 = true` does not enable RC4: MIT never reads that section.
    #[test]
    fn upper_libdefaults_header_is_not_honoured() -> Result<(), Box<dyn Error>> {
        for header in ["LIBDEFAULTS", "LibDefaults"] {
            let text = format!("[{header}]\n allow_rc4 = true\n default_realm = WRONG.TEST\n");
            let config = ignored(
                &text,
                &ConfigDiagnostic::UnknownSection {
                    section: header.to_owned(),
                },
            )?;
            assert_eq!(config.libdefaults.allow_rc4, Toggle::Disabled, "{text}");
            assert_eq!(config.libdefaults.default_realm, "", "{text}");
        }
        Ok(())
    }

    /// `[libdefaults] ALLOW_RC4 = true` does not enable RC4: MIT never reads that relation.
    #[test]
    fn upper_libdefaults_relation_is_not_honoured() -> Result<(), Box<dyn Error>> {
        for name in ["ALLOW_RC4", "Allow_Rc4"] {
            let text = format!("[libdefaults]\n {name} = true\n");
            let config = ignored(
                &text,
                &ConfigDiagnostic::UnknownRelation {
                    path: vec!["libdefaults".to_owned(), name.to_owned()],
                },
            )?;
            assert_eq!(config.libdefaults.allow_rc4, Toggle::Disabled, "{text}");
        }
        Ok(())
    }

    /// `[Realms]` and a wrongly cased `kdc` configure no KDC.
    #[test]
    fn realms_header_and_relation_are_case_sensitive() -> Result<(), Box<dyn Error>> {
        let config = ignored(
            "[Realms]\n R = {\n kdc = h:88\n }\n",
            &ConfigDiagnostic::UnknownSection {
                section: "Realms".to_owned(),
            },
        )?;
        assert!(config.realm("R").is_none());
        let cased = ignored(
            "[realms]\n R = {\n KDC = h:88\n }\n",
            &ConfigDiagnostic::UnknownRelation {
                path: vec!["realms".to_owned(), "R".to_owned(), "KDC".to_owned()],
            },
        )?;
        assert_eq!(cased.realm("R").ok_or("realm")?.kdc, Vec::<String>::new());
        Ok(())
    }

    /// `[Plugins]` is not the plugins section, so its fail-closed control is never read.
    #[test]
    fn plugins_header_is_case_sensitive() -> Result<(), Box<dyn Error>> {
        for header in ["Plugins", "PLUGINS"] {
            let text = format!("[{header}]\nclpreauth = {{\n disable = encrypted_timestamp\n}}\n");
            let config = ignored(
                &text,
                &ConfigDiagnostic::UnknownSection {
                    section: header.to_owned(),
                },
            )?;
            assert!(config.plugins.is_empty(), "{text}");
        }
        Ok(())
    }

    /// A `[domain_realm]` key with an upper-case letter never matches MIT's folded host.
    #[test]
    fn upper_domain_realm_key_never_matches() -> Result<(), Box<dyn Error>> {
        let config = ignored(
            "[domain_realm]\n .EXAMPLE.TEST = WRONG.TEST\n",
            &ConfigDiagnostic::UnknownRelation {
                path: vec!["domain_realm".to_owned(), ".EXAMPLE.TEST".to_owned()],
            },
        )?;
        assert!(config.domain_realm.is_empty(), "{:?}", config.domain_realm);
        assert_eq!(config.resolve_realm("host.example.test"), None);
        let exact = Config::parse("[domain_realm]\n .example.test = RIGHT.TEST\n")?;
        assert_eq!(exact.resolve_realm("HOST.Example.TEST"), Some("RIGHT.TEST"));
        Ok(())
    }
}
