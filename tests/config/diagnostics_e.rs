//! Complete diagnostic visibility and strict-mode regression contracts.

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
        config::{Config, ParseMode},
        crypto::camellia,
    };

    /// Unknown headers and paths cannot disappear, including empty subsections.
    #[test]
    fn unknown_configuration_is_visible() -> Result<(), Box<dyn Error>> {
        for input in [
            "[mystery]\n",
            "[libdefaults]\n typo = false\n",
            "[realms]\n R = {\n typo = value\n }\n",
            "[plugins]\n clpreauth = {\n typo = value\n }\n",
            "[libdefaults]\n typo = {\n }\n",
        ] {
            // Given an unrecognized path, when parsed, then diagnose or reject strictly.
            let config = Config::parse(input)?;
            assert!(
                !config.diagnostics().is_empty(),
                "unknown input must be visible"
            );
            drop(
                Config::parse_with_mode(input, ParseMode::Strict)
                    .err()
                    .ok_or("strict accepted unknown input")?,
            );
        }
        Ok(())
    }

    /// Every diagnostic currently emitted by real configs must fail Strict mode.
    #[test]
    fn every_real_diagnostic_is_strict() -> Result<(), Box<dyn Error>> {
        for input in [
            "[unknown]\n",
            "[libdefaults]\n typo = true\n",
            "[libdefaults]\n ignore_acceptor_hostname = false\n",
            "[libdefaults]\n permitted_enctypes = aes camellia\n",
            "[logging]\n",
            "[libdefaults]\n preferred_preauth_types = 14,15\n",
        ] {
            if camellia::AVAILABLE && input.contains("camellia") {
                // With the leaf the name is supported, so it emits no diagnostic.
                continue;
            }
            drop(
                Config::parse_with_mode(input, ParseMode::Strict)
                    .err()
                    .ok_or("diagnostic accepted in strict mode")?,
            );
        }
        Ok(())
    }

    /// Unknown paths retain context and discarded finals do not produce warnings.
    #[test]
    fn unknown_paths_preserve_scope_and_finality() -> Result<(), Box<dyn Error>> {
        use rskrb5_ng::config::ConfigDiagnostic;
        let config = Config::parse(
            "[realms]\n R = {\n typo = false\n }\n[libdefaults]*\n clockskew = 20\n[libdefaults]\n ignored_typo = false\n[unknown]\n key = value\n",
        )?;
        assert!(
            config
                .diagnostics()
                .contains(&ConfigDiagnostic::UnknownRelation {
                    path: vec!["realms".to_owned(), "R".to_owned(), "typo".to_owned()]
                })
        );
        assert!(
            config
                .diagnostics()
                .contains(&ConfigDiagnostic::UnknownSection {
                    section: "unknown".to_owned()
                })
        );
        assert_eq!(
            config.diagnostics().len(),
            2,
            "unknown section gives one diagnostic, finalized input none"
        );
        Ok(())
    }

    /// Strict draft-9 errors occur before the separate deferred-preference diagnostic.
    #[test]
    fn draft9_diagnostics_are_not_hidden() -> Result<(), Box<dyn Error>> {
        use rskrb5_ng::{config::ConfigDiagnostic, error::Config as Failure};
        for id in [14_i32, 15_i32] {
            let text = format!("[libdefaults]\n preferred_preauth_types = {id}\n");
            let config = Config::parse(&text)?;
            assert!(
                config
                    .diagnostics()
                    .contains(&ConfigDiagnostic::IgnoredPreauthType { id })
            );
            let error = Config::parse_with_mode(&text, ParseMode::Strict)
                .err()
                .ok_or("strict ignored preference")?;
            assert!(matches!(error, Failure::IgnoredPreauthType { id: actual } if actual == id));
        }
        Ok(())
    }
}
