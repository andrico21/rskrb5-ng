//! Plan QA configurations pass through the public profile parser.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::error::Error;
    use std::path::Path;

    use rskrb5_ng::{
        config::{Config, ConfigDiagnostic, ParseMode},
        crypto::camellia,
    };

    /// Number of secure Camellia names the fixtures list that the build skips.
    const SKIPPED_CAMELLIA: usize = if camellia::AVAILABLE { 0 } else { 2 };

    /// Host profile plus a Fedora-shaped include preserves usable AES policy.
    #[test]
    fn host_profile_and_crypto_policy_are_compatible() -> Result<(), Box<dyn Error>> {
        let directory =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/profile/host-e.d");
        let input = include_str!("../fixtures/profile/host-e.conf")
            .replace("@INCLUDEDIR@", &directory.to_string_lossy());
        let config = Config::parse(&input)?;
        assert_eq!(config.libdefaults.default_realm, "0.0.0.0");
        let permitted: &[i32] = if camellia::AVAILABLE {
            &[20, 19, 18, 17, 26, 25]
        } else {
            &[20, 19, 18, 17]
        };
        assert_eq!(config.libdefaults.permitted_enctype_ids(), permitted);
        assert_eq!(config.configured_kdcs("ATHENA.MIT.EDU")?.len(), 3);
        assert!(
            config
                .diagnostics()
                .contains(&ConfigDiagnostic::OutOfScope {
                    relation: "default_domain",
                    decision: "D2"
                })
        );
        // Every other relation of the host profile (`rdns`, `ccache_type` among
        // them) is effective: only these three kinds of diagnostic remain.
        assert!(
            config.diagnostics().iter().all(|item| matches!(
                item,
                ConfigDiagnostic::OutOfScope {
                    relation: "default_domain",
                    decision: "D2"
                } | ConfigDiagnostic::UnsupportedSecureEnctype { token: _, until: _ }
            ) || matches!(item, ConfigDiagnostic::UnknownRelation { path } if path == &["libdefaults", "fcc-mit-ticketflags"])),
            "{:?}",
            config.diagnostics()
        );
        assert!(config.diagnostics().iter().any(|item| matches!(item, ConfigDiagnostic::UnknownRelation { path } if path == &["libdefaults", "fcc-mit-ticketflags"])));
        assert_eq!(
            config
                .diagnostics()
                .iter()
                .filter(|item| matches!(
                    item,
                    ConfigDiagnostic::UnsupportedSecureEnctype { token: _, until: _ }
                ))
                .count(),
            SKIPPED_CAMELLIA
        );
        drop(
            Config::parse_with_mode(&input, ParseMode::Strict)
                .err()
                .ok_or("strict accepted host diagnostics")?,
        );
        Ok(())
    }

    /// The independently loaded crypto-policy include reports only secure unsupported types.
    #[test]
    fn fedora_crypto_policy_has_only_diagnostics() -> Result<(), Box<dyn Error>> {
        let input = include_str!("../fixtures/profile/host-e.d/crypto-policies");
        let config = Config::parse(input)?;
        assert_eq!(config.diagnostics().len(), SKIPPED_CAMELLIA);
        assert!(config.diagnostics().iter().all(|item| matches!(
            item,
            ConfigDiagnostic::UnsupportedSecureEnctype { token: _, until: _ }
        )));
        let requested: &[i32] = if camellia::AVAILABLE {
            &[20, 19, 18, 17, 26, 25]
        } else {
            &[20, 19, 18, 17]
        };
        assert_eq!(config.libdefaults.default_tkt_enctype_ids(), requested);
        Ok(())
    }

    /// The plan's exact realm policy is effective (plan 2 todo 9): both modes admit
    /// it without a diagnostic, and the exchange engine honours it.
    #[test]
    fn plan_timestamp_qa_is_effective() -> Result<(), Box<dyn Error>> {
        for mode in [ParseMode::Compatible, ParseMode::Strict] {
            let config = Config::parse_with_mode(
                "[realms]\n TEST.RSKRB5 = {\n disable_encrypted_timestamp = true\n }\n",
                mode,
            )?;
            assert!(
                config.diagnostics().is_empty(),
                "{mode:?}: {:?}",
                config.diagnostics()
            );
        }
        Ok(())
    }
}
