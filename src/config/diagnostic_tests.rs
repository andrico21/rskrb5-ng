//! Exhaustive diagnostic promotion tests, including kinds masked by earlier failures.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::{error::Error, slice};

    use super::super::{ConfigDiagnostic, Error as Failure, ParseMode, realm_values};

    /// The discriminant of a diagnostic, matched exhaustively so that a new
    /// kind cannot be added without a case below.
    const fn kind(diagnostic: &ConfigDiagnostic) -> usize {
        match diagnostic {
            ConfigDiagnostic::UnknownSection { section: _ } => 0,
            ConfigDiagnostic::UnknownRelation { path: _ } => 1,
            ConfigDiagnostic::ServerOnly { section: _ } => 2,
            ConfigDiagnostic::FeatureUnavailable {
                relation: _,
                feature: _,
            } => 3,
            ConfigDiagnostic::OutOfScope {
                relation: _,
                decision: _,
            } => 4,
            ConfigDiagnostic::IgnoredPreauthType { id: _ } => 5,
            ConfigDiagnostic::UnsupportedSecureEnctype { token: _, until: _ } => 6,
        }
    }

    /// Every diagnostic discriminant is tested through production reporting in both modes.
    #[test]
    fn every_diagnostic_promotes_to_error() -> Result<(), Box<dyn Error>> {
        let cases = [
            ConfigDiagnostic::UnknownSection {
                section: "unknown".to_owned(),
            },
            ConfigDiagnostic::UnknownRelation {
                path: vec!["libdefaults".to_owned(), "typo".to_owned()],
            },
            ConfigDiagnostic::FeatureUnavailable {
                relation: "spake_preauth_groups",
                feature: "spake",
            },
            ConfigDiagnostic::UnsupportedSecureEnctype {
                token: "camellia".to_owned(),
                until: "the `camellia` Cargo feature is enabled",
            },
            ConfigDiagnostic::OutOfScope {
                relation: "plugin_base_dir",
                decision: "D1/D3",
            },
            ConfigDiagnostic::ServerOnly { section: "logging" },
            ConfigDiagnostic::IgnoredPreauthType { id: 14_i32 },
        ];
        let mut kinds: Vec<usize> = cases.iter().map(kind).collect();
        kinds.sort_unstable();
        assert_eq!(kinds, [0, 1, 2, 3, 4, 5, 6], "one case per diagnostic kind");
        for diagnostic in cases {
            let mut output = Vec::new();
            realm_values::report(diagnostic.clone(), ParseMode::Compatible, &mut output)?;
            assert_eq!(output.as_slice(), slice::from_ref(&diagnostic));
            let error = realm_values::report(diagnostic.clone(), ParseMode::Strict, &mut output)
                .err()
                .ok_or("diagnostic escaped strict mode")?;
            match (diagnostic, error) {
                (
                    ConfigDiagnostic::UnknownSection { section: wanted },
                    Failure::UnknownSection { section },
                ) => assert_eq!(section, wanted),
                (
                    ConfigDiagnostic::UnknownRelation { path: wanted },
                    Failure::UnknownRelation { path },
                ) => assert_eq!(path, wanted),
                (
                    ConfigDiagnostic::FeatureUnavailable {
                        relation: wanted,
                        feature: leaf,
                    },
                    Failure::FeatureUnavailable { relation, feature },
                ) => assert_eq!((relation, feature), (wanted, leaf)),
                (
                    ConfigDiagnostic::UnsupportedSecureEnctype {
                        token: wanted,
                        until: _,
                    },
                    Failure::UnsupportedSecureEnctype { token, until: _ },
                ) => assert_eq!(token, wanted),
                (
                    ConfigDiagnostic::OutOfScope {
                        relation: wanted,
                        decision: reason,
                    },
                    Failure::OutOfScope { relation, decision },
                ) => assert_eq!((relation, decision), (wanted, reason)),
                (
                    ConfigDiagnostic::ServerOnly { section: wanted },
                    Failure::ServerOnly { section },
                ) => assert_eq!(section, wanted),
                (
                    ConfigDiagnostic::IgnoredPreauthType { id: wanted },
                    Failure::IgnoredPreauthType { id },
                ) => assert_eq!(id, wanted),
                _ => return Err("wrong strict error kind".into()),
            }
            assert_eq!(output.len(), 1, "strict failure must not append");
        }
        Ok(())
    }
}
