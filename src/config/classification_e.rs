//! Consumer classification review of all three relation catalogues.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::error::Error;

    use super::super::{
        Config, ConfigDiagnostic, ParseMode, libdefaults::relations::RELATIONS,
        realm_relations::REALM_RELATIONS, section_decode::SECTION_RELATIONS,
    };

    /// Relations whose semantics an owner decision excludes: section, name,
    /// a value, and the decision both parse modes report.
    const PERMANENT: [(&str, &str, &str, &str); 6] = [
        (
            "libdefaults",
            "plugin_base_dir",
            "%{LIBDIR}/unloaded",
            "D1/D3",
        ),
        ("realms", "default_domain", "example.test", "D2"),
        ("realms", "pkinit_identity", "FILE:/identity", "D1"),
        ("realms", "pkinit_allow_upn", "false", "D1"),
        ("realms", "pkinit_indicator", "strong", "D1"),
        ("realms", "pkinit_require_freshness", "true", "D1"),
    ];

    /// Render actual profile inputs, not direct calls to classification predicates.
    fn profile(section: &str, name: &str, value: &str) -> String {
        if section == "realms" {
            format!("[realms]\n R = {{\n {name} = {value}\n }}\n")
        } else {
            format!("[libdefaults]\n {name} = {value}\n")
        }
    }

    /// Every catalogue row an owner decision excludes reports that decision in
    /// Compatible mode and is refused with it in Strict mode.
    #[test]
    fn every_permanent_scope_row_is_reviewed() -> Result<(), Box<dyn Error>> {
        let rows: Vec<&str> = RELATIONS
            .iter()
            .chain(REALM_RELATIONS.iter())
            .filter(|row| row.3.starts_with(super::super::diagnostic::OUT_OF_SCOPE))
            .map(|row| row.0)
            .collect();
        let reviewed: Vec<&str> = PERMANENT.iter().map(|case| case.1).collect();
        assert_eq!(rows, reviewed);
        for (section, name, value, decision) in PERMANENT {
            let text = profile(section, name, value);
            let config = Config::parse(&text)?;
            assert!(
                config
                    .diagnostics()
                    .contains(&ConfigDiagnostic::OutOfScope {
                        relation: name,
                        decision
                    }),
                "{name}: {:?}",
                config.diagnostics()
            );
            let strict = Config::parse_with_mode(&text, ParseMode::Strict);
            assert!(
                matches!(strict, Err(super::super::Error::OutOfScope { relation, decision: reason }) if relation == name && reason == decision),
                "{name}: {strict:?}"
            );
        }
        Ok(())
    }

    /// No row of the three catalogues defers its relation to a later change.
    ///
    /// Every consumer is effective (with its leaf, when it names one) or an
    /// owner decision excludes the relation (`every_permanent_scope_row_is_reviewed`).
    #[test]
    fn no_catalogue_row_is_deferred() {
        assert_eq!(
            RELATIONS
                .iter()
                .chain(REALM_RELATIONS.iter())
                .chain(SECTION_RELATIONS.iter())
                .filter(|row| row.3.is_empty() || row.3.starts_with("plan "))
                .map(|row| row.0)
                .collect::<Vec<&str>>(),
            Vec::<&str>::new()
        );
    }
}
