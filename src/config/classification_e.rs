//! Exhaustive deferred-consumer boundary review against all three catalogues.

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

    /// Libdefaults: safe assignment and optional genuinely stronger assignment.
    /// None means no valid value tightens current behavior; table rationale explains why.
    const LIB: [(&str, &str, Option<&str>); 1] = [("plugin_base_dir", "%{LIBDIR}/unloaded", None)];

    /// Realm values are restrictions on absent mechanisms, except encrypted timestamp.
    const REALM: [(&str, &str, Option<&str>); 5] = [
        ("default_domain", "example.test", None),
        ("pkinit_identity", "FILE:/identity", None),
        ("pkinit_allow_upn", "false", None),
        ("pkinit_indicator", "strong", None),
        ("pkinit_require_freshness", "true", None),
    ];

    /// Render actual profile inputs, not direct calls to classification predicates.
    fn profile(section: &str, name: &str, value: &str) -> String {
        if section == "realms" {
            format!("[realms]\n R = {{\n {name} = {value}\n }}\n")
        } else {
            format!("[libdefaults]\n {name} = {value}\n")
        }
    }

    /// Both parse modes are tested for each side; Compatible must preserve the diagnostic.
    fn boundary(name: &str, safe: &str, tighter: Option<&str>) -> Result<(), Box<dyn Error>> {
        let config = Config::parse(safe)?;
        assert!(config.diagnostics().iter().any(|item| matches!(item, ConfigDiagnostic::NotYetEffective { relation, package: _ } if *relation == name)), "safe {name}");
        drop(
            Config::parse_with_mode(safe, ParseMode::Strict)
                .err()
                .ok_or_else(|| format!("strict accepted {name}"))?,
        );
        if let Some(input) = tighter {
            for mode in [ParseMode::Compatible, ParseMode::Strict] {
                let failure = Config::parse_with_mode(input, mode)
                    .err()
                    .ok_or_else(|| format!("tightening ignored: {name}"))?;
                assert!(
                    matches!(failure, super::super::Error::NotYetEffective { relation, package: _ } if relation == name)
                );
            }
        }
        Ok(())
    }

    /// Every deferred libdefaults row has an explicit safe/tightening decision.
    #[test]
    fn every_libdefaults_boundary_is_reviewed() -> Result<(), Box<dyn Error>> {
        for row in RELATIONS.iter().filter(|row| row.3.starts_with("plan 2 ")) {
            let (name, safe, tight) = LIB
                .iter()
                .copied()
                .find(|case| case.0 == row.0)
                .ok_or("unreviewed libdefaults row")?;
            let tighter = tight.map(|value| profile("libdefaults", name, value));
            boundary(
                name,
                &profile("libdefaults", name, safe),
                tighter.as_deref(),
            )?;
        }
        assert_eq!(
            RELATIONS
                .iter()
                .filter(|row| row.3.starts_with("plan 2 "))
                .count(),
            LIB.len()
        );
        Ok(())
    }

    /// Every deferred realm row has an explicit safe/tightening decision.
    #[test]
    fn every_realm_boundary_is_reviewed() -> Result<(), Box<dyn Error>> {
        for row in REALM_RELATIONS
            .iter()
            .filter(|row| row.3.starts_with("plan 2 "))
        {
            let (name, safe, tight) = REALM
                .iter()
                .copied()
                .find(|case| case.0 == row.0)
                .ok_or("unreviewed realm row")?;
            let tighter = tight.map(|value| profile("realms", name, value));
            boundary(name, &profile("realms", name, safe), tighter.as_deref())?;
        }
        assert_eq!(
            REALM_RELATIONS
                .iter()
                .filter(|row| row.3.starts_with("plan 2 "))
                .count(),
            REALM.len()
        );
        Ok(())
    }

    /// Section restrictions are compared with actual built-in behavior, not plugin names alone.
    #[test]
    fn every_section_boundary_is_reviewed() -> Result<(), Box<dyn Error>> {
        for row in SECTION_RELATIONS
            .iter()
            .filter(|row| row.3.starts_with("plan 2 "))
        {
            match row.0 {
                "capaths" => boundary("capaths", "[capaths]\n A = {\n B = .\n }\n", None)?,
                "disable" => boundary(
                    "disable",
                    "[plugins]\n clpreauth = {\n disable = pkinit\n }\n",
                    Some("[plugins]\n clpreauth = {\n disable = encrypted_timestamp\n }\n"),
                )?,
                "enable_only" => boundary(
                    "enable_only",
                    "[plugins]\n clpreauth = {\n enable_only = encrypted_timestamp\n }\n",
                    Some("[plugins]\n clpreauth = {\n enable_only = pkinit\n }\n"),
                )?,
                _ => return Err("unreviewed section row".into()),
            }
        }
        Ok(())
    }
}
