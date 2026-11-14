//! Wrong-case twins of every catalogued name are never honoured, like MIT's `strcmp`.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::{error::Error, slice};

    use super::super::{
        Config, ConfigDiagnostic, ParseMode, libdefaults::relations::RELATIONS, protocol,
        realm_relations::REALM_RELATIONS, section_decode::SECTION_RELATIONS,
    };

    /// The all-upper and the capitalized spelling of a lower-case catalogue name.
    fn twins(name: &str) -> [String; 2] {
        let (first, rest) = name.split_at_checked(1).unwrap_or_default();
        [
            name.to_ascii_uppercase(),
            format!("{}{rest}", first.to_ascii_uppercase()),
        ]
    }

    /// The twin parses to the baseline plus one diagnostic, and Strict mode refuses it.
    fn never_honoured(
        text: &str,
        baseline: &str,
        wanted: &ConfigDiagnostic,
    ) -> Result<(), Box<dyn Error>> {
        let mut config = Config::parse_with_mode(text, ParseMode::Compatible)?;
        assert_eq!(config.diagnostics(), slice::from_ref(wanted), "{text}");
        config.libdefaults.enctype_diagnostics.clear();
        assert_eq!(config, Config::parse(baseline)?, "{text}");
        let failure = Config::parse_with_mode(text, ParseMode::Strict)
            .err()
            .ok_or_else(|| format!("strict accepted {text}"))?;
        assert_eq!(
            failure.to_string(),
            wanted.clone().into_error().to_string(),
            "{text}"
        );
        Ok(())
    }

    /// Every libdefaults, realm and section catalogue row has wrong-case twins that apply nothing.
    #[test]
    fn wrong_case_twins_of_every_relation_are_unknown() -> Result<(), Box<dyn Error>> {
        let realm_base = "[realms]\n R = {\n kdc = k:88\n }\n";
        for value in ["1", "0"] {
            for row in RELATIONS {
                for twin in twins(row.0) {
                    never_honoured(
                        &format!("[libdefaults]\n {twin} = {value}\n"),
                        "[libdefaults]\n",
                        &ConfigDiagnostic::UnknownRelation {
                            path: vec!["libdefaults".to_owned(), twin],
                        },
                    )?;
                }
            }
            for row in REALM_RELATIONS {
                for twin in twins(row.0) {
                    let text = format!("[realms]\n R = {{\n kdc = k:88\n {twin} = {value}\n }}\n");
                    if value == "1" && protocol::recognized(row.0) {
                        // A removed-protocol selector stays refused in any case.
                        assert!(Config::parse(&text).is_err(), "{text}");
                        continue;
                    }
                    never_honoured(
                        &text,
                        realm_base,
                        &ConfigDiagnostic::UnknownRelation {
                            path: vec!["realms".to_owned(), "R".to_owned(), twin],
                        },
                    )?;
                }
            }
        }
        for row in SECTION_RELATIONS {
            for twin in twins(row.0) {
                if matches!(row.0, "disable" | "enable_only" | "module") {
                    never_honoured(
                        &format!("[plugins]\n kdcpreauth = {{\n {twin} = pkinit\n }}\n"),
                        "[plugins]\n kdcpreauth = {\n }\n",
                        &ConfigDiagnostic::UnknownRelation {
                            path: vec!["plugins".to_owned(), "kdcpreauth".to_owned(), twin],
                        },
                    )?;
                } else {
                    never_honoured(
                        &format!("[{twin}]\n a = {{\n b = c\n }}\n"),
                        "",
                        &ConfigDiagnostic::UnknownSection { section: twin },
                    )?;
                }
            }
        }
        Ok(())
    }

    /// Every section header the library reads has wrong-case twins that are unknown sections.
    #[test]
    fn wrong_case_twins_of_every_section_are_unknown() -> Result<(), Box<dyn Error>> {
        for section in super::super::unknown::SECTIONS.iter().chain(&["logging"]) {
            for twin in twins(section) {
                never_honoured(
                    &format!("[{twin}]\n"),
                    "",
                    &ConfigDiagnostic::UnknownSection { section: twin },
                )?;
            }
        }
        Ok(())
    }
}
