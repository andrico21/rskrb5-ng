//! Public symbol evidence requires a supported non-test configuration.

use super::{declares_clean, sanitized_sources};
use crate::TestError;

/// Disabled items cannot prove API, and their exclusion ends at the item boundary.
#[test]
fn symbol_evidence_requires_enabled_items() -> Result<(), TestError> {
    for attribute in [
        "#[cfg(any())]",
        "#[cfg(FALSE)]",
        "#[cfg(test)]",
        "# [ cfg ( all(test, unix) ) ]",
        "#[cfg(not(all()))]",
        "#[cfg_attr(all(), cfg(any()))]",
        "#[cfg(unix)]\n#[cfg(windows)]",
    ] {
        let disabled = vec![(
            "src/keytab.rs".to_owned(),
            format!("{attribute}\npub struct Ghost;\npub struct Real;"),
        )];
        let cleaned = sanitized_sources(&disabled)?;
        assert!(
            !declares_clean(&cleaned, &disabled, "keytab::Ghost"),
            "disabled item admitted: {attribute}"
        );
        assert!(declares_clean(&cleaned, &disabled, "keytab::Real"));
        let method = vec![(
            "src/keytab.rs".to_owned(),
            format!(
                "pub struct Real;\nimpl Real {{\n{attribute}\npub fn ghost() {{}}\npub fn live() {{}}\n}}"
            ),
        )];
        let cleaned_method = sanitized_sources(&method)?;
        assert!(!declares_clean(
            &cleaned_method,
            &method,
            "keytab::Real::ghost"
        ));
        assert!(declares_clean(
            &cleaned_method,
            &method,
            "keytab::Real::live"
        ));
    }
    Ok(())
}
