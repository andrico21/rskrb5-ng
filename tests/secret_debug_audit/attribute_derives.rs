//! Reviewed derive consumers for credential inventory admission.

/// These implementations do not append independent storage owners.
pub(super) const DERIVES: &[&str] = &[
    "Clone",
    "Copy",
    "Debug",
    "Default",
    "Eq",
    "PartialEq",
    "Ord",
    "PartialOrd",
    "Hash",
    "core::fmt::Debug",
    "std::fmt::Debug",
    "serde::Serialize",
    "serde::Deserialize",
    "thiserror::Error",
    "zeroize::Zeroize",
    "zeroize::ZeroizeOnDrop",
    "rasn::AsnType",
    "rasn::Encode",
    "rasn::Decode",
];

#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    clippy::missing_errors_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use std::io;

    use crate::source::parse;

    /// Renaming Debug cannot remove disclosure classification.
    #[test]
    fn renamed_debug_retains_disclosure_classification() -> Result<(), io::Error> {
        for attribute in [
            "#[derive(D)]",
            "#[cfg_attr(feature = \"enabled\", derive(D))]",
            "#[cfg_attr(feature = \"enabled\", cfg_attr(unix, derive(D)))]",
        ] {
            let source = format!(
                "use core::fmt::Debug as D;\n{attribute} pub struct Owner {{ password: Vec<u8> }}"
            );
            drop(parse("src/probe.rs", &source)?);
            match super::super::super::declarations::declarations("src/probe.rs", &source) {
                Ok(owners) => assert!(
                    owners.iter().any(|owner| owner.derived_debug),
                    "renamed Debug lost disclosure classification: {owners:?}"
                ),
                Err(error) => assert!(error.to_string().contains("src/probe.rs:2:")),
            }
        }
        Ok(())
    }
}
