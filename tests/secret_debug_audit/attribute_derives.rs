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

#[test]
fn renamed_debug_retains_disclosure_classification() {
    for attribute in [
        "#[derive(D)]",
        "#[cfg_attr(feature = \"enabled\", derive(D))]",
        "#[cfg_attr(feature = \"enabled\", cfg_attr(unix, derive(D)))]",
    ] {
        let source = format!(
            "use core::fmt::Debug as D;\n{attribute} pub struct Owner {{ password: Vec<u8> }}"
        );
        match super::super::declarations::declarations("src/probe.rs", &source) {
            Ok(owners) => assert!(
                owners.iter().any(|owner| owner.derived_debug),
                "renamed Debug lost disclosure classification: {owners:?}"
            ),
            Err(error) => assert!(error.to_string().contains("src/probe.rs:2:")),
        }
    }
}
