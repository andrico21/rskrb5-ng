use core::error::Error;
use std::fs;

/// The profile guide's delivery index resolves every completed stage to a section.
#[test]
fn profile_delivery_index_is_complete() -> Result<(), Box<dyn Error>> {
    // Given the packaged reference and its machine-readable delivery index.
    let document = fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/config-profile.md"
    ))?;
    let index = document
        .split_once("<!-- profile-delivery:start -->")
        .ok_or("missing profile delivery index")?
        .1
        .split_once("<!-- profile-delivery:end -->")
        .ok_or("unterminated profile delivery index")?
        .0;
    // When parsing the status/link rows, as the parity docs tests parse status fields.
    let mut anchors = Vec::new();
    for row in index.lines().filter(|line| line.starts_with("| [")) {
        let cells: Vec<&str> = row.split('|').map(str::trim).collect();
        let status = cells.get(2).ok_or("delivery status")?;
        let anchor = cells
            .get(1)
            .ok_or("delivery reference")?
            .split_once("](#")
            .ok_or("delivery link")?
            .1
            .strip_suffix(')')
            .ok_or("delivery anchor")?;
        // Then every entry is delivered, uniquely linked and locally resolvable.
        assert_eq!(*status, "delivered", "{anchor}");
        assert!(!anchors.contains(&anchor), "duplicate {anchor}");
        assert!(
            document
                .lines()
                .any(|line| line.trim() == format!("<a id=\"{anchor}\"></a>")),
            "missing {anchor}"
        );
        anchors.push(anchor);
    }
    assert_eq!(anchors.len(), 8, "all eight profile stages must be indexed");
    Ok(())
}

/// Every catalogue entry must link a real packaged policy section.
#[test]
fn catalogue_policy_anchors_exist() -> Result<(), Box<dyn Error>> {
    // Given every policy link in the authoritative variant catalogue.
    let catalogue = include_str!("../../src/error/policy.rs");
    let document = fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/security-policy.md"
    ))?;
    let mut count = 0_usize;
    // When resolving each linked anchor using line-based, CRLF-safe matching.
    for line in catalogue
        .lines()
        .filter(|line| line.contains("security-policy.md#"))
    {
        let anchor = line
            .split_once("security-policy.md#")
            .ok_or("anchor")?
            .1
            .split_once(')')
            .ok_or("link end")?
            .0;
        // Then missing sections cannot pass silently.
        assert!(
            document
                .lines()
                .any(|section| section.trim() == format!("<a id=\"{anchor}\"></a>")),
            "missing {anchor}"
        );
        count = count.saturating_add(1);
    }
    assert_eq!(count, 9);
    for anchor in ["policy", "residual-copies", "windows-api-ccache"] {
        assert!(
            document
                .lines()
                .any(|line| line.trim() == format!("<a id=\"{anchor}\"></a>")),
            "missing {anchor}"
        );
    }
    Ok(())
}

/// Serde preferences report removed IDs rather than silently dropping them.
#[cfg(feature = "serde")]
#[test]
fn serde_preferences_expose_ignored_ids() -> Result<(), Box<dyn Error>> {
    use rskrb5_ng::config::{ConfigDiagnostic, LibDefaults};
    // Given MIT's historical preference list serialized as configuration.
    let mut json = serde_json::to_value(LibDefaults::new())?;
    drop(json.as_object_mut().ok_or("object")?.insert(
        "preferred_preauth_types".to_owned(),
        serde_json::json!([17_i32, 16_i32, 15_i32, 14_i32]),
    ));
    // When serde admits the informational preference list.
    let defaults: LibDefaults = serde_json::from_value(json)?;
    // Then the same accessor as text parsing reports every ignored ID.
    assert!(matches!(
        defaults.diagnostics().as_ref(),
        [
            ConfigDiagnostic::IgnoredPreauthType { id: 15_i32 },
            ConfigDiagnostic::IgnoredPreauthType { id: 14_i32 }
        ]
    ));
    Ok(())
}
