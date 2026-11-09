//! Manifest-independent audits of parity rows: shape, named evidence, counts and Markdown.

use std::fs;

use toml::{Table, Value};

use crate::{
    Feature, Spec, TestError,
    model::read,
    render::STATUSES,
    sources::{
        anchor_exists, cargo_features, check_test_name, declares_in, rejected_feature_variants,
        rust_sources, sanitized_sources, scopes,
    },
};

/// Evidence classes a row may claim.
const EVIDENCE: [&str; 6] = [
    "unit",
    "fixture",
    "live-local",
    "live-ci",
    "unproven",
    "blocked",
];
/// Dispositions other than the work packages `WP-01`..`WP-20`.
const DISPOSITIONS: [&str; 5] = ["ALREADY", "POL-01", "D1", "D2", "D13"];

/// Whether `disposition` is a work package `WP-01`..`WP-20`.
fn is_work_package(disposition: &str) -> bool {
    disposition
        .strip_prefix("WP-")
        .filter(|digits| digits.len() == 2)
        .and_then(|digits| digits.parse::<u8>().ok())
        .is_some_and(|number| (1..=20).contains(&number))
}

/// Whether the id is `<prefix>-<area>-<n>` with a known area and a canonical positive `n`.
fn well_formed(prefix: &str, areas: &[&str], feature: &Feature) -> bool {
    let number = feature
        .id
        .strip_prefix(prefix)
        .and_then(|rest| rest.strip_prefix('-'))
        .and_then(|rest| rest.strip_prefix(feature.area.as_str()))
        .and_then(|rest| rest.strip_prefix('-'));
    let canonical = number.is_some_and(|digits| {
        !digits.starts_with('0') && digits.parse::<u16>().is_ok_and(|value| value > 0)
    });
    canonical && areas.contains(&feature.area.as_str())
}

/// Ids are unique and well formed, and every enumerated field holds a known value.
pub(crate) fn check_shape(spec: &Spec, areas: &[&str], rows: &[Feature]) {
    let mut ids = Vec::new();
    for feature in rows {
        let (id, disposition) = (&feature.id, feature.disposition.as_str());
        assert!(
            well_formed(spec.prefix, areas, feature),
            "{id}: malformed id or area"
        );
        assert!(!ids.contains(id), "{id}: duplicate id");
        ids.push(id.clone());
        assert_eq!(
            feature.upstream_ref, spec.upstream_ref,
            "{id}: upstream ref"
        );
        assert!(
            !feature.capability.trim().is_empty(),
            "{id}: empty capability"
        );
        assert!(STATUSES.contains(&feature.status.as_str()), "{id}: status");
        assert!(
            EVIDENCE.contains(&feature.evidence.as_str()),
            "{id}: evidence"
        );
        let known = DISPOSITIONS.contains(&disposition) || is_work_package(disposition);
        assert!(known, "{id}: disposition {disposition}");
    }
}

/// Every named test, symbol, Cargo feature, rejection variant and anchor exists.
pub(crate) fn check_evidence(rows: &[Feature]) -> Result<(), TestError> {
    let sources = rust_sources("src")?;
    let cleaned = sanitized_sources(&sources)?;
    let modules = scopes(&cleaned, &sources);
    let flags = cargo_features()?;
    let variants = rejected_feature_variants()?;
    for feature in rows {
        let id = &feature.id;
        for name in &feature.test_names {
            check_test_name(name)?;
        }
        for symbol in &feature.rust_symbols {
            assert!(
                declares_in(&cleaned, &modules, symbol),
                "{id}: undeclared symbol {symbol}"
            );
        }
        for flag in &feature.cargo_features {
            assert!(flags.contains(flag), "{id}: unknown Cargo feature {flag}");
        }
        if let Some(variant) = &feature.rejection {
            assert!(
                variants.contains(variant),
                "{id}: no RejectedFeature::{variant}"
            );
        }
        if matches!(feature.disposition.as_str(), "D2" | "POL-01") {
            let anchor = feature.doc_anchor.as_deref().unwrap_or_default();
            assert!(
                anchor.starts_with("docs/security-policy.md#"),
                "{id}: D2 anchor"
            );
            assert!(feature.rejection.is_some(), "{id}: D2 variant");
        }
        if let Some(anchor) = &feature.doc_anchor {
            assert!(anchor_exists(anchor)?, "{id}: missing anchor {anchor}");
        }
    }
    Ok(())
}

/// The `[key]` counts equal the per-status row counts and their total.
pub(crate) fn check_summary(
    manifest: &Table,
    key: &str,
    rows: &[Feature],
) -> Result<(), TestError> {
    let summary = manifest
        .get(key)
        .and_then(Value::as_table)
        .ok_or_else(|| format!("missing [{key}]"))?;
    let stated = |name: &str| {
        let count = summary.get(&name.replace('-', "_"))?.as_integer()?;
        usize::try_from(count).ok()
    };
    for status in STATUSES {
        let counted = rows
            .iter()
            .filter(|feature| feature.status == status)
            .count();
        assert_eq!(stated(status), Some(counted), "{key}.{status}");
    }
    assert_eq!(stated("total"), Some(rows.len()), "{key}.total");
    Ok(())
}

/// The committed Markdown equals the generated one (CRLF-safe); drift leaves a fresh copy.
pub(crate) fn check_markdown(
    spec: &Spec,
    manifest: &Table,
    rows: &[Feature],
) -> Result<(), TestError> {
    let committed = read(spec.markdown).unwrap_or_default();
    let generated = (spec.generate)(manifest, rows)?;
    if committed != generated {
        let name = spec.markdown.rsplit('/').next().unwrap_or(spec.markdown);
        let fresh = format!("{}/{name}", env!("CARGO_TARGET_TMPDIR"));
        fs::write(&fresh, &generated)?;
        assert_eq!(
            committed, generated,
            "{} drifted; regenerated copy at {fresh}",
            spec.markdown
        );
    }
    Ok(())
}
