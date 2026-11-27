//! Per-row tests of the gokrb5 parity manifest: features, upstream behaviours not
//! copied, post-pin changes, area consistency and the generated Markdown.

extern crate alloc;

use alloc::collections::BTreeSet;

use toml::{Table, Value};

use crate::{
    Feature, Spec, TestError,
    audit::{check_evidence, check_markdown, check_shape, check_summary},
    markdown::markdown,
    model::{manifest, rows, todo_index},
    rules::{check_rules, d14_admits, incomplete},
    sources::check_test_name,
};

/// The gokrb5 v8.4.4 tag commit.
const PIN: &str = "47cd2e7744531465a983bf457bac38e6ad8f4684";
/// The gokrb5 manifest and its generated Markdown.
const GO: Spec = Spec {
    manifest: "docs/gokrb5-parity.toml",
    markdown: "docs/gokrb5-parity.md",
    prefix: "GO",
    upstream_ref: PIN,
    generate: markdown,
};
/// gokrb5 packages, the middle segment of each feature id.
const PACKAGES: [&str; 16] = [
    "config",
    "keytab",
    "credentials",
    "client",
    "service",
    "spnego",
    "crypto",
    "messages",
    "kadmin",
    "pac",
    "gssapi",
    "iana",
    "krberror",
    "types",
    "asn1tools",
    "doc",
];
/// Area statuses that claim every row of the area is implemented.
const COVERED: [&str; 3] = [
    "covered",
    "covered-with-gated-evidence",
    "covered-needs-ad-evidence",
];
/// Number of Table 2 behaviours in the inventory.
const BEHAVIOURS: usize = 14;

/// Whether `text` is a full lowercase hexadecimal commit id.
fn is_commit(text: &str) -> bool {
    text.len() == 40
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// The target pins the v8.4.4 commit and keeps the observed master separate.
#[test]
fn target_pins_the_tag_commit() -> Result<(), TestError> {
    // Given the manifest target.
    let (table, _) = manifest(GO.manifest)?;
    let target = table
        .get("target")
        .and_then(Value::as_table)
        .ok_or("target")?;
    let field = |key: &str| target.get(key).and_then(Value::as_str).unwrap_or_default();
    // When its commit fields are read.
    // Then the pin is immutable and distinct from the rolling master.
    assert_eq!(field("commit"), PIN);
    assert_eq!(field("upstream_ref"), PIN);
    assert!(field("usage_url").contains(PIN), "usage_url must be pinned");
    assert!(is_commit(field("observed_master")) && field("observed_master") != PIN);
    Ok(())
}

/// Feature ids are unique, well formed and grouped into declared parity areas.
#[test]
fn features_are_well_formed_and_grouped() -> Result<(), TestError> {
    // Given the feature rows and the declared areas.
    let (table, features) = manifest(GO.manifest)?;
    let areas = area_statuses(&table)?;
    // When each row is read.
    check_shape(&GO, &PACKAGES, &features);
    // Then each row names a declared area and no behaviour-row field.
    for feature in &features {
        let area = feature.parity_area.as_deref().unwrap_or_default();
        assert!(
            areas.iter().any(|(id, _, _)| id == area),
            "{}: area {area}",
            feature.id
        );
        assert!(
            feature.related.is_empty(),
            "{}: related_features on a feature",
            feature.id
        );
    }
    Ok(())
}

/// `(id, status, next work)` of every `[[area]]`.
fn area_statuses(table: &Table) -> Result<Vec<(String, String, String)>, TestError> {
    let values = table
        .get("area")
        .and_then(Value::as_array)
        .ok_or("area array")?;
    values
        .iter()
        .map(|value| {
            let area = value.as_table().ok_or("area table")?;
            let get = |key: &str| {
                area.get(key)
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned()
            };
            let next = area.get("next").map_or_default(ToString::to_string);
            Ok((get("id"), get("status"), next))
        })
        .collect()
}

/// An area claims coverage only when no row is open (`partial` or `absent`); otherwise
/// its next work names each open row's closing todo. A row an owner decision omits
/// or rejects is final, not open.
#[test]
fn area_statuses_follow_their_rows() -> Result<(), TestError> {
    // Given the areas and their feature rows.
    let (table, features) = manifest(GO.manifest)?;
    // When the open rows of each area are collected.
    for (id, status, next) in area_statuses(&table)? {
        let open: Vec<&Feature> = features
            .iter()
            .filter(|feature| feature.parity_area.as_deref() == Some(id.as_str()))
            .filter(|feature| matches!(feature.status.as_str(), "partial" | "absent"))
            .collect();
        // Then a covered area has none, and every open row's closing todo is named.
        assert!(
            open.is_empty() || !COVERED.contains(&status.as_str()),
            "area {id} is {status} with open rows"
        );
        for feature in open {
            let (plan, todo) = feature.closing.ok_or("open row without closing todo")?;
            assert!(
                next.contains(&format!("P{plan}-{todo}")),
                "area {id} next lacks {}'s P{plan}-{todo}",
                feature.id
            );
        }
    }
    Ok(())
}

/// Feature dispositions, statuses and closing todos follow the shared rules.
#[test]
fn feature_rules_hold() -> Result<(), TestError> {
    // Given the feature rows and the committed todo index.
    let (_, features) = manifest(GO.manifest)?;
    let todos = todo_index()?;
    // When each row is checked.
    // Then any inconsistent row fails.
    for feature in &features {
        check_rules(feature, &todos);
    }
    Ok(())
}

/// Every named test, symbol and feature flag of the feature and behaviour rows exists.
#[test]
fn named_evidence_exists_in_the_checkout() -> Result<(), TestError> {
    // Given both row kinds.
    let (table, features) = manifest(GO.manifest)?;
    let behaviours = rows(&table, "insecure_behaviour")?;
    // When each cited item is looked up lexically.
    // Then a missing item fails closed.
    check_evidence(&features)?;
    check_evidence(&behaviours)
}

/// Each Table 2 behaviour is a row that is either not copied, with negative tests,
/// or partial with a closing todo, and relates to existing feature rows.
#[test]
fn upstream_behaviours_are_rejected_or_scheduled() -> Result<(), TestError> {
    // Given the behaviour rows, the feature ids and the todo index.
    let (table, features) = manifest(GO.manifest)?;
    let behaviours = rows(&table, "insecure_behaviour")?;
    let ids: BTreeSet<&str> = features.iter().map(|feature| feature.id.as_str()).collect();
    let todos = todo_index()?;
    check_shape(&GO, &["T2"], &behaviours);
    assert_eq!(
        behaviours.len(),
        BEHAVIOURS,
        "one row per Table 2 behaviour"
    );
    for (index, row) in behaviours.iter().enumerate() {
        // When each row is checked against the behaviour rules.
        let id = &row.id;
        // Then statuses, evidence, closing todos and relations are consistent.
        assert_eq!(
            *id,
            format!("GO-T2-{}", index.saturating_add(1)),
            "behaviour rows are in order"
        );
        assert!(
            !row.divergence.is_empty() && !row.test_names.is_empty(),
            "{id}: divergence and tests"
        );
        assert!(
            !row.related.is_empty() && row.related.iter().all(|other| ids.contains(other.as_str())),
            "{id}: relations"
        );
        match row.status.as_str() {
            "rejected" => {
                assert!(
                    row.disposition == "ALREADY" && row.closing.is_none(),
                    "{id}: rejected rows are done"
                );
                assert!(row.missing.is_empty(), "{id}: rejected rows miss nothing");
            }
            "partial" => {
                let closing = row
                    .closing
                    .ok_or("partial behaviour without closing todo")?;
                assert!(
                    todos.contains(&closing) && row.disposition.starts_with("WP-"),
                    "{id}: closing"
                );
                assert!(
                    !row.missing.is_empty(),
                    "{id}: partial rows say what is missing"
                );
            }
            other => return Err(format!("{id}: behaviour status {other}").into()),
        }
    }
    check_summary(&table, "insecure_summary", &behaviours)
}

/// Post-pin upstream commits are recorded, and each protocol-relevant one names tests.
#[test]
fn post_pin_changes_name_regression_tests() -> Result<(), TestError> {
    // Given the post-pin rows.
    let (table, _) = manifest(GO.manifest)?;
    let changes = table
        .get("post_pin_change")
        .and_then(Value::as_array)
        .ok_or("post_pin_change")?;
    let mut commits = BTreeSet::new();
    for change in changes.iter().filter_map(Value::as_table) {
        // When each row is read.
        let commit = change
            .get("commit")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let relevant = change
            .get("protocol_relevant")
            .and_then(Value::as_bool)
            .ok_or("protocol_relevant")?;
        let tests = change
            .get("test_names")
            .and_then(Value::as_array)
            .ok_or("test_names")?;
        // Then commits are unique ids and relevant changes cite existing tests.
        assert!(
            is_commit(commit) && commits.insert(commit),
            "bad or duplicate commit {commit}"
        );
        assert!(
            !relevant || !tests.is_empty(),
            "{commit}: protocol-relevant without tests"
        );
        for name in tests {
            check_test_name(name.as_str().ok_or("test name")?)?;
        }
    }
    assert_eq!(
        commits.len(),
        changes.len(),
        "every post-pin row is a table"
    );
    Ok(())
}

/// The feature rows in scope that are not `implemented` and the upstream
/// behaviour rows that are not `rejected` (not copied, with negative tests).
fn open_rows(table: &Table) -> Result<Vec<String>, TestError> {
    let features = rows(table, "feature")?;
    let behaviours = rows(table, "insecure_behaviour")?;
    let mut open: Vec<String> = incomplete(&features)
        .into_iter()
        .map(str::to_owned)
        .collect();
    open.extend(
        behaviours
            .iter()
            .filter(|row| row.status != "rejected")
            .map(|row| row.id.clone()),
    );
    Ok(open)
}

/// Every feature row in scope is `implemented` and every upstream behaviour
/// row is `rejected`.
#[test]
fn every_in_scope_row_is_implemented() -> Result<(), TestError> {
    // Given the manifest.
    let (table, _) = manifest(GO.manifest)?;
    // When the open rows are collected.
    // Then there are none.
    assert_eq!(open_rows(&table)?, Vec::<String>::new());
    Ok(())
}

/// A feature row and a behaviour row reverted to `partial` fail the
/// completeness check.
#[test]
fn rows_reverted_to_partial_fail_the_completeness_check() -> Result<(), TestError> {
    // Given the manifest with one feature and one behaviour row reverted to partial.
    let (mut table, _) = manifest(GO.manifest)?;
    for (key, id) in [
        ("feature", "GO-client-2"),
        ("insecure_behaviour", "GO-T2-14"),
    ] {
        let row = table
            .get_mut(key)
            .and_then(Value::as_array_mut)
            .and_then(|rows| {
                rows.iter_mut()
                    .filter_map(Value::as_table_mut)
                    .find(|row| row.get("id").and_then(Value::as_str) == Some(id))
            })
            .ok_or_else(|| format!("{id} row"))?;
        drop(row.insert(
            "implementation_status".to_owned(),
            Value::String("partial".to_owned()),
        ));
    }
    // When the completeness check reads the rows.
    // Then exactly those rows are reported.
    assert_eq!(open_rows(&table)?, ["GO-client-2", "GO-T2-14"]);
    Ok(())
}

/// Disposition `D14` admits its one row as `omitted` and nothing else: the same
/// disposition on another row, or with another status, is refused.
#[test]
fn d14_names_only_the_client_key_row() -> Result<(), TestError> {
    // Given the manifest's D14 row and two scratch copies of it.
    let (table, _) = manifest(GO.manifest)?;
    let decided = |id: &str, status: &str| -> Result<bool, TestError> {
        let mut scratch = table.clone();
        let row = scratch
            .get_mut("feature")
            .and_then(Value::as_array_mut)
            .and_then(|rows| {
                rows.iter_mut()
                    .filter_map(Value::as_table_mut)
                    .find(|row| row.get("disposition").and_then(Value::as_str) == Some("D14"))
            })
            .ok_or("D14 row")?;
        drop(row.insert("id".to_owned(), Value::String(id.to_owned())));
        drop(row.insert(
            "implementation_status".to_owned(),
            Value::String(status.to_owned()),
        ));
        let features = rows(&scratch, "feature")?;
        let feature = features
            .iter()
            .find(|feature| feature.disposition == "D14")
            .ok_or("scratch row")?;
        Ok(d14_admits(feature))
    };
    // When the rule reads the real row, another id and another status.
    // Then only the real row passes.
    assert!(decided("GO-client-8", "omitted")?, "the decided row");
    assert!(!decided("GO-client-1", "omitted")?, "another row");
    assert!(!decided("GO-client-8", "rejected")?, "another status");
    Ok(())
}

/// The summary counts equal the per-status feature counts.
#[test]
fn summary_counts_match_rows() -> Result<(), TestError> {
    // Given the manifest summary and rows.
    let (table, features) = manifest(GO.manifest)?;
    // When each status is counted.
    // Then every count and the total match.
    check_summary(&table, "summary", &features)
}

/// The committed Markdown equals the rendering of the manifest (CRLF-safe).
#[test]
fn markdown_matches_manifest() -> Result<(), TestError> {
    // Given the manifest.
    let (table, features) = manifest(GO.manifest)?;
    // When the Markdown is generated again.
    // Then any drift fails and leaves the regenerated file for review.
    check_markdown(&GO, &table, &features)
}
