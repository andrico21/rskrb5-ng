//! Tests of the MIT parity manifest, its todo index and its generated Markdown.

use toml::{Table, Value};

use crate::{
    Feature, Spec, TestError,
    audit::{check_evidence, check_markdown, check_shape, check_summary},
    markdown::markdown,
    model::{manifest, read, rows, todo_index},
    rules::{check_rules, incomplete},
};

/// The MIT manifest and its generated Markdown.
const MIT: Spec = Spec {
    manifest: "docs/mit-krb5-parity.toml",
    markdown: "docs/mit-krb5-parity.md",
    prefix: "MIT",
    upstream_ref: "krb5-1.22.2-final",
    generate: markdown,
};
/// Areas of the MIT inventory, the middle segment of each id.
const AREAS: [&str; 14] = [
    "client", "preauth", "crypto", "ccache", "keytab", "config", "dns", "gss", "admin", "pac",
    "authz", "plugin", "trace", "removed",
];

/// Ids are unique and well formed, and every enumerated field holds a known value.
#[test]
fn rows_are_well_formed_with_known_values() -> Result<(), TestError> {
    // Given the manifest rows.
    let (_, features) = manifest(MIT.manifest)?;
    // When each row's id and enumerated fields are read.
    // Then malformed or unknown values fail.
    check_shape(&MIT, &AREAS, &features);
    for feature in &features {
        let grouped = feature.parity_area.is_some() || !feature.related.is_empty();
        assert!(!grouped, "{}: gokrb5-only fields on an MIT row", feature.id);
    }
    Ok(())
}

/// Dispositions, statuses and closing todos follow the manifest rules.
#[test]
fn dispositions_statuses_and_closing_todos_are_consistent() -> Result<(), TestError> {
    // Given the manifest rows and the committed todo index.
    let (_, features) = manifest(MIT.manifest)?;
    let todos = todo_index()?;
    // When each row is checked against the rules.
    // Then any inconsistent row fails.
    for feature in &features {
        check_rules(feature, &todos);
    }
    Ok(())
}

/// Every named test, symbol, feature flag, rejection variant and anchor exists.
#[test]
fn named_evidence_exists_in_the_checkout() -> Result<(), TestError> {
    // Given the manifest rows.
    let (_, features) = manifest(MIT.manifest)?;
    // When each cited item is looked up lexically in the checkout.
    // Then a missing item fails closed.
    check_evidence(&features)
}

/// The summary counts equal the per-status row counts.
#[test]
fn summary_counts_match_rows() -> Result<(), TestError> {
    // Given the manifest summary and rows.
    let (table, features) = manifest(MIT.manifest)?;
    // When each status is counted.
    // Then every count and the total match.
    check_summary(&table, "summary", &features)
}

/// The committed Markdown equals the rendering of the manifest (CRLF-safe).
#[test]
fn markdown_matches_manifest() -> Result<(), TestError> {
    // Given the manifest.
    let (table, features) = manifest(MIT.manifest)?;
    // When the Markdown is generated again.
    // Then any drift fails and leaves the regenerated file for review.
    check_markdown(&MIT, &table, &features)
}

/// The `[plugins]` selection row is not `implemented` while a consumer is still deferred.
#[test]
fn plugin_selection_row_is_not_implemented_while_a_consumer_is_deferred() -> Result<(), TestError> {
    // Given the manifest row and the generated catalogue of the two selection relations.
    let (_, features) = manifest(MIT.manifest)?;
    let catalogue = read("docs/config-relations.md")?;
    let consumers: Vec<&str> = catalogue
        .lines()
        .filter(|line| {
            ["| plugins | disable |", "| plugins | enable_only |"]
                .iter()
                .any(|prefix| line.starts_with(prefix))
        })
        .filter_map(|line| line.split('|').nth(5).map(str::trim))
        .collect();
    assert_eq!(
        consumers.len(),
        2,
        "catalogue rows of disable and enable_only"
    );
    // When a catalogue consumer is a later plan-2 package.
    let deferred = consumers
        .iter()
        .any(|consumer| consumer.starts_with("plan "));
    let row = features
        .iter()
        .find(|feature| feature.id == "MIT-config-54")
        .ok_or("MIT-config-54 row")?;
    // Then the row cannot claim completion.
    assert!(
        !deferred || row.status != "implemented",
        "MIT-config-54 is implemented while a consumer is deferred: {consumers:?}"
    );
    Ok(())
}

/// The sections of the generated catalogue and the number of relations each
/// must list: the pinned MIT inventories `scripts/check-config-relations.py`
/// checks the tables against.
const SECTIONS: [(&str, usize); 3] = [("libdefaults", 43), ("realms", 28), ("sections", 6)];

/// The relation names whose catalogue consumer is a later plan-2 package.
fn deferred(catalogue: &str) -> Vec<&str> {
    catalogue
        .lines()
        .filter_map(|line| {
            let cells: Vec<&str> = line.split('|').map(str::trim).collect();
            (cells.len() > 6 && cells.get(5)?.starts_with("plan "))
                .then(|| cells.get(2).copied())?
        })
        .collect()
}

/// The `implemented` rows whose capability is exactly one of `relations`, `` `name` ``.
fn claimed<'rows>(features: &'rows [Feature], relations: &[&str]) -> Vec<&'rows str> {
    features
        .iter()
        .filter(|feature| feature.status == "implemented")
        .filter(|feature| {
            feature
                .capability
                .strip_prefix('`')
                .and_then(|rest| rest.strip_suffix('`'))
                .is_some_and(|name| relations.contains(&name))
        })
        .map(|feature| feature.id.as_str())
        .collect()
}

/// `(section, declared count, listed rows)` of every `## <section> (<n>)` table.
fn inventory(catalogue: &str) -> Vec<(&str, usize, usize)> {
    let mut sections: Vec<(&str, usize, usize)> = Vec::new();
    for line in catalogue.lines() {
        if let Some(heading) = line.strip_prefix("## ") {
            let (name, count) = heading.split_once(" (").unwrap_or((heading, ""));
            let declared = count.trim_end_matches(')').parse().unwrap_or(usize::MAX);
            sections.push((name, declared, 0));
            continue;
        }
        let relation = line.starts_with("| ")
            && !line.starts_with("| Section ")
            && !line.starts_with("| --- ");
        if relation && let Some(last) = sections.last_mut() {
            last.2 = last.2.saturating_add(1);
        }
    }
    sections
}

/// The generated catalogue lists the whole relation inventory and defers no
/// relation to a later package: every relation has an effective consumer, a
/// leaf it needs or an owner decision that excludes it.
#[test]
fn the_catalogue_is_complete_and_defers_nothing() -> Result<(), TestError> {
    // Given the generated catalogue.
    let catalogue = read("docs/config-relations.md")?;
    // When its sections and consumer column are read.
    let expected: Vec<(&str, usize, usize)> = SECTIONS
        .iter()
        .map(|&(name, count)| (name, count, count))
        .collect();
    // Then each section lists its whole inventory and no consumer is deferred.
    assert_eq!(inventory(&catalogue), expected, "catalogue inventory");
    assert_eq!(
        deferred(&catalogue),
        Vec::<&str>::new(),
        "deferred consumers"
    );
    Ok(())
}

/// No row that names one relation claims completion over a deferred consumer.
#[test]
fn relation_rows_are_not_implemented_while_the_catalogue_defers_them() -> Result<(), TestError> {
    // Given the manifest and the deferred relations of the catalogue.
    let (_, features) = manifest(MIT.manifest)?;
    let catalogue = read("docs/config-relations.md")?;
    // When a row's capability is exactly one deferred relation name.
    // Then no such row claims completion.
    assert_eq!(
        claimed(&features, &deferred(&catalogue)),
        Vec::<&str>::new(),
        "implemented while the catalogue defers the relation"
    );
    Ok(())
}

/// A deferred consumer written back into the catalogue fails both catalogue
/// checks: it is found, and the implemented row that names it is reported.
#[test]
fn a_reintroduced_deferred_consumer_fails_the_catalogue_checks() -> Result<(), TestError> {
    // Given the catalogue with the consumer of `kcm_mach_service` deferred again.
    let (_, features) = manifest(MIT.manifest)?;
    let catalogue = read("docs/config-relations.md")?;
    let consumer = "kcm::Store::from_libdefaults; kcm::seam::TransportFactory";
    let row = catalogue
        .lines()
        .find(|line| line.starts_with("| libdefaults | kcm_mach_service |"))
        .ok_or("kcm_mach_service row")?;
    assert!(row.contains(consumer), "fixture consumer: {row}");
    let fixture = catalogue.replace(row, &row.replace(consumer, &format!("plan {} WP-09", 2_u8)));
    // When the catalogue checks read it.
    // Then the relation is deferred and its implemented row is claimed over it.
    assert_eq!(deferred(&fixture), ["kcm_mach_service"]);
    assert_eq!(claimed(&features, &deferred(&fixture)), ["MIT-config-25"]);
    assert_eq!(inventory(&fixture), inventory(&catalogue));
    Ok(())
}

/// Every row in scope is `implemented`; D1, D2, D13 and POL-01 rows keep their
/// own statuses (checked by `dispositions_statuses_and_closing_todos_are_consistent`).
#[test]
fn every_in_scope_row_is_implemented() -> Result<(), TestError> {
    // Given the manifest rows.
    let (_, features) = manifest(MIT.manifest)?;
    // When the rows in scope that are not implemented are collected.
    // Then there are none.
    assert_eq!(incomplete(&features), Vec::<&str>::new());
    Ok(())
}

/// A row in scope reverted to `partial` fails the completeness check.
#[test]
fn a_row_reverted_to_partial_fails_the_completeness_check() -> Result<(), TestError> {
    // Given the manifest with one implemented work-package row reverted to partial.
    let mut table: Table = read(MIT.manifest)?.parse()?;
    let row = table
        .get_mut("feature")
        .and_then(Value::as_array_mut)
        .and_then(|rows| {
            rows.iter_mut()
                .filter_map(Value::as_table_mut)
                .find(|row| row.get("id").and_then(Value::as_str) == Some("MIT-config-25"))
        })
        .ok_or("MIT-config-25 row")?;
    drop(row.insert(
        "implementation_status".to_owned(),
        Value::String("partial".to_owned()),
    ));
    // When the completeness check reads the rows.
    let features = rows(&table, "feature")?;
    // Then exactly that row is reported.
    assert_eq!(incomplete(&features), ["MIT-config-25"]);
    Ok(())
}
