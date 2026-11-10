//! Typed view of the parity manifests and of `docs/parity-todo-index.toml`.

extern crate alloc;

use alloc::collections::BTreeSet;
use std::{fs, path::Path};

use toml::{Table, Value};

use crate::{Feature, TestError};

/// Fields every feature row carries.
const REQUIRED: [&str; 13] = [
    "id",
    "area",
    "upstream_ref",
    "capability",
    "implementation_status",
    "evidence_status",
    "missing",
    "rust_symbols",
    "test_names",
    "feature_flags",
    "security_divergence",
    "disposition",
    "contributors",
];
/// Fields a feature row may carry in addition.
const OPTIONAL: [&str; 6] = [
    "closing_plan",
    "closing_todo",
    "rejected_feature",
    "doc_anchor",
    "parity_area",
    "related_features",
];

/// Reads a repository file as text with LF line endings, failing closed when absent.
pub(crate) fn read(relative: &str) -> Result<String, TestError> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(relative);
    let text = fs::read_to_string(&path).map_err(|source| format!("{relative}: {source}"))?;
    Ok(text.replace("\r\n", "\n"))
}

/// Returns a string field.
fn text(table: &Table, key: &str) -> Result<String, TestError> {
    let value = table.get(key).and_then(Value::as_str);
    Ok(value
        .ok_or_else(|| format!("missing string {key}"))?
        .to_owned())
}

/// Returns a string-array field.
fn strings(table: &Table, key: &str) -> Result<Vec<String>, TestError> {
    let values = table.get(key).and_then(Value::as_array);
    let items = values.ok_or_else(|| format!("missing array {key}"))?.iter();
    items
        .map(|item| {
            Ok(item
                .as_str()
                .ok_or_else(|| format!("{key} holds a non-string"))?
                .to_owned())
        })
        .collect()
}

/// Parses one row, rejecting unknown and missing keys.
fn parse(table: &Table) -> Result<Feature, TestError> {
    for key in table.keys() {
        let known = REQUIRED.contains(&key.as_str()) || OPTIONAL.contains(&key.as_str());
        assert!(known, "unknown feature key {key}");
    }
    let plan = table.get("closing_plan").map(Value::as_integer);
    let todo = table.get("closing_todo").map(Value::as_integer);
    let closing = match (plan, todo) {
        (None, None) => None,
        (Some(Some(plan_number)), Some(Some(todo_number))) => Some((plan_number, todo_number)),
        _ => return Err("closing_plan and closing_todo come as an integer pair".into()),
    };
    let optional = |key: &str| table.get(key).map(|_| text(table, key)).transpose();
    Ok(Feature {
        id: text(table, "id")?,
        area: text(table, "area")?,
        upstream_ref: text(table, "upstream_ref")?,
        capability: text(table, "capability")?,
        status: text(table, "implementation_status")?,
        evidence: text(table, "evidence_status")?,
        missing: text(table, "missing")?,
        rust_symbols: strings(table, "rust_symbols")?,
        test_names: strings(table, "test_names")?,
        cargo_features: strings(table, "feature_flags")?,
        divergence: text(table, "security_divergence")?,
        disposition: text(table, "disposition")?,
        closing,
        contributors: strings(table, "contributors")?,
        rejection: optional("rejected_feature")?,
        doc_anchor: optional("doc_anchor")?,
        parity_area: optional("parity_area")?,
        related: match table.get("related_features") {
            Some(_) => strings(table, "related_features")?,
            None => Vec::new(),
        },
    })
}

/// Parsed manifest `relative`: its whole table and its `[[feature]]` rows.
pub(crate) fn manifest(relative: &str) -> Result<(Table, Vec<Feature>), TestError> {
    let table: Table = read(relative)?.parse()?;
    let features = rows(&table, "feature")?;
    Ok((table, features))
}

/// Parses the `[[key]]` rows of `table` with the feature schema.
pub(crate) fn rows(table: &Table, key: &str) -> Result<Vec<Feature>, TestError> {
    let values = table.get(key).and_then(Value::as_array);
    values
        .ok_or_else(|| format!("manifest has a {key} array"))?
        .iter()
        .map(|row| parse(row.as_table().ok_or("row is a table")?))
        .collect()
}

/// Numbered `(plan, todo)` pairs of the committed todo index; `F` rows are checked, not returned.
pub(crate) fn todo_index() -> Result<BTreeSet<(i64, i64)>, TestError> {
    let table: Table = read("docs/parity-todo-index.toml")?.parse()?;
    let rows = table.get("todo").and_then(Value::as_array);
    let mut numbered = BTreeSet::new();
    let mut finals = BTreeSet::new();
    for row in rows.ok_or("index has a todo array")? {
        let entry = row.as_table().ok_or("todo row is a table")?;
        assert_eq!(entry.len(), 3, "todo rows carry plan, number and title");
        let plan = entry
            .get("plan")
            .and_then(Value::as_integer)
            .ok_or("plan")?;
        assert!(plan == 1 || plan == 2, "unknown plan {plan}");
        assert!(
            !text(entry, "title")?.trim().is_empty(),
            "todo title is empty"
        );
        let fresh = match entry.get("number") {
            Some(&Value::Integer(number)) if number > 0 => numbered.insert((plan, number)),
            Some(Value::String(label)) if is_final_label(label) => {
                finals.insert((plan, label.clone()))
            }
            _ => return Err(format!("plan {plan}: malformed todo number").into()),
        };
        assert!(fresh, "duplicate todo in plan {plan}");
    }
    check_complete(&table, &numbered)?;
    Ok(numbered)
}

/// Each `[[plan]]` row declares how many numbered todos its plan has; the index must list
/// exactly todos `1..=todos` of every plan it names.
fn check_complete(table: &Table, numbered: &BTreeSet<(i64, i64)>) -> Result<(), TestError> {
    let rows = table.get("plan").and_then(Value::as_array);
    let mut declared = BTreeSet::new();
    for row in rows.ok_or("index has a plan array")? {
        let entry = row.as_table().ok_or("plan row is a table")?;
        assert_eq!(entry.len(), 2, "plan rows carry number and todos");
        let plan = entry
            .get("number")
            .and_then(Value::as_integer)
            .ok_or("plan number")?;
        let count = entry
            .get("todos")
            .and_then(Value::as_integer)
            .ok_or("plan todos")?;
        assert!(declared.insert(plan), "duplicate plan {plan}");
        let listed: BTreeSet<i64> = numbered
            .range((plan, i64::MIN)..=(plan, i64::MAX))
            .map(|&(_, todo)| todo)
            .collect();
        let expected: BTreeSet<i64> = (1..=count).collect();
        assert_eq!(
            listed, expected,
            "plan {plan}: the index lists exactly todos 1..={count}"
        );
    }
    let indexed: BTreeSet<i64> = numbered.iter().map(|&(plan, _)| plan).collect();
    assert_eq!(
        declared, indexed,
        "every indexed plan declares its todo count"
    );
    Ok(())
}

/// Whether `label` is a final-verification todo such as `F1`.
fn is_final_label(label: &str) -> bool {
    label.strip_prefix('F').is_some_and(|digits| {
        !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit())
    })
}
