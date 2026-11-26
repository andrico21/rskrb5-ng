//! Disposition, status, evidence and closing-todo rules of one manifest row.

extern crate alloc;

use alloc::collections::BTreeSet;

use crate::Feature;

/// The only rows disposition `D14` may name: the owner decision of 2026-11-25
/// that no long-term key leaves a client omits gokrb5 `Client.Key` and nothing else.
pub(crate) const D14_ROWS: [&str; 1] = ["GO-client-8"];

/// Whether `feature` uses disposition `D14` as the decision allows: only a row of
/// [`D14_ROWS`], and only `omitted`. Rows with another disposition pass.
pub(crate) fn d14_admits(feature: &Feature) -> bool {
    feature.disposition != "D14"
        || (D14_ROWS.contains(&feature.id.as_str()) && feature.status == "omitted")
}

/// Checks the disposition, status and closing-todo rules of one row.
pub(crate) fn check_rules(feature: &Feature, todos: &BTreeSet<(i64, i64)>) {
    let (id, status, disposition) = (
        &feature.id,
        feature.status.as_str(),
        feature.disposition.as_str(),
    );
    let finished_elsewhere = matches!(disposition, "ALREADY" | "D1");
    assert_eq!(
        disposition == "ALREADY",
        finished_elsewhere && status == "implemented",
        "{id}: ALREADY rows are implemented"
    );
    assert_eq!(
        disposition == "D1",
        status == "out-of-scope",
        "{id}: out-of-scope only with D1"
    );
    assert_eq!(
        matches!(disposition, "D13" | "D14"),
        status == "omitted",
        "{id}: omitted only with D13/D14"
    );
    assert!(d14_admits(feature), "{id}: D14 names only {D14_ROWS:?}");
    assert_eq!(
        matches!(disposition, "D2" | "POL-01"),
        status == "rejected",
        "{id}: rejected only with D2/POL-01"
    );
    assert_eq!(
        feature.closing.is_none(),
        finished_elsewhere,
        "{id}: closing todo presence"
    );
    if let Some(closing) = feature.closing {
        assert!(
            todos.contains(&closing),
            "{id}: closing todo {closing:?} not in the index"
        );
    }
    for contributor in &feature.contributors {
        let parsed = contributor
            .strip_prefix('P')
            .and_then(|rest| rest.split_once('-'));
        let pair = parsed.and_then(|(plan, todo)| Some((plan.parse().ok()?, todo.parse().ok()?)));
        assert!(
            pair.is_some_and(|key| todos.contains(&key)),
            "{id}: contributor {contributor}"
        );
    }
    let has_tests = !feature.test_names.is_empty();
    let unproven = matches!(feature.evidence.as_str(), "unproven" | "blocked");
    assert_eq!(
        has_tests, !unproven,
        "{id}: evidence status must match the named tests"
    );
    match status {
        "implemented" | "rejected" => assert!(has_tests, "{id}: {status} without a named test"),
        _ => assert!(
            !feature.missing.is_empty(),
            "{id}: {status} must say what is missing"
        ),
    }
    if status == "implemented" {
        assert!(
            feature.missing.is_empty(),
            "{id}: implemented rows miss nothing"
        );
    }
    if status == "partial" && feature.closing.is_some_and(|(plan, _)| plan == 1) {
        assert!(
            feature.missing.contains("P2-"),
            "{id}: missing must name a plan-2 contributor"
        );
    }
    if status == "rejected" || status == "omitted" {
        assert!(
            feature.doc_anchor.is_some(),
            "{id}: {status} rows need a documentation anchor"
        );
    }
}

/// The ids of the rows in scope that are not `implemented`: a row whose
/// disposition is a work package or `ALREADY`. The D1, D2, D13, D14 and POL-01
/// rows keep the statuses [`check_rules`] pins for them.
pub(crate) fn incomplete(rows: &[Feature]) -> Vec<&str> {
    rows.iter()
        .filter(|feature| {
            feature.disposition == "ALREADY" || feature.disposition.starts_with("WP-")
        })
        .filter(|feature| feature.status != "implemented")
        .map(|feature| feature.id.as_str())
        .collect()
}
