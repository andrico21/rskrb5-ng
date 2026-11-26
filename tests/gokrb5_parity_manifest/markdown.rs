//! Markdown rendering of the gokrb5 parity manifest.

use core::fmt::Write as _;

use toml::{Table, Value};

use crate::{
    Feature, TestError,
    model::rows,
    render::{cell, feature_tables, summary},
};

/// Fixed prose after the target line.
const SCOPE: &str =
    "This file is generated from [`gokrb5-parity.toml`](gokrb5-parity.toml); edit the
TOML and regenerate it with `cargo test --test gokrb5_parity_manifest` (a drift
leaves the regenerated copy in the test's temporary directory).

The target is relative: a row is required because gokrb5 v8.4.4 provides it.
Platform credential stores, FAST armor, PKINIT and the other MIT-only features
are not gokrb5 rows, but the combined target is the union of this manifest and
[the MIT krb5 manifest](mit-krb5-parity.md), so they remain required there. Only
C-ABI or system-library wrappers and server machinery are excluded globally
([scope](mit-krb5-parity.md#scope)). Behaviours of gokrb5 that a secure
superset must not copy are listed under
[Upstream behaviours not copied](#upstream-behaviours-not-copied).
";

/// Fixed prose at the end of the document.
const STATUS_VALUES: &str = "## Status values

Feature rows use `implemented`, `partial` (the `missing` column names the gap
and its closing todo), `absent` and `omitted` (an owner decision leaves the row
out: D14, no long-term key leaves a client); behaviour rows are `rejected` when the
gokrb5 behaviour is not copied and `partial` while a fix is outstanding. Areas
and gates use these values:

- `covered`: unit and fixture evidence is sufficient for every row of the area.
- `covered-with-gated-evidence`: implemented and unit-covered, but release
  confidence depends on keeping a live Docker or privileged gate green.
- `covered-needs-ad-evidence`: implemented and unit-covered, but AD parity is
  not proven until `TESTAD=1` runs against a maintained lab.
- `partial`: at least one row of the area is not implemented yet.
- `needs-live-evidence`: implementation may exist, but current proof is not
  broad enough for a release parity claim.
- `blocked-on-lab`: code exists, but external infrastructure is required.
- `historical-upstream`: the gate was captured green only by the upstream
  `clelange/rskrb5` workflow; this repository's CI doesn't run it (see
  [`gated-integration.md`](gated-integration.md)).
- `proven`: the named gate has been captured green on the required platform.
- `unproven`: the proof target is known but has not been captured.
- `missing-api`: supporting pieces exist, but the user-facing API is missing.
- `intentionally-out-of-scope`: not required by gokrb5 alone; see the scope above.

## Active Directory evidence

- Active Directory behaviour is verified against Samba AD (owner decision D12:
  Samba AD in Docker is sufficient AD evidence); Windows-specific behaviour is
  Samba-verified, not Windows-AD-verified. The strict Windows AD gate of
  [`ad-integration.md`](ad-integration.md) runs only if a lab with reachable
  USER and RESOURCE AD endpoints is provided. Do not add random or placeholder
  endpoint secrets.
";

/// String field `key` of `table`.
fn text<'table>(table: &'table Table, key: &str) -> Result<&'table str, TestError> {
    let value = table.get(key).and_then(Value::as_str);
    Ok(value.ok_or_else(|| format!("missing string {key}"))?)
}

/// String-array field `key` of `table`, joined with `separator`.
fn joined(table: &Table, key: &str, separator: &str) -> Result<String, TestError> {
    let values = table
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("missing array {key}"))?;
    let items: Option<Vec<&str>> = values.iter().map(Value::as_str).collect();
    Ok(items
        .ok_or_else(|| format!("{key} holds a non-string"))?
        .join(separator))
}

/// The `[[key]]` tables of `manifest`.
fn tables<'table>(manifest: &'table Table, key: &str) -> Result<Vec<&'table Table>, TestError> {
    let values = manifest
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("missing [[{key}]]"))?;
    let items: Option<Vec<&Table>> = values.iter().map(Value::as_table).collect();
    Ok(items.ok_or_else(|| format!("[[{key}]] holds a non-table"))?)
}

/// Appends the parity-area table.
fn areas(out: &mut String, manifest: &Table) -> Result<(), TestError> {
    out.push_str("\n## Parity areas\n\n| Area | Name | Status | Evidence | Next |\n| --- | --- | --- | --- | --- |\n");
    for area in tables(manifest, "area")? {
        writeln!(
            out,
            "| {} | {} | {} | {} | {} |",
            text(area, "id")?,
            cell(text(area, "name")?),
            text(area, "status")?,
            cell(&joined(area, "evidence", "; ")?),
            cell(&joined(area, "next", "; ")?)
        )?;
    }
    Ok(())
}

/// Appends the post-pin upstream change table.
fn post_pin(out: &mut String, manifest: &Table) -> Result<(), TestError> {
    out.push_str("\n## Upstream changes after the pin\n\nCommits between v8.4.4 and the observed master; protocol-relevant ones need named regression tests.\n\n| Commit | Change | Protocol relevant | Tests |\n| --- | --- | --- | --- |\n");
    for change in tables(manifest, "post_pin_change")? {
        let relevant = change
            .get("protocol_relevant")
            .and_then(Value::as_bool)
            .ok_or("protocol_relevant")?;
        writeln!(
            out,
            "| `{}` | {} | {} | {} |",
            text(change, "commit")?,
            cell(text(change, "summary")?),
            if relevant { "yes" } else { "no" },
            cell(&joined(change, "test_names", ", ")?)
        )?;
    }
    Ok(())
}

/// Appends the parity-gate table.
fn gates(out: &mut String, manifest: &Table) -> Result<(), TestError> {
    out.push_str("\n## Parity gates\n\n| Gate | Status | Proves | Command | CI job | Evidence | Next |\n| --- | --- | --- | --- | --- | --- | --- |\n");
    for gate in tables(manifest, "gate")? {
        writeln!(
            out,
            "| {} | {} | {} | `{}` | {} | {} | {} |",
            cell(text(gate, "name")?),
            text(gate, "status")?,
            joined(gate, "proves", ", ")?,
            text(gate, "command")?,
            cell(text(gate, "ci_job")?),
            cell(&joined(gate, "evidence", "; ")?),
            cell(&joined(gate, "next", "; ")?)
        )?;
    }
    Ok(())
}

/// Generates `docs/gokrb5-parity.md` from the parsed manifest.
pub(crate) fn markdown(manifest: &Table, features: &[Feature]) -> Result<String, TestError> {
    let target = manifest
        .get("target")
        .and_then(Value::as_table)
        .ok_or("target")?;
    let mut out = String::from("# gokrb5 parity\n\n");
    out.push_str("<!-- Generated from gokrb5-parity.toml by tests/gokrb5_parity_manifest.rs. Do not edit. -->\n\n");
    writeln!(
        out,
        "Target: `{}` {} (commit `{}`, released {}). The observed upstream master `{}` is tracked separately and is not the pin. Inventory of {}, statuses as of `{}`.\n",
        text(target, "module")?,
        text(target, "version")?,
        text(target, "commit")?,
        text(target, "release_date")?,
        text(target, "observed_master")?,
        text(target, "inventory_date")?,
        text(target, "manifest_commit_base")?
    )?;
    out.push_str(SCOPE);
    out.push_str("\n## Summary\n\n");
    summary(&mut out, manifest, "summary")?;
    areas(&mut out, manifest)?;
    out.push_str("\n## Features\n");
    feature_tables(&mut out, features, "###", |feature| {
        feature.parity_area.as_deref().unwrap_or_default()
    })?;
    out.push_str(
        "\n<a id=\"upstream-behaviours-not-copied\"></a>\n## Upstream behaviours not copied\n\n",
    );
    summary(&mut out, manifest, "insecure_summary")?;
    feature_tables(
        &mut out,
        &rows(manifest, "insecure_behaviour")?,
        "###",
        |_| "Table 2 behaviours",
    )?;
    post_pin(&mut out, manifest)?;
    gates(&mut out, manifest)?;
    write!(out, "\n{STATUS_VALUES}")?;
    Ok(out)
}
