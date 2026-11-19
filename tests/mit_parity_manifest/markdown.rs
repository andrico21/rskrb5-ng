//! Markdown rendering of the MIT parity manifest.

use core::fmt::Write as _;

use toml::{Table, Value};

use crate::{
    Feature, TestError,
    render::{feature_tables, summary},
};

/// Fixed prose between the summary and the feature tables.
const SCOPE: &str = "<a id=\"scope\"></a>
## Scope

The manifest covers MIT's client and service library surface. D1 rows are
KDC, kadmind, database and C-ABI machinery: they are recorded as
`out-of-scope` and no API is provided for them. D2 rows are features MIT
removed or that are insecure by design: they are `rejected` with a typed
`error::RejectedFeature` and a section of
[the security policy](security-policy.md). D13 records the owner decision to
omit the legacy Windows `API:` credential cache.

Completion means the union of this manifest and
[the gokrb5 manifest](gokrb5-parity.md), not their intersection. Each row's
closing todo is the plan todo that makes it final; `P1-N` is plan 1 todo N
and `P2-N` is plan 2 todo N, listed in `docs/parity-todo-index.toml`.

<a id=\"rust-extension-points\"></a>
## Rust extension points

MIT loads C plugin modules from `plugin_base_dir` and `module` directives. This
crate loads no code: providers are Rust values registered in an
`extensions::Registry`, and `Registry::parse_config` resolves a `module` that
names a registered provider. Any other `module` is
`Config::UnsupportedDynamicModule` in every mode.
";

/// Generates `docs/mit-krb5-parity.md` from the parsed manifest.
pub(crate) fn markdown(manifest: &Table, features: &[Feature]) -> Result<String, TestError> {
    let target = manifest
        .get("target")
        .and_then(Value::as_table)
        .ok_or("target")?;
    let field = |key: &str| {
        target
            .get(key)
            .and_then(Value::as_str)
            .ok_or_else(|| format!("target.{key}"))
    };
    let mut out = String::from("# MIT krb5 parity\n\n");
    out.push_str("<!-- Generated from mit-krb5-parity.toml by tests/mit_parity_manifest.rs. Do not edit. -->\n\n");
    writeln!(
        out,
        "Target: MIT krb5 {} (`{}`, released {}), inventory of {}, statuses as of `{}`.\n",
        field("release")?,
        field("upstream_ref")?,
        field("release_date")?,
        field("inventory_date")?,
        field("manifest_commit_base")?
    )?;
    out.push_str("## Summary\n\n");
    summary(&mut out, manifest, "summary")?;
    writeln!(out, "\n{SCOPE}")?;
    feature_tables(&mut out, features, "##", |feature| &feature.area)?;
    Ok(out)
}
