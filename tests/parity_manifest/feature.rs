#[cfg(test)]
use core::error::Error;

#[cfg(test)]
use toml::Table;

/// Error type of the manifest helpers and tests.
#[cfg(test)]
type TestError = Box<dyn Error>;

/// One `[[feature]]` row of the manifest.
#[cfg(test)]
struct Feature {
    /// Source row id, such as `MIT-client-1`.
    id: String,
    /// Upstream area, the middle segment of the id.
    area: String,
    /// Upstream tag or commit the row is pinned to.
    upstream_ref: String,
    /// Upstream capability text.
    capability: String,
    /// `implemented`, `partial`, `absent`, `rejected`, `omitted` or `out-of-scope`.
    status: String,
    /// Strongest evidence class backing the named tests.
    evidence: String,
    /// What is still missing, or why nothing is in scope.
    missing: String,
    /// Public Rust items delivering the row.
    rust_symbols: Vec<String>,
    /// `path::function` names of the tests proving the row.
    test_names: Vec<String>,
    /// Cargo features the named symbols need.
    cargo_features: Vec<String>,
    /// Deliberate divergence from upstream behavior.
    divergence: String,
    /// `ALREADY`, `WP-NN`, `POL-01`, `D1`, `D2`, `D13` or `D14` (the owner
    /// decision of 2026-11-25 that no long-term key leaves a client; only the
    /// rows of `rules::D14_ROWS`).
    disposition: String,
    /// Closing plan and todo number, absent for `ALREADY` and `D1` rows.
    closing: Option<(i64, i64)>,
    /// Contributing todos, such as `P2-4`.
    contributors: Vec<String>,
    /// `RejectedFeature` variant of a rejected row.
    rejection: Option<String>,
    /// `docs/<file>.md#<anchor>` reference.
    doc_anchor: Option<String>,
    /// Parity area of the gokrb5 manifest that groups the row.
    parity_area: Option<String>,
    /// Source rows an upstream-behaviour row relates to.
    related: Vec<String>,
}

/// One manifest: its files, id scheme, pin and Markdown generator.
#[cfg(test)]
struct Spec {
    /// Repository path of the TOML manifest.
    manifest: &'static str,
    /// Repository path of the generated Markdown.
    markdown: &'static str,
    /// Id prefix, such as `MIT`.
    prefix: &'static str,
    /// Upstream tag or commit every row is pinned to.
    upstream_ref: &'static str,
    /// Generates the Markdown from the parsed manifest.
    generate: fn(&Table, &[Feature]) -> Result<String, TestError>,
}
