//! Lexical macro binding regressions at the owner inventory boundary.

use std::{io, path::Path};

/// Textual shadowing selects only definitions preceding the invocation in scope.
#[test]
fn inventory_resolves_textual_macro_shadowing() -> Result<(), io::Error> {
    let safe = "macro_rules! owner { () => { impl Dummy {} }; }";
    let secret = "macro_rules! owner { () => { pub struct Leaked { password: Vec<u8> } }; }";
    for (body, accepted) in [
        (format!("{safe} {secret} owner!();"), false),
        (format!("{secret} {safe} owner!();"), true),
        (format!("{safe} owner!(); {secret}"), true),
        (format!("{secret} owner!(); {safe}"), false),
        (format!("owner!(); {safe}"), false),
        (format!("{safe} mod child {{ {secret} owner!(); }}"), false),
        (format!("{secret} mod child {{ {safe} owner!(); }}"), true),
        (format!("{secret} mod child {{ owner!(); }} {safe}"), false),
        (format!("{safe} mod child {{ owner!(); }} {secret}"), true),
        (format!("{safe} mod child {{ {secret} }} owner!();"), true),
    ] {
        let source = format!("pub struct Dummy; {body}");
        drop(super::source::parse("src/shadow.rs", &source)?);
        match super::declarations::declarations("src/shadow.rs", &source) {
            Ok(owners) => assert!(
                accepted,
                "invoked secret macro omitted: {source}: {owners:?}"
            ),
            Err(error) => {
                assert!(!accepted, "in-scope safe macro rejected: {source}: {error}");
                assert!(error.to_string().contains("src/shadow.rs:1:"));
            }
        }
    }
    Ok(())
}

/// Include and module edges cannot borrow an unrelated file's textual binding.
#[test]
fn inventory_refuses_unproven_cross_file_macros() -> Result<(), io::Error> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let graph =
        super::graph::load(&root.join("tests/secret_debug_audit/fixtures/macro-root.rs.txt"))?;
    let unit = graph
        .first()
        .ok_or_else(|| io::Error::other("missing root"))?;
    let file = unit.path.display().to_string();
    match super::declarations::graph_unit(&file, unit, &graph) {
        Ok(owners) => Err(io::Error::other(format!(
            "include shadow omitted: {owners:?}"
        ))),
        Err(error) => {
            assert!(
                error.to_string().contains("macro-root.rs.txt:4:"),
                "{error}"
            );
            Ok(())
        }
    }
}
