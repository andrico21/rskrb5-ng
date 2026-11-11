//! Round-eight source inventory regressions use the real inventory boundary.

use std::{io, path::Path};

use super::{declarations::declarations, inventory::secret_owners, source::parse};

/// Only provably test-only predicates exclude owners; features remain visible.
#[test]
fn inventory_cfg_preserves_library_branches() -> Result<(), io::Error> {
    for (attribute, expected) in [
        ("#[cfg(test)]", false),
        ("#[cfg(all(test, feature = \"x\"))]", false),
        ("#[cfg(feature = \"x\")]", true),
        ("#[cfg(not(feature = \"x\"))]", true),
        ("#[cfg(any(test, feature = \"x\"))]", true),
        ("#[cfg(not(test))]", true),
    ] {
        let tree = parse(
            "src/cfg.rs",
            &format!("{attribute} pub struct Owner {{ password: Vec<u8> }}"),
        )?;
        let Some(syn::Item::Struct(owner)) = tree.items.first() else {
            return Err(io::Error::other("missing cfg fixture"));
        };
        assert_eq!(
            super::configuration::included("src/cfg.rs", &owner.attrs)?,
            expected,
            "{attribute}"
        );
    }
    let tree = parse("src/cfg.rs", "#[cfg(mystery(test))] pub struct Owner;")?;
    let Some(syn::Item::Struct(owner)) = tree.items.first() else {
        return Err(io::Error::other("missing cfg fixture"));
    };
    assert!(
        matches!(super::configuration::included("src/cfg.rs", &owner.attrs), Err(error) if error.to_string().contains("src/cfg.rs:1:"))
    );
    Ok(())
}

/// The real library graph retains features and excludes test-only macro-bearing files.
#[test]
fn library_graph_excludes_only_test_sources() -> Result<(), io::Error> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let graph = super::graph::load(&root.join("src/lib.rs"))?;
    assert!(
        graph.iter().any(|unit| unit.path.ends_with("http.rs")),
        "optional HTTP source missing"
    );
    assert!(
        !graph
            .iter()
            .any(|unit| unit.path.ends_with("payload_tests.rs")),
        "test-only file included"
    );
    let owners = declarations(
        "src/probe.rs",
        "#[cfg(feature = \"x\")] pub struct Included { password: Vec<u8> } #[cfg(test)] pub struct Excluded { password: Vec<u8> }",
    )?;
    assert_eq!(secret_owners(&owners), ["src/probe.rs::Included"]);
    Ok(())
}

/// Includes preserve physical source identity and reject missing targets and cycles.
#[test]
fn literal_includes_load_original_source() -> Result<(), io::Error> {
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/secret_debug_audit/fixtures");
    let loaded = super::source::load(&fixtures.join("include.rs.txt"))?;
    assert_eq!(loaded.len(), 2);
    let included = loaded
        .get(1)
        .ok_or_else(|| io::Error::other("included tree missing"))?;
    assert!(included.path.ends_with("owner.rs.txt"));
    let Some(syn::Item::Struct(owner)) = included.tree.items.first() else {
        return Err(io::Error::other("included owner missing"));
    };
    assert_eq!(owner.ident.to_string(), "Included");
    let graph = super::graph::load(&fixtures.join("scoped.rs.txt"))?;
    let mut owners = Vec::new();
    for unit in &graph {
        let scopes = graph
            .iter()
            .filter(|candidate| candidate.module == unit.module)
            .map(|candidate| candidate.tree.items.as_slice())
            .collect();
        owners.extend(super::declarations::scoped(
            &unit.path.display().to_string(),
            &unit.tree,
            scopes,
        )?);
    }
    assert_eq!(owners.len(), 1);
    assert_eq!(
        secret_owners(&owners).len(),
        1,
        "include lost enclosing alias"
    );
    let modules = super::graph::load(&fixtures.join("module-root.rs.txt"))?;
    let mut module_owners = Vec::new();
    for unit in &modules {
        module_owners.extend(super::declarations::graph_unit(
            &unit.path.display().to_string(),
            unit,
            &modules,
        )?);
    }
    assert_eq!(module_owners.len(), 1);
    assert_eq!(
        secret_owners(&module_owners).len(),
        1,
        "module alias lost credential storage"
    );
    for file in ["missing.rs.txt", "cycle.rs.txt"] {
        let Err(error) = super::source::load(&fixtures.join(file)) else {
            return Err(io::Error::other("unresolved include accepted"));
        };
        assert!(error.to_string().contains(&format!("{file}:1:")));
    }
    Ok(())
}

/// Local macro output must prove its item shape, including nested declarations.
#[test]
fn local_macro_transcribers_require_structural_proof() -> Result<(), io::Error> {
    for (source, accepted) in [
        (
            "macro_rules! plain { ($($value:expr),*) => { ($($value),*) }; }",
            true,
        ),
        (
            "macro_rules! convert { ($($domain:ident),+) => { $(impl From<u32> for $domain { fn from(value: u32) -> Self { Self(value) } })+ }; }",
            true,
        ),
        (
            "macro_rules! leak { ($name:ident) => { pub struct $name { password: Vec<u8> } }; }",
            false,
        ),
        (
            "macro_rules! leak { ($kind:ident $name:ident) => { pub $kind $name { password: Vec<u8> } }; }",
            false,
        ),
        (
            "macro_rules! leak { () => { impl Owner { fn method() { struct Hidden { password: Vec<u8> } } } }; }",
            false,
        ),
        ("macro_rules! leak { () => { another::items!(); }; }", false),
        ("macro_rules! leak { ($value:tt) => { $value }; }", false),
    ] {
        let tree = parse("src/macros.rs", source)?;
        let Some(syn::Item::Macro(item)) = tree.items.first() else {
            return Err(io::Error::other("missing macro fixture"));
        };
        match super::macros::classify("src/macros.rs", &item.mac) {
            Ok(()) => assert!(accepted, "unsafe transcriber accepted: {source}"),
            Err(error) => {
                assert!(!accepted, "safe transcriber rejected: {source}: {error}");
                assert!(
                    error
                        .to_string()
                        .starts_with("unsupported source src/macros.rs:1:")
                );
            }
        }
    }
    Ok(())
}

/// Syntax failures retain the actual line after inert text, including CRLF input.
#[test]
fn parser_reports_original_error_line() -> Result<(), io::Error> {
    for newline in ["\n", "\r\n"] {
        let source = [
            "// pub struct Decoy;",
            "const TEXT: &str = r###\"enum Decoy {}\"###;",
            "pub struct Broken { password: }",
        ]
        .join(newline);
        let Err(error) = parse("src/probe.rs", &source) else {
            return Err(io::Error::other("malformed field accepted"));
        };
        assert!(
            error
                .to_string()
                .starts_with("unsupported source src/probe.rs:3:"),
            "incorrect original source location: {error}"
        );
    }
    let Err(error) = declarations(
        "src/types.rs",
        "// header\n\npub struct Owner { password: *const u8 }",
    ) else {
        return Err(io::Error::other("opaque pointer storage accepted"));
    };
    assert!(
        error
            .to_string()
            .starts_with("unsupported source src/types.rs:3:")
    );
    Ok(())
}

/// Every unclassified source must fail explicitly, with its source location.
fn rejects(sources: &[&str]) -> Result<(), io::Error> {
    let mut missed = Vec::new();
    for source in sources {
        match declarations("src/probe.rs", source) {
            Err(error)
                if error
                    .to_string()
                    .contains("unsupported source src/probe.rs:") => {}
            result => missed.push(format!("{source}\nresult: {result:?}")),
        }
    }
    if missed.is_empty() {
        Ok(())
    } else {
        Err(io::Error::other(missed.join("\n")))
    }
}

/// Keyword fragments and opaque item calls cannot hide credential declarations.
#[test]
fn inventory_rejects_keyword_fragment_macros() -> Result<(), io::Error> {
    rejects(&[
        "macro_rules! owner { ($kind:ident $name:ident) => { #[derive(Debug)] pub $kind $name { password: Vec<u8> } }; } owner!(struct Leaked);",
        "macro_rules! owner { ($kind:ident $name:ident) => { #[derive(Debug)] pub $kind $name { Password(Vec<u8>) } }; } owner!(enum Leaked);",
        "external::owner!(Leaked);",
        "macro_rules! plain { ($value:expr) => { $value }; } plain!({ struct Hidden { password: Vec<u8> } });",
    ])
}

/// Standard crate spellings cannot conceal locally bound generic storage.
#[test]
fn inventory_rejects_standard_module_shadowing() -> Result<(), io::Error> {
    rejects(&[
        "mod core { pub type Payload<T = u8> = Vec<T>; } use core::Payload as Storage; #[derive(Debug)] pub struct Leaked { password: Storage }",
        "mod std { pub type Payload<T = u8> = Vec<T>; } use std::Payload as Storage; #[derive(Debug)] pub struct Leaked { password: Storage }",
        "mod hidden { pub type Payload = Vec<u8>; } use hidden::Payload as Storage; pub struct Leaked { password: Storage }",
        "mod hidden { pub type Payload = Vec<u8>; } pub struct Leaked { password: hidden::Payload }",
    ])
}

/// Direct, aliased and wrapped associated projections remain unclassified.
#[test]
fn inventory_rejects_associated_projections() -> Result<(), io::Error> {
    rejects(&[
        "trait HasPayload { type Payload; } pub struct Provider; impl HasPayload for Provider { type Payload = Vec<u8>; } #[derive(Debug)] pub struct Leaked { password: <Provider as HasPayload>::Payload }",
        "trait HasPayload { type Payload; } pub struct Provider; impl HasPayload for Provider { type Payload = Vec<u8>; } type Storage = <Provider as HasPayload>::Payload; pub struct Leaked { password: Storage }",
        "trait HasPayload { type Payload; } pub struct Provider; impl HasPayload for Provider { type Payload = Vec<u8>; } pub struct Leaked { password: Option<<Provider as HasPayload>::Payload> }",
        "pub struct Provider; pub struct Leaked { password: Provider::Payload }",
        "pub struct Leaked { password: UnknownStorage }",
    ])
}

/// Owner defaults cannot turn unresolved generic credential fields into scalars.
#[test]
fn inventory_rejects_generic_owner_defaults() -> Result<(), io::Error> {
    rejects(&[
        "#[derive(Debug)] pub struct Leaked<T = Vec<u8>> { password: T }",
        "#[derive(Debug)] pub struct Leaked<T = Vec<u8>> { password: Option<T> }",
        "#[derive(Debug)] pub struct Scalar<T = u32> { password: T }",
        "#[derive(Debug)] pub struct Scalar<T = u32> { password: Option<T> }",
    ])
}

/// Scalar storage and inert source text must not acquire secret ownership.
#[test]
fn inventory_preserves_nonsecret_controls() -> Result<(), io::Error> {
    for source in [
        "#[derive(Debug)] pub struct Scalar { password: u32 }",
        "use core::result::Result as Outcome; pub struct Scalar { value: Outcome<u32, u32> }",
        "/* owner!(struct Leaked); */ const TEXT: &str = r###\"pub struct Leaked { password: Vec<u8> }\"###; pub struct Scalar { password: u32 }",
    ] {
        let owners = declarations("src/probe.rs", source)?;
        assert_eq!(owners.len(), 1, "scalar owner omitted: {source}");
        assert!(
            secret_owners(&owners).is_empty(),
            "scalar classified secret: {source}"
        );
    }
    let plain = "macro_rules! plain { ($($value:expr),*) => { ($($value),*) }; } plain!(1, 2);";
    assert!(
        declarations("src/probe.rs", plain)?.is_empty(),
        "expression-only macro declares no owners"
    );
    Ok(())
}
