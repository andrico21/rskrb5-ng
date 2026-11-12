//! Lexical macro binding regressions at the owner inventory boundary.

use std::{env, fs, io, path::Path, process};

#[path = "physical_paths.rs"]
mod physical_paths;

/// Physical private storage must not disappear behind a qualified type path.
#[test]
fn inventory_accounts_for_physical_private_storage() -> Result<(), io::Error> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    for fixture in ["private_storage", "private_import"] {
        let result = super::inventory::inspect(
            root,
            &root.join("tests/secret_debug_audit/fixtures").join(fixture),
        );
        assert!(
            result.is_err(),
            "physical private password owner omitted: {result:?}"
        );
        let error = result
            .err()
            .ok_or_else(|| io::Error::other("private storage admitted"))?;
        assert!(error.to_string().contains("hidden.rs:2:"));
    }
    Ok(())
}

/// A physical re-export cannot hide a private credential owner from graph traversal.
#[test]
fn inventory_accounts_for_reexported_private_storage() -> Result<(), io::Error> {
    let root = env::temp_dir().join(format!("rskrb5-t62-reexport-{}", process::id()));
    fs::create_dir_all(&root)?;
    let result = (|| {
        fs::write(
            root.join("lib.rs"),
            "mod hidden; mod bridge; #[derive(Debug)] pub struct Outer { value: bridge::Storage }",
        )?;
        fs::write(
            root.join("hidden.rs"),
            "#[derive(Debug)]\npub(crate) struct Hidden { pub(crate) password: Vec<u8> }",
        )?;
        fs::write(
            root.join("bridge.rs"),
            "pub(crate) use crate::hidden::Hidden as Storage;",
        )?;
        let observed = super::inventory::inspect(&root, &root);
        let error = observed
            .err()
            .ok_or_else(|| io::Error::other("re-exported private credential omitted"))?;
        if !error.to_string().contains("hidden.rs:2:") {
            return Err(error);
        }
        Ok(())
    })();
    fs::remove_dir_all(&root)?;
    result
}

/// Generated owners require a located refusal rather than a partial inventory.
#[test]
fn inventory_refuses_opaque_attributes() -> Result<(), io::Error> {
    for source in [
        "#[external::owners] pub struct Marker;",
        "#[derive(external::Owners)] pub struct Marker;",
        "#[cfg_attr(feature = \"serde\", external::owners)] pub struct Marker;",
        "#[derive(Debug, external::Owners)] pub struct Marker;",
        "pub struct Marker; impl Marker { #[external::owners] pub fn make() {} }",
        "use external::Owners as Debug; #[derive(Debug)] pub struct Marker;",
        "use external as serde; #[derive(serde::Serialize)] pub struct Marker;",
        "mod serde {} #[derive(serde::Serialize)] pub struct Marker;",
        "use external::owners as serde; #[serde] pub struct Marker;",
    ] {
        drop(super::source::parse("src/attributes.rs", source)?);
        assert!(
            super::declarations::declarations("src/attributes.rs", source)
                .is_err_and(|error| error.to_string().contains("src/attributes.rs:1:")),
            "opaque expansion admitted: {source}"
        );
    }
    let owners = super::declarations::declarations(
        "src/attributes.rs",
        "#[derive(Clone, Debug)] #[repr(C)] #[must_use] pub struct Marker;",
    )?;
    assert_eq!(owners.len(), 1);
    Ok(())
}

/// Replacement discovery retains inline impls, transparent wrappers and opaque mutations.
#[test]
fn replacement_accounts_for_indirect_mutations() -> Result<(), io::Error> {
    for source in [
        "mod nested { impl Owner { pub fn set(&mut self, value: Vec<u8>) { self.secret = value; } } }",
        "impl Owner { pub fn set(&mut self, value: Vec<u8>) { (self.secret) = value; } }",
        "impl Owner { pub fn set(&mut self, value: Vec<u8>) { self.secret.swap_remove(0); } }",
        "impl Owner { pub fn set(&mut self, value: Vec<u8>) { replace_secret!(self, value); } }",
        "impl Owner { pub fn set(&mut self, value: Vec<u8>) { self.secret[0] = 0; } }",
        "impl Owner { pub fn set(&mut self, value: Vec<u8>) { self.secret += value; } }",
        "impl Owner { pub fn set(&mut self, value: Vec<u8>) { let secret = &mut self.secret; secret.clear(); } }",
        "impl Owner { pub fn set(&mut self, value: Vec<u8>) { self.secret.get(); } }",
    ] {
        drop(super::source::parse("src/mutation.rs", source)?);
        match super::replacement::methods("src/mutation.rs", source) {
            Ok(methods) => assert!(
                methods
                    .iter()
                    .any(|method| method.fields.iter().any(|field| field == "secret")),
                "mutation omitted: {methods:?}"
            ),
            Err(error) => assert!(error.to_string().contains("src/mutation.rs:1:"), "{error}"),
        }
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let methods = super::replacement::inspect(
        root,
        &root.join("tests/secret_debug_audit/fixtures/replacement"),
    )?;
    assert_eq!(methods.len(), 1);
    assert_eq!(
        methods.first().map(|method| method.fields.as_slice()),
        Some(["secret".to_owned()].as_slice())
    );
    Ok(())
}

/// Private wrappers and opaque function returns cannot hide credential owners.
#[test]
fn inventory_accounts_for_hidden_owners() -> Result<(), io::Error> {
    for (source, expected) in [
        (
            "#[derive(Debug)] struct Hidden { password: Vec<u8> } #[derive(Debug)] pub struct Outer { value: Hidden }",
            "src/hidden.rs::Outer",
        ),
        (
            "pub fn make() -> impl core::fmt::Debug { #[derive(Debug)] pub struct Owner { password: Vec<u8> } Owner { password: vec![65; 16] } }",
            "src/hidden.rs::make::Owner",
        ),
        (
            "pub struct Factory; impl Factory { pub fn make() -> impl core::fmt::Debug { #[derive(Debug)] struct Owner { password: Vec<u8> } Owner { password: vec![65; 16] } } }",
            "src/hidden.rs::Factory::make::Owner",
        ),
    ] {
        drop(super::source::parse("src/hidden.rs", source)?);
        match super::declarations::declarations("src/hidden.rs", source) {
            Ok(owners) => assert!(
                super::inventory::secret_owners(&owners)
                    .iter()
                    .any(|owner| owner == expected),
                "hidden credential omitted: {owners:?}"
            ),
            Err(error) => assert!(error.to_string().contains("src/hidden.rs:1:"), "{error}"),
        }
    }
    Ok(())
}

/// Inline alias chains must resolve to credentials or refuse at their source location.
#[test]
fn inventory_refuses_unresolved_inline_aliases() -> Result<(), io::Error> {
    for source in [
        "mod outer { pub mod inner { pub type Payload = Vec<u8>; } } pub struct Owner { password: outer::inner::Payload }",
        "mod a { pub type Payload = Vec<u8>; } mod b { pub use super::a::Payload as Storage; } use b::Storage; pub struct Owner { password: Storage }",
        "mod a { pub type Payload = Vec<u8>; } mod b { pub use super::a::Payload as Storage; } pub struct Owner { password: b::Storage }",
        "mod outer { pub mod inner { pub type Payload = Vec<u8>; } } pub struct Owner { password: self::outer::inner::Payload }",
    ] {
        drop(super::source::parse("src/alias.rs", source)?);
        match super::declarations::declarations("src/alias.rs", source) {
            Ok(owners) => assert_eq!(
                super::inventory::secret_owners(&owners),
                ["src/alias.rs::Owner"],
                "inline alias lost storage"
            ),
            Err(error) => assert!(error.to_string().contains("src/alias.rs:1:"), "{error}"),
        }
    }
    let owners = super::declarations::declarations(
        "src/scalar.rs",
        "pub struct Scalar { value: core::option::Option<u32> }",
    )?;
    assert!(
        super::inventory::secret_owners(&owners).is_empty(),
        "standard scalar became secret"
    );
    Ok(())
}

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
