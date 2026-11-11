//! Round-eight source inventory regressions use the real inventory boundary.

use std::io;

use super::{
    inventory::{declarations, secret_owners},
    lex::tokens,
};

/// Every unclassified source must fail explicitly, with its source location.
fn rejects(sources: &[&str]) -> Result<(), io::Error> {
    let mut missed = Vec::new();
    for source in sources {
        match declarations("src/probe.rs", &tokens(source)?) {
            Err(error)
                if error
                    .to_string()
                    .contains("unsupported source src/probe.rs:") => {}
            result => missed.push(format!("{source}\nresult: {result:?}")),
        }
    }
    assert!(missed.is_empty(), "{}", missed.join("\n"));
    Ok(())
}

/// Keyword fragments and opaque item calls cannot hide credential declarations.
#[test]
fn inventory_rejects_keyword_fragment_macros() -> Result<(), io::Error> {
    rejects(&[
        "macro_rules! owner { ($kind:ident $name:ident) => { #[derive(Debug)] pub $kind $name { password: Vec<u8> } }; } owner!(struct Leaked);",
        "macro_rules! owner { ($kind:ident $name:ident) => { #[derive(Debug)] pub $kind $name { Password(Vec<u8>) } }; } owner!(enum Leaked);",
        "external::owner!(Leaked);",
    ])
}

/// Standard crate spellings cannot conceal locally bound generic storage.
#[test]
fn inventory_rejects_standard_module_shadowing() -> Result<(), io::Error> {
    rejects(&[
        "mod core { pub type Payload<T = u8> = Vec<T>; } use core::Payload as Storage; #[derive(Debug)] pub struct Leaked { password: Storage }",
        "mod std { pub type Payload<T = u8> = Vec<T>; } use std::Payload as Storage; #[derive(Debug)] pub struct Leaked { password: Storage }",
    ])
}

/// Direct, aliased and wrapped associated projections remain unclassified.
#[test]
fn inventory_rejects_associated_projections() -> Result<(), io::Error> {
    rejects(&[
        "trait HasPayload { type Payload; } pub struct Provider; impl HasPayload for Provider { type Payload = Vec<u8>; } #[derive(Debug)] pub struct Leaked { password: <Provider as HasPayload>::Payload }",
        "trait HasPayload { type Payload; } pub struct Provider; impl HasPayload for Provider { type Payload = Vec<u8>; } type Storage = <Provider as HasPayload>::Payload; pub struct Leaked { password: Storage }",
        "trait HasPayload { type Payload; } pub struct Provider; impl HasPayload for Provider { type Payload = Vec<u8>; } pub struct Leaked { password: Option<<Provider as HasPayload>::Payload> }",
    ])
}

/// Owner defaults cannot turn unresolved generic credential fields into scalars.
#[test]
fn inventory_rejects_generic_owner_defaults() -> Result<(), io::Error> {
    rejects(&[
        "#[derive(Debug)] pub struct Leaked<T = Vec<u8>> { password: T }",
        "#[derive(Debug)] pub struct Leaked<T = Vec<u8>> { password: Option<T> }",
    ])
}

/// Scalar storage and inert source text must not acquire secret ownership.
#[test]
fn inventory_preserves_nonsecret_controls() -> Result<(), io::Error> {
    for source in [
        "#[derive(Debug)] pub struct Scalar<T = u32> { password: T }",
        "#[derive(Debug)] pub struct Scalar { password: u32 }",
        "use core::result::Result as Outcome; pub struct Scalar { value: Outcome<u32, u32> }",
        "/* owner!(struct Leaked); */ const TEXT: &str = r###\"pub struct Leaked { password: Vec<u8> }\"###; pub struct Scalar { password: u32 }",
    ] {
        let owners = declarations("src/probe.rs", &tokens(source)?)?;
        assert_eq!(owners.len(), 1, "scalar owner omitted: {source}");
        assert!(
            secret_owners(&owners).is_empty(),
            "scalar classified secret: {source}"
        );
    }
    let plain = "macro_rules! plain { ($($value:expr),*) => { ($($value),*) }; } plain!(1, 2);";
    assert!(
        declarations("src/probe.rs", &tokens(plain)?)?.is_empty(),
        "expression-only macro declares no owners"
    );
    Ok(())
}
