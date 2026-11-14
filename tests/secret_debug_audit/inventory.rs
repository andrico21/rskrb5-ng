//! Credential inventory follows the library module graph across every feature branch.
//! Only structurally proven test-only items are excluded; opaque source fails closed.

use std::{io, path::Path};

/// A public owner and its structurally resolved field declarations.
#[derive(Debug)]
pub(super) struct Owner {
    /// Full physical source identity, including inline modules.
    pub identity: String,
    /// Unqualified declaration name.
    pub name: String,
    /// Field name, public visibility, and resolved storage components.
    pub fields: Vec<(String, bool, Vec<String>)>,
    /// An attached unconditional or conditional Debug derive.
    pub derived_debug: bool,
}

/// Match same-scope owners or unique cross-module owner references.
fn references(owner: &Owner, ty: &[String], target: &Owner, all: &[Owner]) -> bool {
    if !ty.contains(&target.name) {
        return false;
    }
    let owner_scope = owner
        .identity
        .rsplit_once("::")
        .map_or("", |(scope, _)| scope);
    let target_scope = target
        .identity
        .rsplit_once("::")
        .map_or("", |(scope, _)| scope);
    if owner_scope == target_scope
        || all
            .iter()
            .filter(|candidate| candidate.name == target.name)
            .count()
            == 1
    {
        return true;
    }
    let module = target_scope
        .strip_prefix("src/")
        .unwrap_or(target_scope)
        .trim_end_matches(".rs")
        .rsplit('/')
        .next()
        .unwrap_or_default();
    ty.windows(2)
        .any(|path| matches!(path, [prefix, name] if prefix == module && *name == target.name))
}

/// Propagate secret ownership through containers without relying on field spelling.
pub(super) fn secret_owners(owners: &[Owner]) -> Vec<String> {
    let mut secret: Vec<String> = owners
        .iter()
        .filter(|owner| {
            owner.fields.iter().any(|(name, _, ty)| {
                secret_field(name, ty) && !super::nonsecret::contains(&owner.identity, name)
            })
        })
        .map(|owner| owner.identity.clone())
        .collect();
    for _ in 0..owners.len() {
        let previous = secret.clone();
        for owner in owners {
            if owner.fields.iter().any(|(name, _, ty)| {
                !super::nonsecret::contains(&owner.identity, name)
                    && owners.iter().any(|target| {
                        previous.contains(&target.identity) && references(owner, ty, target, owners)
                    })
            }) && !secret.contains(&owner.identity)
            {
                secret.push(owner.identity.clone());
            }
        }
        if secret == previous {
            break;
        }
    }
    secret
}

/// Follow literal source edges; never inventory test support by directory proximity.
pub(super) fn inspect(root: &Path, directory: &Path) -> Result<Vec<Owner>, io::Error> {
    let mut owners = Vec::new();
    let graph = super::graph::load(&directory.join("lib.rs"))?;
    for unit in &graph {
        let relative = unit
            .path
            .strip_prefix(root)
            .map_err(io::Error::other)?
            .to_string_lossy()
            .replace('\\', "/");
        owners.extend(super::declarations::graph_unit(&relative, unit, &graph)?);
    }
    Ok(owners)
}

/// Classify resolved byte storage, known credential and session owners and unconstrained generic storage.
pub(super) fn secret_field(name: &str, ty: &[String]) -> bool {
    let secret_name = [
        "key",
        "secret",
        "password",
        "passwd",
        "token",
        "ticket",
        "ccache",
        "hash",
        "payload",
        "credential",
        "nt_",
        "lm_",
        "cipher",
        "padata",
        "checksum",
        "der",
        "e_data",
    ]
    .iter()
    .any(|needle| name.contains(needle));
    let bytes = ty
        .iter()
        .any(|word| matches!(word.as_str(), "u8" | "Bytes" | "OctetString" | "String"));
    (secret_name && bytes)
        || ty.iter().any(|word| {
            matches!(
                word.as_str(),
                "Zeroizing"
                    | "GenericStorage"
                    | "EncryptionKey"
                    | "KeyBytes"
                    | "key_bytes"
                    | "password"
                    | "SessionKey"
                    | "Password"
                    | "Secret"
                    | "PaData"
                    | "Ticket"
                    | "Checksum"
                    | "ApReq"
                    | "AsReq"
                    | "TgsReq"
                    | "Keytab"
                    | "ApRep"
                    | "KrbPriv"
                    | "KrbCred"
                    | "Authenticator"
                    | "EncKrbCredPart"
                    | "EncKrbPrivPart"
                    | "AsRepSession"
                    | "TgsRepSession"
                    | "TokioClientCredentials"
            )
        })
}
