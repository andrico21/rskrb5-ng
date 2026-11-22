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
/// The module whose name a path must carry to reach an owner of an
/// `include!`d GSS file whose short name another module also uses (the GSS
/// `Credential`, `Initiator`, `Acceptor` and `Name` beside the ccache,
/// keytab and SPNEGO ones), or `None` for every other owner.
fn qualified_module(identity: &str) -> Option<&'static str> {
    if identity.starts_with("src/gss/") {
        Some("gss")
    } else if identity.starts_with("src/spnego/gss_types.rs") {
        Some("spnego")
    } else {
        None
    }
}

fn references(owner: &Owner, ty: &[String], target: &Owner, all: &[Owner]) -> bool {
    if !ty.contains(&target.name) {
        return false;
    }
    if let Some(module) = qualified_module(&target.identity) {
        let same_module = owner.identity.starts_with("src/gss") && module == "gss";
        return same_module
            || ty.windows(2).any(
                |path| matches!(path, [prefix, name] if prefix == module && *name == target.name),
            );
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
            .filter(|candidate| {
                candidate.name == target.name && qualified_module(&candidate.identity).is_none()
            })
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

/// The registered secret owners of an inventory and the fields that store credentials through them.
pub(super) struct Storage<'owners> {
    owners: &'owners [Owner],
    secret: Vec<String>,
}

impl<'owners> Storage<'owners> {
    /// Register every owner that holds credential storage, directly or through another registered owner.
    pub(super) fn new(owners: &'owners [Owner]) -> Self {
        Self {
            owners,
            secret: secret_owners(owners),
        }
    }

    /// Whether the field stores a credential by its own shape or holds a registered secret owner, whatever that type is called.
    pub(super) fn field(&self, owner: &Owner, name: &str, ty: &[String]) -> bool {
        !super::nonsecret::contains(&owner.identity, name)
            && (secret_field(name, ty) || self.holds_owner(owner, ty))
    }

    /// The declared owners the registry was built from.
    pub(super) fn owners(&self) -> &'owners [Owner] {
        self.owners
    }

    /// Whether the owner identity is a registered secret owner.
    pub(super) fn contains(&self, identity: &str) -> bool {
        self.secret.iter().any(|registered| registered == identity)
    }

    fn holds_owner(&self, owner: &Owner, ty: &[String]) -> bool {
        self.owners.iter().any(|target| {
            self.secret.contains(&target.identity) && references(owner, ty, target, self.owners)
        })
    }
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
        let previous = Storage {
            owners,
            secret: secret.clone(),
        };
        for owner in owners {
            if owner.fields.iter().any(|(name, _, ty)| {
                !super::nonsecret::contains(&owner.identity, name)
                    && previous.holds_owner(owner, ty)
            }) && !secret.contains(&owner.identity)
            {
                secret.push(owner.identity.clone());
            }
        }
        if secret == previous.secret {
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

/// Store traits whose objects may own credentials: a MEMORY cache handle or
/// collection owns `CCache`s, a key store owns keys, a provider owns stores.
const CREDENTIAL_TRAITS: [&str; 6] = [
    "CacheHandle",
    "CacheCollection",
    "CredentialStore",
    "KeyStore",
    "KeytabType",
    "StoreProvider",
];

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
            ) || CREDENTIAL_TRAITS.contains(&word.as_str())
        })
}
