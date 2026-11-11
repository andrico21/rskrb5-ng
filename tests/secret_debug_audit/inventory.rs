//! Structural credential ownership discovery over every source feature branch.
// allow: SIZE_OK - declaration, alias and containment analysis form one fail-closed source inventory.

use std::{fs, io, path::Path};

use super::lex::{closing, tokens};

/// A public owner and its direct field declarations.
#[derive(Debug)]
pub(super) struct Owner {
    /// Full source-relative identity, including nested modules.
    pub identity: String,
    /// Unqualified type name used for nested owner propagation.
    pub name: String,
    /// Each named or positional field, visibility and type tokens.
    pub fields: Vec<(String, bool, Vec<String>)>,
    /// Whether an attached derive invokes Debug, including `cfg_attr` branches.
    pub derived_debug: bool,
}

/// Canonicalize aliases, rejecting referenced basenames whose scope is ambiguous.
fn resolve_aliases(words: &[String], field_type: &[String]) -> Result<Vec<String>, io::Error> {
    let mut mappings = Vec::new();
    let mut implementation_end = 0_usize;
    for (index, word) in words.iter().enumerate() {
        if index < implementation_end {
            continue;
        }
        if word == "impl"
            && let Some(open) = words
                .iter()
                .enumerate()
                .skip(index)
                .find_map(|(position, item)| (item == "{").then_some(position))
        {
            implementation_end = closing(words, open)?.saturating_add(1);
            continue;
        }
        if word == "as"
            && let (Some(original), Some(alias)) = (
                index
                    .checked_sub(1)
                    .and_then(|position| words.get(position)),
                words.get(index.saturating_add(1)),
            )
        {
            let import = words.get(..index).unwrap_or_default();
            let start = import
                .iter()
                .rposition(|item| item == "use")
                .unwrap_or(index);
            let standard = import
                .get(start.saturating_add(1))
                .is_some_and(|root| matches!(root.as_str(), "core" | "std"));
            mappings.push((alias.clone(), Some(vec![original.clone()]), !standard));
        }
        if word == "type"
            && let Some(alias) = words.get(index.saturating_add(1))
        {
            let rest = words.get(index.saturating_add(2)..).unwrap_or_default();
            if rest.first().is_some_and(|item| item == "=")
                && let Some(end) = rest.iter().position(|item| item == ";")
            {
                mappings.push((
                    alias.clone(),
                    Some(rest.get(1..end).unwrap_or_default().to_vec()),
                    true,
                ));
            }
            if rest.first().is_some_and(|item| item == "<") {
                // Substitution and defaults need a scoped generic parser. Until then,
                // retain the alias identity so a reference cannot become nonsecret.
                mappings.push((alias.clone(), None, true));
            }
        }
    }
    let mut output: Vec<_> = field_type
        .iter()
        .cloned()
        .map(|word| (word, true))
        .collect();
    for _ in 0..mappings.len() {
        output = output
            .into_iter()
            .map(|(word, local)| {
                if !local {
                    return Ok(vec![(word, false)]);
                }
                let mut matches = mappings.iter().filter(|(alias, _, _)| *alias == word);
                let mapping = matches.next();
                if matches.next().is_some() {
                    return Err(io::Error::other(format!("ambiguous alias {word}")));
                }
                match mapping {
                    Some((_, Some(target), expand)) => {
                        Ok(target.iter().cloned().map(|item| (item, *expand)).collect())
                    }
                    Some((_, None, _)) => {
                        Err(io::Error::other(format!("unresolved generic alias {word}")))
                    }
                    None => Ok(vec![(word, true)]),
                }
            })
            .collect::<Result<Vec<_>, io::Error>>()?
            .into_iter()
            .flatten()
            .collect();
    }
    Ok(output.into_iter().map(|(word, _)| word).collect())
}

/// Match a referenced owner in its module, or an unambiguous cross-module type.
fn references(owner: &Owner, ty: &[String], target: &Owner, all: &[Owner]) -> bool {
    if !ty.contains(&target.name) {
        return false;
    }
    let owner_file = owner
        .identity
        .rsplit_once("::")
        .map_or("", |(file, _)| file);
    let target_file = target
        .identity
        .rsplit_once("::")
        .map_or("", |(file, _)| file);
    if owner_file == target_file {
        return true;
    }
    if all
        .iter()
        .filter(|candidate| candidate.name == target.name)
        .count()
        == 1
    {
        return true;
    }
    let module = target_file
        .strip_prefix("src/")
        .unwrap_or(target_file)
        .trim_end_matches(".rs")
        .rsplit('/')
        .next()
        .unwrap_or_default();
    ty.windows(4).any(|path| matches!(path, [prefix, first, second, name] if prefix == module && first == ":" && second == ":" && *name == target.name))
}

/// Split declarations at commas outside generic arguments and balanced delimiters.
fn fields(words: &[String]) -> Result<Vec<(String, bool, Vec<String>)>, io::Error> {
    let mut result = Vec::new();
    let mut start = 0_usize;
    let mut index = 0_usize;
    let mut generics = 0_usize;
    while index <= words.len() {
        match words.get(index).map(String::as_str) {
            Some("(" | "[" | "{") => index = closing(words, index)?,
            Some("<") => generics = generics.saturating_add(1),
            Some(">") => generics = generics.saturating_sub(1),
            Some(",") | None if generics == 0 => {
                let part = words
                    .get(start..index)
                    .ok_or_else(|| io::Error::other("field extent"))?;
                if !part.is_empty() {
                    let mut field = 0_usize;
                    while part.get(field).is_some_and(|word| word == "#") {
                        field = closing(part, field.saturating_add(1))?.saturating_add(1);
                    }
                    let visible = part.get(field).is_some_and(|word| word == "pub");
                    let public = visible
                        && part
                            .get(field.saturating_add(1))
                            .is_none_or(|word| word != "(");
                    if visible {
                        field = field.saturating_add(1);
                        if part.get(field).is_some_and(|word| word == "(") {
                            field = closing(part, field)?.saturating_add(1);
                        }
                    }
                    let named = part
                        .get(field.saturating_add(1))
                        .is_some_and(|word| word == ":")
                        && part
                            .get(field.saturating_add(2))
                            .is_none_or(|word| word != ":");
                    let name = if named {
                        part.get(field)
                            .cloned()
                            .ok_or_else(|| io::Error::other("field name"))?
                    } else {
                        result.len().to_string()
                    };
                    let ty_start = if named {
                        field.saturating_add(2)
                    } else {
                        field
                    };
                    let ty = part
                        .get(ty_start..)
                        .ok_or_else(|| io::Error::other("field type"))?
                        .to_vec();
                    if ty.is_empty() {
                        return Err(io::Error::other("empty field type"));
                    }
                    result.push((name, public, ty));
                }
                start = index.saturating_add(1);
            }
            _ => {}
        }
        index = index.saturating_add(1);
    }
    if generics != 0 {
        return Err(io::Error::other("unbalanced generic field"));
    }
    Ok(result)
}

/// Inspect declaration tokens without losing attributes or macro-generated public items.
pub(super) fn declarations(file: &str, words: &[String]) -> Result<Vec<Owner>, io::Error> {
    let mut owners = Vec::new();
    let mut index = 0_usize;
    let mut attributes = Vec::new();
    while let Some(word) = words.get(index) {
        if word == "macro_rules" {
            attributes.clear();
            index = macro_end(words, index)?.saturating_add(1);
            continue;
        }
        if word == "#"
            && words
                .get(index.saturating_add(1))
                .is_some_and(|item| item == "[")
        {
            let end = closing(words, index.saturating_add(1))?;
            attributes.extend_from_slice(
                words
                    .get(index..=end)
                    .ok_or_else(|| io::Error::other("attribute"))?,
            );
            index = end.saturating_add(1);
            continue;
        }
        if word == "pub"
            && words
                .get(index.saturating_add(1))
                .is_some_and(|item| matches!(item.as_str(), "struct" | "enum"))
        {
            let name = words
                .get(index.saturating_add(2))
                .ok_or_else(|| io::Error::other("owner name"))?
                .clone();
            let start = words
                .iter()
                .enumerate()
                .skip(index.saturating_add(3))
                .find(|(_, item)| matches!(item.as_str(), "{" | "(" | ";"))
                .map(|(position, _)| position)
                .ok_or_else(|| io::Error::other("owner body"))?;
            let end = if words.get(start).is_some_and(|item| item == ";") {
                start
            } else {
                closing(words, start)?
            };
            let body = words.get(start.saturating_add(1)..end).unwrap_or_default();
            let mut members = fields(body)?;
            if words
                .get(index.saturating_add(1))
                .is_some_and(|item| item == "enum")
            {
                let mut variants = Vec::new();
                for (variant, _, ty) in members {
                    let variant_name = ty.first().unwrap_or(&variant);
                    if let Some(open) = ty
                        .iter()
                        .position(|item| matches!(item.as_str(), "(" | "{"))
                    {
                        let finish = closing(&ty, open)?;
                        for (field_name, _, field) in fields(
                            ty.get(open.saturating_add(1)..finish)
                                .ok_or_else(|| io::Error::other("variant"))?,
                        )? {
                            variants.push((format!("{variant_name}.{field_name}"), false, field));
                        }
                    }
                }
                members = variants;
            }
            owners.push(Owner {
                identity: format!("{file}::{name}"),
                name,
                fields: members
                    .into_iter()
                    .map(|(field, public, ty)| Ok((field, public, resolve_aliases(words, &ty)?)))
                    .collect::<Result<_, io::Error>>()?,
                derived_debug: attributes.iter().any(|item| item == "derive")
                    && attributes.iter().any(|item| item == "Debug"),
            });
            attributes.clear();
            index = end.saturating_add(1);
            continue;
        }
        if word != "pub" {
            attributes.clear();
        }
        index = index.saturating_add(1);
    }
    Ok(owners)
}

/// Reject unexpanded declaration macros before their opaque visibility can hide owners.
fn macro_end(words: &[String], start: usize) -> Result<usize, io::Error> {
    let open = words
        .iter()
        .enumerate()
        .skip(start)
        .find_map(|(position, item)| matches!(item.as_str(), "{" | "(" | "[").then_some(position))
        .ok_or_else(|| io::Error::other("macro body"))?;
    let end = closing(words, open)?;
    let body = words
        .get(open..=end)
        .ok_or_else(|| io::Error::other("macro extent"))?;
    if body
        .iter()
        .any(|item| matches!(item.as_str(), "struct" | "enum"))
    {
        return Err(io::Error::other("unsupported macro visibility declaration"));
    }
    Ok(end)
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

/// Read all Rust files, independent of enabled build features.
pub(super) fn inspect(root: &Path, directory: &Path) -> Result<Vec<Owner>, io::Error> {
    let mut owners = Vec::new();
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        if path.is_dir() {
            owners.extend(inspect(root, &path)?);
            continue;
        }
        if path.extension().is_some_and(|extension| extension == "rs") {
            let relative = path
                .strip_prefix(root)
                .map_err(io::Error::other)?
                .to_string_lossy()
                .replace('\\', "/");
            owners.extend(declarations(
                &relative,
                &tokens(&fs::read_to_string(path)?)?,
            )?);
        }
    }
    Ok(owners)
}

/// Recognize secret byte storage by name and explicit owner types, including aliases.
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
                    | "ApRep"
                    | "KrbPriv"
                    | "KrbCred"
                    | "Authenticator"
                    | "EncKrbCredPart"
                    | "EncKrbPrivPart"
            )
        })
}
