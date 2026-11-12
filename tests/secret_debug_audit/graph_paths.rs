//! Logical module paths preserve parent traversal and module import provenance.

use std::io;

use syn::Item;

use super::{Parsed, Scope, import_path, unsupported};

pub(super) fn concrete<'ast>(
    item: &'ast Item,
    name: &str,
) -> Option<(&'ast syn::Ident, &'ast syn::Generics)> {
    match item {
        Item::Struct(owner) if owner.ident == name => Some((&owner.ident, &owner.generics)),
        Item::Enum(owner) if owner.ident == name => Some((&owner.ident, &owner.generics)),
        Item::Union(owner) if owner.ident == name => Some((&owner.ident, &owner.generics)),
        Item::Const(_)
        | Item::Enum(_)
        | Item::ExternCrate(_)
        | Item::Fn(_)
        | Item::ForeignMod(_)
        | Item::Impl(_)
        | Item::Macro(_)
        | Item::Mod(_)
        | Item::Static(_)
        | Item::Struct(_)
        | Item::Trait(_)
        | Item::TraitAlias(_)
        | Item::Type(_)
        | Item::Union(_)
        | Item::Use(_)
        | Item::Verbatim(_)
        | _ => None,
    }
}

pub(super) fn module_segments(
    scope: &Scope<'_>,
    prefix: &[String],
) -> Result<Vec<String>, io::Error> {
    let mut segments: Vec<_> = scope
        .module
        .split("::")
        .filter(|part| !part.is_empty())
        .map(str::to_owned)
        .collect();
    let mut parts = prefix.iter().peekable();
    while let Some(part) = parts.peek() {
        match part.as_str() {
            "crate" => segments.clear(),
            "self" => {}
            "super" => {
                if segments.pop().is_none() {
                    return Err(unsupported(
                        scope.file,
                        proc_macro2::Span::call_site(),
                        "local path escapes crate root",
                    ));
                }
            }
            _ => break,
        }
        let _part = parts.next();
    }
    segments.extend(parts.cloned());
    Ok(segments)
}

pub(super) fn module_import<'ast>(
    scope: &'ast Scope<'_>,
    segments: &[String],
    name: &str,
) -> Option<(&'ast Parsed, Vec<String>)> {
    for (index, segment) in segments.iter().enumerate() {
        let parent = if index == 0 {
            String::new()
        } else {
            format!(
                "::{}",
                segments
                    .iter()
                    .take(index)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join("::")
            )
        };
        for unit in scope.graph.iter().filter(|unit| unit.module == parent) {
            for item in &unit.tree.items {
                if let Item::Use(import) = item
                    && let Some(mut imported) = import_path(&import.tree, segment, Vec::new())
                {
                    imported.extend(segments.iter().skip(index.saturating_add(1)).cloned());
                    imported.push(name.to_owned());
                    return Some((unit, imported));
                }
            }
        }
    }
    None
}
