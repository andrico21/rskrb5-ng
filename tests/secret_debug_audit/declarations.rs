//! Parsed owner declarations retain lexical module scope and attached attributes.

use std::io;

use proc_macro2::{Span, TokenStream};
use syn::{Fields, Generics, Item, Visibility};

use super::{
    inventory::Owner,
    resolve::Scope,
    source::{parse, unsupported},
};

/// Inventory one complete source unit without expanding opaque item invocations.
pub(super) fn declarations(file: &str, text: &str) -> Result<Vec<Owner>, io::Error> {
    let tree = parse(file, text)?;
    parsed(file, &tree)
}

/// Inspect a loaded tree after source-graph selection without losing physical spans.
pub(super) fn parsed(file: &str, tree: &syn::File) -> Result<Vec<Owner>, io::Error> {
    scoped(file, tree, vec![tree.items.as_slice()])
}

/// A library source unit resolves file-module aliases using the complete loaded graph.
pub(super) fn graph_unit(
    file: &str,
    unit: &super::source::Parsed,
    graph: &[super::source::Parsed],
) -> Result<Vec<Owner>, io::Error> {
    let generics = Generics::default();
    let scope = Scope {
        file,
        items: graph
            .iter()
            .filter(|candidate| candidate.module == unit.module)
            .map(|candidate| candidate.tree.items.as_slice())
            .collect(),
        generics: &generics,
        graph,
        module: &unit.module,
    };
    items_from(&scope, file, &unit.tree.items)
}

/// Included files contribute bindings to their actual enclosing module.
pub(super) fn scoped<'ast>(
    file: &'ast str,
    tree: &'ast syn::File,
    scopes: Vec<&'ast [Item]>,
) -> Result<Vec<Owner>, io::Error> {
    let generics = Generics::default();
    let scope = Scope {
        file,
        items: scopes,
        generics: &generics,
        graph: &[],
        module: "",
    };
    items_from(&scope, file, &tree.items)
}

/// Read each lexical module independently while retaining its parent bindings.
fn items(scope: &Scope<'_>, identity: &str) -> Result<Vec<Owner>, io::Error> {
    items_from(
        scope,
        identity,
        scope.items.last().copied().unwrap_or_default(),
    )
}

/// Bindings may span includes; emitted owners belong only to the current source unit.
fn items_from(
    scope: &Scope<'_>,
    identity: &str,
    declarations: &[Item],
) -> Result<Vec<Owner>, io::Error> {
    let mut owners = Vec::new();
    for declaration in declarations {
        if !super::configuration::included(
            scope.file,
            super::configuration::attributes(declaration)?,
        )? {
            continue;
        }
        match declaration {
            Item::Struct(item) if matches!(item.vis, Visibility::Public(_)) => {
                let nested = Scope {
                    file: scope.file,
                    items: scope.items.clone(),
                    generics: &item.generics,
                    graph: scope.graph,
                    module: scope.module,
                };
                owners.push(Owner {
                    identity: format!("{identity}::{}", item.ident),
                    name: item.ident.to_string(),
                    fields: fields(&nested, &item.fields, "")?,
                    derived_debug: super::configuration::debug(&item.attrs)?,
                });
            }
            Item::Enum(item) if matches!(item.vis, Visibility::Public(_)) => {
                let nested = Scope {
                    file: scope.file,
                    items: scope.items.clone(),
                    generics: &item.generics,
                    graph: scope.graph,
                    module: scope.module,
                };
                let mut members = Vec::new();
                for variant in &item.variants {
                    members.extend(fields(
                        &nested,
                        &variant.fields,
                        &format!("{}.", variant.ident),
                    )?);
                }
                owners.push(Owner {
                    identity: format!("{identity}::{}", item.ident),
                    name: item.ident.to_string(),
                    fields: members,
                    derived_debug: super::configuration::debug(&item.attrs)?,
                });
            }
            Item::Union(item) if matches!(item.vis, Visibility::Public(_)) => {
                owners.push(union(scope, identity, item)?);
            }
            Item::Mod(module) => {
                if let Some((_, content)) = &module.content {
                    let mut scopes = scope.items.clone();
                    scopes.push(content);
                    let nested = Scope {
                        file: scope.file,
                        items: scopes,
                        generics: scope.generics,
                        graph: scope.graph,
                        module: scope.module,
                    };
                    owners.extend(items(&nested, &format!("{identity}::{}", module.ident))?);
                }
            }
            Item::Macro(item) if item.ident.is_some() && item.mac.path.is_ident("macro_rules") => {}
            Item::Macro(item) => {
                super::macro_scope::invocation(scope, item)?;
            }
            Item::Const(_)
            | Item::Enum(_)
            | Item::ExternCrate(_)
            | Item::Fn(_)
            | Item::ForeignMod(_)
            | Item::Impl(_)
            | Item::Static(_)
            | Item::Struct(_)
            | Item::Trait(_)
            | Item::TraitAlias(_)
            | Item::Type(_)
            | Item::Union(_)
            | Item::Use(_) => {}
            Item::Verbatim(tokens) => {
                return Err(unsupported(scope.file, first_span(tokens), "unparsed item"));
            }
            _ => {
                return Err(unsupported(
                    scope.file,
                    Span::call_site(),
                    "unsupported item",
                ));
            }
        }
    }
    Ok(owners)
}

/// Union fields are independent storage alternatives and all require classification.
fn union(scope: &Scope<'_>, identity: &str, item: &syn::ItemUnion) -> Result<Owner, io::Error> {
    let nested = Scope {
        file: scope.file,
        items: scope.items.clone(),
        generics: &item.generics,
        graph: scope.graph,
        module: scope.module,
    };
    let mut members = Vec::new();
    for field in &item.fields.named {
        if super::configuration::included(scope.file, &field.attrs)? {
            let name = field
                .ident
                .as_ref()
                .ok_or_else(|| unsupported(scope.file, item.ident.span(), "unnamed union field"))?;
            members.push((
                name.to_string(),
                matches!(field.vis, Visibility::Public(_)),
                nested.resolve(&field.ty)?,
            ));
        }
    }
    Ok(Owner {
        identity: format!("{identity}::{}", item.ident),
        name: item.ident.to_string(),
        fields: members,
        derived_debug: super::configuration::debug(&item.attrs)?,
    })
}

/// Preserve original token locations even when Syn cannot classify an item.
fn first_span(tokens: &TokenStream) -> Span {
    tokens
        .clone()
        .into_iter()
        .next()
        .map_or_else(Span::call_site, |token| token.span())
}

/// Named and positional fields preserve visibility and structurally resolved storage.
fn fields(
    scope: &Scope<'_>,
    fields: &Fields,
    prefix: &str,
) -> Result<Vec<(String, bool, Vec<String>)>, io::Error> {
    fields
        .iter()
        .enumerate()
        .filter_map(|(index, field)| {
            match super::configuration::included(scope.file, &field.attrs) {
                Ok(true) => Some(Ok((index, field))),
                Ok(false) => None,
                Err(error) => Some(Err(error)),
            }
        })
        .map(|entry| {
            let (index, field) = entry?;
            let name = field
                .ident
                .as_ref()
                .map_or_else(|| index.to_string(), ToString::to_string);
            Ok((
                format!("{prefix}{name}"),
                prefix.is_empty() && matches!(field.vis, Visibility::Public(_)),
                scope.resolve(&field.ty)?,
            ))
        })
        .collect()
}
