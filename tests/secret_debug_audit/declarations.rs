//! Parsed owner declarations retain lexical module scope and attached attributes.

use std::io;

use proc_macro2::{Span, TokenStream};
use syn::{
    Attribute, Fields, Generics, Item, ItemMacro, Meta, Token, Visibility, parse::Parser as _,
    punctuated::Punctuated,
};

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
                    derived_debug: debug(&item.attrs)?,
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
                    derived_debug: debug(&item.attrs)?,
                });
            }
            Item::Union(item) if matches!(item.vis, Visibility::Public(_)) => {
                return Err(unsupported(
                    scope.file,
                    item.union_token.span,
                    "union storage requires an owning audit",
                ));
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
                invocation(scope, item)?;
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

/// Preserve original token locations even when Syn cannot classify an item.
fn first_span(tokens: &TokenStream) -> Span {
    tokens
        .clone()
        .into_iter()
        .next()
        .map_or_else(Span::call_site, |token| token.span())
}

/// An item invocation needs a locally visible definition with classifiable output.
fn invocation(scope: &Scope<'_>, item: &ItemMacro) -> Result<(), io::Error> {
    let Some(name) = item.mac.path.get_ident() else {
        return Err(unsupported(
            scope.file,
            item.mac.bang_token.span,
            "external item macro",
        ));
    };
    for candidate in scope.items.iter().rev().flat_map(|items| items.iter()) {
        if let Item::Macro(local) = candidate
            && local.ident.as_ref() == Some(name)
            && local.mac.path.is_ident("macro_rules")
        {
            super::macros::classify(scope.file, &local.mac)?;
            return super::macros::arguments(scope.file, &item.mac);
        }
    }
    Err(unsupported(
        scope.file,
        item.mac.bang_token.span,
        "unknown item macro",
    ))
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

/// Inspect derive lists and every `cfg_attr` branch without interpreting string contents.
fn debug(attributes: &[Attribute]) -> Result<bool, io::Error> {
    for attribute in attributes {
        if debug_meta(&attribute.meta)? {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Nested conditional attributes carry real meta syntax, not searchable prose.
fn debug_meta(meta: &Meta) -> Result<bool, io::Error> {
    let Meta::List(list) = meta else {
        return Ok(false);
    };
    if list.path.is_ident("derive") {
        let paths = Punctuated::<syn::Path, Token![,]>::parse_terminated
            .parse2(list.tokens.clone())
            .map_err(io::Error::other)?;
        return Ok(paths.iter().any(|path| {
            path.segments
                .last()
                .is_some_and(|segment| segment.ident == "Debug")
        }));
    }
    if list.path.is_ident("cfg_attr") {
        let nested = Punctuated::<Meta, Token![,]>::parse_terminated
            .parse2(list.tokens.clone())
            .map_err(io::Error::other)?;
        for attribute in nested.iter().skip(1) {
            if debug_meta(attribute)? {
                return Ok(true);
            }
        }
    }
    Ok(false)
}
