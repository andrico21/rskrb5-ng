//! Library module graph: all feature branches, excluding only proven test-only items.

use core::mem;
use std::{
    fs, io,
    path::{Path, PathBuf},
};

use syn::{Expr, Item, ItemMod, Lit, Meta};

use super::{
    configuration::{attributes, included},
    source::{Parsed, parse, unsupported},
};

/// Walk library module declarations and literal includes, never unrelated source files.
pub(super) fn load(path: &Path) -> Result<Vec<Parsed>, io::Error> {
    let directory = path
        .parent()
        .ok_or_else(|| io::Error::other("library parent"))?;
    file(path, directory, "", &mut Vec::new())
}

/// Canonical active paths bound both include and module recursion.
fn file(
    path: &Path,
    directory: &Path,
    module: &str,
    active: &mut Vec<PathBuf>,
) -> Result<Vec<Parsed>, io::Error> {
    let display = path.display().to_string();
    let canonical = path
        .canonicalize()
        .map_err(|error| io::Error::other(format!("unsupported source {display}:1: {error}")))?;
    if active.contains(&canonical) || active.len() >= 64 {
        return Err(io::Error::other(format!(
            "unsupported source {display}:1: source cycle or depth limit"
        )));
    }
    active.push(canonical);
    let mut tree = parse(&display, &fs::read_to_string(path)?)?;
    if !included(&display, &tree.attrs)? {
        drop(active.pop());
        return Ok(Vec::new());
    }
    let mut children = Vec::new();
    tree.items = items(path, directory, module, tree.items, active, &mut children)?;
    drop(active.pop());
    let mut output = vec![Parsed {
        module: module.to_owned(),
        path: path.to_path_buf(),
        tree,
    }];
    output.extend(children);
    Ok(output)
}

/// Retain feature branches while following each structurally selected source edge.
fn items(
    path: &Path,
    directory: &Path,
    module_scope: &str,
    input: Vec<Item>,
    active: &mut Vec<PathBuf>,
    children: &mut Vec<Parsed>,
) -> Result<Vec<Item>, io::Error> {
    let display = path.display().to_string();
    let mut output = Vec::new();
    for mut item in input {
        if !included(&display, attributes(&item)?)? {
            continue;
        }
        match &mut item {
            Item::Mod(module) => {
                if let Some((_, nested)) = &mut module.content {
                    *nested = items(
                        path,
                        &directory.join(module.ident.to_string()),
                        &format!("{module_scope}::{}", module.ident),
                        mem::take(nested),
                        active,
                        children,
                    )?;
                } else {
                    let target = module_path(path, directory, module)?;
                    let module_directory =
                        if target.file_name().is_some_and(|name| name == "mod.rs") {
                            target.parent().unwrap_or(directory).to_path_buf()
                        } else {
                            target.with_extension("")
                        };
                    children.extend(file(
                        &target,
                        &module_directory,
                        &format!("{module_scope}::{}", module.ident),
                        active,
                    )?);
                }
            }
            Item::Macro(invocation) if invocation.mac.path.is_ident("include") => {
                let literal =
                    syn::parse2::<syn::LitStr>(invocation.mac.tokens.clone()).map_err(|error| {
                        unsupported(&display, error.span(), "include requires literal path")
                    })?;
                let target = path.parent().unwrap_or(directory).join(literal.value());
                children.extend(file(&target, directory, module_scope, active).map_err(
                    |error| {
                        unsupported(&display, invocation.mac.bang_token.span, &error.to_string())
                    },
                )?);
                continue;
            }
            Item::Const(_)
            | Item::Enum(_)
            | Item::ExternCrate(_)
            | Item::Fn(_)
            | Item::ForeignMod(_)
            | Item::Impl(_)
            | Item::Macro(_)
            | Item::Static(_)
            | Item::Struct(_)
            | Item::Trait(_)
            | Item::TraitAlias(_)
            | Item::Type(_)
            | Item::Union(_)
            | Item::Use(_)
            | Item::Verbatim(_)
            | _ => {}
        }
        output.push(item);
    }
    Ok(output)
}

/// Literal module path attributes are parsed rather than inferred from file names.
fn module_path(including: &Path, directory: &Path, module: &ItemMod) -> Result<PathBuf, io::Error> {
    let display = including.display().to_string();
    let mut explicit = None;
    for attribute in &module.attrs {
        if attribute.path().is_ident("path") {
            if explicit.is_some() {
                return Err(unsupported(
                    &display,
                    module.ident.span(),
                    "duplicate module path",
                ));
            }
            let Meta::NameValue(value) = &attribute.meta else {
                return Err(unsupported(
                    &display,
                    module.ident.span(),
                    "unclassified module path",
                ));
            };
            let Expr::Lit(expression) = &value.value else {
                return Err(unsupported(
                    &display,
                    module.ident.span(),
                    "nonliteral module path",
                ));
            };
            let Lit::Str(literal) = &expression.lit else {
                return Err(unsupported(
                    &display,
                    module.ident.span(),
                    "nonstring module path",
                ));
            };
            explicit = Some(
                including
                    .parent()
                    .unwrap_or(directory)
                    .join(literal.value()),
            );
        }
    }
    if let Some(path) = explicit {
        return Ok(path);
    }
    let direct = directory.join(format!("{}.rs", module.ident));
    let nested = directory.join(module.ident.to_string()).join("mod.rs");
    match (direct.exists(), nested.exists()) {
        (true, false) => Ok(direct),
        (false, true) => Ok(nested),
        (true, true) | (false, false) => Err(unsupported(
            &display,
            module.ident.span(),
            "ambiguous or missing module file",
        )),
    }
}
