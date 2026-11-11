//! Rust syntax parsing with original source locations for inventory failures.

use std::{
    fs, io,
    path::{Path, PathBuf},
};

use proc_macro2::Span;
use syn::File;

/// Extract an original field-type token span without enabling Syn's printing feature.
pub(super) fn type_span(ty: &syn::Type) -> Span {
    match ty {
        syn::Type::Array(value) => value.bracket_token.span.open(),
        syn::Type::FnPtr(value) => value.fn_token.span,
        syn::Type::Group(value) => value.group_token.span,
        syn::Type::ImplTrait(value) => value.impl_token.span,
        syn::Type::Infer(value) => value.underscore_token.span,
        syn::Type::Macro(value) => value.mac.bang_token.span,
        syn::Type::Never(value) => value.bang_token.span,
        syn::Type::Paren(value) => value.paren_token.span.open(),
        syn::Type::Path(value) => value
            .path
            .segments
            .first()
            .map_or_else(Span::call_site, |segment| segment.ident.span()),
        syn::Type::Ptr(value) => value.star_token.span,
        syn::Type::Reference(value) => value.and_token.span,
        syn::Type::Slice(value) => value.bracket_token.span.open(),
        syn::Type::TraitObject(value) => value
            .dyn_token
            .as_ref()
            .map_or_else(Span::call_site, |token| token.span),
        syn::Type::Tuple(value) => value.paren_token.span.open(),
        syn::Type::Verbatim(value) => value
            .clone()
            .into_iter()
            .next()
            .map_or_else(Span::call_site, |token| token.span()),
        _ => Span::call_site(),
    }
}

/// A parsed source file keeps its physical path for included-item diagnostics.
pub(super) struct Parsed {
    /// Path of the bytes parsed into this tree.
    pub path: PathBuf,
    /// Parsed item declarations.
    pub tree: File,
}

/// Load literal includes recursively, refusing unresolved paths and cycles.
pub(super) fn load(path: &Path) -> Result<Vec<Parsed>, io::Error> {
    load_inner(path, &mut Vec::new())
}

/// The active canonical path stack bounds expansion and detects include cycles.
fn load_inner(path: &Path, active: &mut Vec<PathBuf>) -> Result<Vec<Parsed>, io::Error> {
    let display = path.display().to_string();
    let canonical = path.canonicalize().map_err(|error| {
        io::Error::other(format!(
            "unsupported source {display}:1: unresolved source path: {error}"
        ))
    })?;
    if active.contains(&canonical) || active.len() >= 32 {
        return Err(io::Error::other(format!(
            "unsupported source {display}:1: include cycle or depth limit"
        )));
    }
    active.push(canonical);
    let tree = parse(&display, &fs::read_to_string(path)?)?;
    let mut included = Vec::new();
    include_items(path, &tree.items, active, &mut included)?;
    drop(active.pop());
    let mut output = vec![Parsed {
        path: path.to_path_buf(),
        tree,
    }];
    output.extend(included);
    Ok(output)
}

/// Inline modules retain the including file's directory for include resolution.
fn include_items(
    path: &Path,
    items: &[syn::Item],
    active: &mut Vec<PathBuf>,
    output: &mut Vec<Parsed>,
) -> Result<(), io::Error> {
    for declaration in items {
        match declaration {
            syn::Item::Macro(item) if item.mac.path.is_ident("include") => {
                let file = path.display().to_string();
                let literal =
                    syn::parse2::<syn::LitStr>(item.mac.tokens.clone()).map_err(|error| {
                        unsupported(&file, error.span(), "include requires one literal path")
                    })?;
                let target = path
                    .parent()
                    .unwrap_or_else(|| Path::new("."))
                    .join(literal.value());
                let children = load_inner(&target, active).map_err(|error| {
                    unsupported(&file, item.mac.bang_token.span, &error.to_string())
                })?;
                output.extend(children);
            }
            syn::Item::Mod(module) => {
                if let Some((_, nested)) = &module.content {
                    include_items(path, nested, active, output)?;
                }
            }
            syn::Item::Const(_)
            | syn::Item::Enum(_)
            | syn::Item::ExternCrate(_)
            | syn::Item::Fn(_)
            | syn::Item::ForeignMod(_)
            | syn::Item::Impl(_)
            | syn::Item::Macro(_)
            | syn::Item::Static(_)
            | syn::Item::Struct(_)
            | syn::Item::Trait(_)
            | syn::Item::TraitAlias(_)
            | syn::Item::Type(_)
            | syn::Item::Union(_)
            | syn::Item::Use(_)
            | syn::Item::Verbatim(_)
            | _ => {}
        }
    }
    Ok(())
}

/// Report a source shape the inventory cannot safely classify.
pub(super) fn unsupported(file: &str, span: Span, cause: &str) -> io::Error {
    io::Error::other(format!(
        "unsupported source {file}:{}: {cause}",
        span.start().line
    ))
}

/// Parse complete source without treating comments or literal text as items.
pub(super) fn parse(file: &str, source: &str) -> Result<File, io::Error> {
    syn::parse_file(source).map_err(|error| unsupported(file, error.span(), &error.to_string()))
}
