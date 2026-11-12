//! Admit only reviewed attribute expansions; bindings cannot impersonate approved derives.

use std::io;

use syn::{
    Attribute, Item, Meta, Token, UseTree,
    parse::Parser as _,
    punctuated::Punctuated,
    visit::{self, Visit},
};

use super::source::unsupported;

#[path = "attribute_derives.rs"]
mod attribute_derives;
use attribute_derives::DERIVES;

/// Compiler attributes and reviewed derive helpers do not generate independent owners.
const INERT: &[&str] = &[
    "cfg",
    "default",
    "doc",
    "allow",
    "warn",
    "deny",
    "forbid",
    "expect",
    "inline",
    "cold",
    "must_use",
    "repr",
    "non_exhaustive",
    "deprecated",
    "path",
    "macro_export",
    "error",
    "from",
    "source",
    "transparent",
    "serde",
    "zeroize",
    "rasn",
];

/// Import leaves determine the name introduced into the current namespace.
fn imports(tree: &UseTree, prefix: &str, names: &mut Vec<(String, String)>) {
    match tree {
        UseTree::Name(value) => {
            names.push((value.ident.to_string(), format!("{prefix}{}", value.ident)));
        }
        UseTree::Rename(value) => {
            names.push((value.rename.to_string(), format!("{prefix}{}", value.ident)));
        }
        UseTree::Path(value) => imports(&value.tree, &format!("{prefix}{}::", value.ident), names),
        UseTree::Group(value) => {
            for child in &value.items {
                imports(child, prefix, names);
            }
        }
        UseTree::Glob(_) => names.push(("*".to_owned(), String::new())),
    }
}

/// Only potentially shadowing names matter; unrelated imports remain usable.
#[derive(Default)]
struct Bindings(Vec<(String, String)>);

impl<'ast> Visit<'ast> for Bindings {
    fn visit_item(&mut self, i: &'ast Item) {
        let item = i;
        if let Ok(attributes) = super::configuration::attributes(item)
            && matches!(
                super::configuration::included("bindings", attributes),
                Ok(false)
            )
        {
            return;
        }
        match item {
            Item::Use(value) => imports(&value.tree, "", &mut self.0),
            Item::Mod(value) => self.0.push((value.ident.to_string(), String::new())),
            Item::ExternCrate(value) => self.0.push((
                value
                    .rename
                    .as_ref()
                    .map_or(&value.ident, |(_, alias)| alias)
                    .to_string(),
                String::new(),
            )),
            Item::Macro(value) => {
                if let Some(name) = &value.ident {
                    self.0.push((name.to_string(), String::new()));
                }
            }
            Item::Const(_)
            | Item::Enum(_)
            | Item::Fn(_)
            | Item::ForeignMod(_)
            | Item::Impl(_)
            | Item::Static(_)
            | Item::Struct(_)
            | Item::Trait(_)
            | Item::TraitAlias(_)
            | Item::Type(_)
            | Item::Union(_)
            | Item::Verbatim(_)
            | _ => {}
        }
    }
}

/// Keep the first refusal's original physical location.
struct Admission<'file> {
    /// Physical source path.
    file: &'file str,
    /// Local bindings may shadow a prelude derive or an external crate root.
    bindings: Vec<(String, String)>,
    /// A refused expansion makes the inventory incomplete.
    error: Option<io::Error>,
}

impl Admission<'_> {
    /// Parse conditional branches and derive paths rather than matching token text.
    ///
    /// # Errors
    /// Returns a located refusal for unclassified or shadowed expansions.
    fn meta(&self, meta: &Meta) -> Result<(), io::Error> {
        if let Meta::List(list) = meta {
            if list.path.is_ident("cfg_attr") {
                let nested = Punctuated::<Meta, Token![,]>::parse_terminated
                    .parse2(list.tokens.clone())
                    .map_err(|error| unsupported(self.file, error.span(), "opaque cfg_attr"))?;
                for attribute in nested.iter().skip(1) {
                    self.meta(attribute)?;
                }
                return Ok(());
            }
            if list.path.is_ident("derive") {
                let paths = Punctuated::<syn::Path, Token![,]>::parse_terminated
                    .parse2(list.tokens.clone())
                    .map_err(|error| unsupported(self.file, error.span(), "opaque derive"))?;
                for path in paths {
                    let name = path
                        .segments
                        .iter()
                        .map(|part| part.ident.to_string())
                        .collect::<Vec<_>>()
                        .join("::");
                    let root = path.segments.first().map(|part| part.ident.to_string());
                    let bound = self
                        .bindings
                        .iter()
                        .filter(|(binding, _)| Some(binding) == root.as_ref())
                        .collect::<Vec<_>>();
                    let admitted = match bound.as_slice() {
                        [] => DERIVES.contains(&name.as_str()),
                        [(_, target)] if path.segments.len() == 1 => {
                            DERIVES.contains(&target.as_str())
                                // Debug classification uses the written name. Until it
                                // carries resolved identities, refuse renamed Debug.
                                && !(matches!(
                                    target.as_str(),
                                    "Debug" | "core::fmt::Debug" | "std::fmt::Debug"
                                ) && name != "Debug")
                                && !self.bindings.iter().any(|(binding, _)| {
                                    target.split("::").next() == Some(binding.as_str())
                                })
                        }
                        [_] | [_, _, ..] => false,
                    };
                    if !admitted || self.bindings.iter().any(|(binding, _)| binding == "*") {
                        return Err(unsupported(
                            self.file,
                            list.delimiter.span().open(),
                            "opaque or shadowed derive",
                        ));
                    }
                }
                return Ok(());
            }
        }
        if [
            "error",
            "from",
            "source",
            "transparent",
            "serde",
            "zeroize",
            "rasn",
        ]
        .iter()
        .any(|name| meta.path().is_ident(name))
            && self
                .bindings
                .iter()
                .any(|(binding, _)| binding == "*" || meta.path().is_ident(binding))
        {
            return Err(unsupported(
                self.file,
                meta.path()
                    .segments
                    .first()
                    .map_or_else(proc_macro2::Span::call_site, |part| part.ident.span()),
                "shadowed helper attribute",
            ));
        }
        if INERT.iter().any(|name| meta.path().is_ident(name)) {
            return Ok(());
        }
        Err(unsupported(
            self.file,
            meta.path()
                .segments
                .first()
                .map_or_else(proc_macro2::Span::call_site, |part| part.ident.span()),
            "opaque attribute",
        ))
    }
}

impl<'ast> Visit<'ast> for Admission<'_> {
    fn visit_block(&mut self, i: &'ast syn::Block) {
        let previous = self.bindings.len();
        let mut local = Bindings::default();
        for statement in &i.stmts {
            if let syn::Stmt::Item(item) = statement {
                local.visit_item(item);
            }
        }
        self.bindings.extend(local.0);
        visit::visit_block(self, i);
        self.bindings.truncate(previous);
    }

    fn visit_item(&mut self, i: &'ast Item) {
        let item = i;
        let previous = self.bindings.len();
        if let Item::Mod(module) = item
            && let Some((_, children)) = &module.content
        {
            let mut local = Bindings::default();
            for child in children {
                local.visit_item(child);
            }
            self.bindings.extend(local.0);
        }
        match super::configuration::attributes(item)
            .and_then(|attributes| super::configuration::included(self.file, attributes))
        {
            Ok(true) => visit::visit_item(self, item),
            Ok(false) => {}
            Err(error) => self.error = Some(error),
        }
        self.bindings.truncate(previous);
    }

    fn visit_attribute(&mut self, i: &'ast Attribute) {
        if self.error.is_none() {
            self.error = self.meta(&i.meta).err();
        }
    }
}

/// Inspect the complete AST, including impl members, fields and file attributes.
///
/// # Errors
/// Returns the first located expansion refusal.
pub(super) fn check(file: &str, tree: &syn::File, scopes: &[&[Item]]) -> Result<(), io::Error> {
    let mut bindings = Bindings::default();
    for scope in scopes {
        for item in *scope {
            bindings.visit_item(item);
        }
    }
    let mut admission = Admission {
        file,
        bindings: bindings.0,
        error: None,
    };
    admission.visit_file(tree);
    admission.error.map_or(Ok(()), Err)
}
