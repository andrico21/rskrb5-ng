//! Reject declarations in expression scopes that cannot enter the module inventory.

use std::io;

use syn::{
    Item,
    visit::{self, Visit},
};

use super::source::unsupported;

/// A block-local item has no module-level owner identity.
struct Nested<'file> {
    /// Physical file for diagnostics.
    file: &'file str,
    /// First source-completeness failure.
    error: Option<io::Error>,
}

impl<'ast> Visit<'ast> for Nested<'_> {
    fn visit_stmt(&mut self, i: &'ast syn::Stmt) {
        if let syn::Stmt::Item(item) = i {
            let span = match item {
                Item::Struct(owner) => Some(owner.ident.span()),
                Item::Enum(owner) => Some(owner.ident.span()),
                Item::Union(owner) => Some(owner.ident.span()),
                Item::Mod(module) => Some(module.ident.span()),
                Item::Macro(invocation) => Some(invocation.mac.bang_token.span),
                Item::Const(_)
                | Item::ExternCrate(_)
                | Item::Fn(_)
                | Item::ForeignMod(_)
                | Item::Impl(_)
                | Item::Static(_)
                | Item::Trait(_)
                | Item::TraitAlias(_)
                | Item::Type(_)
                | Item::Use(_)
                | Item::Verbatim(_)
                | _ => None,
            };
            if let Some(location) = span {
                self.error = Some(unsupported(
                    self.file,
                    location,
                    "block-local owner or item generator",
                ));
            }
        }
        visit::visit_stmt(self, i);
    }

    fn visit_item(&mut self, i: &'ast Item) {
        match super::configuration::attributes(i)
            .and_then(|attributes| super::configuration::included(self.file, attributes))
        {
            Ok(true) => visit::visit_item(self, i),
            Ok(false) => {}
            Err(error) => self.error = Some(error),
        }
    }
}

/// Traverse function, impl, const and closure bodies rather than silently skipping them.
pub(super) fn check(file: &str, items: &[Item]) -> Result<(), io::Error> {
    let mut nested = Nested { file, error: None };
    for item in items {
        nested.visit_item(item);
    }
    nested.error.map_or(Ok(()), Err)
}
