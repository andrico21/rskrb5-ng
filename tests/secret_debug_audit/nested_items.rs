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
    definitions: Vec<&'file syn::ItemMacro>,
}

impl<'ast> Visit<'ast> for Nested<'_> {
    fn visit_macro(&mut self, i: &'ast syn::Macro) {
        if let Some(arguments) = super::replacement::macro_expressions(i) {
            for argument in &arguments {
                self.visit_expr(argument);
            }
            return;
        }
        if [
            "include_str",
            "include_bytes",
            "env",
            "option_env",
            "concat",
            "stringify",
            "line",
            "column",
            "file",
            "module_path",
            "cfg",
        ]
        .iter()
        .any(|name| i.path.is_ident(name))
        {
            return;
        }
        let candidates = self
            .definitions
            .iter()
            .filter(|definition| {
                definition
                    .ident
                    .as_ref()
                    .is_some_and(|name| i.path.is_ident(name))
            })
            .collect::<Vec<_>>();
        let result = if candidates.is_empty() {
            Err({
                unsupported(
                    self.file,
                    i.bang_token.span,
                    "unresolved expression generator",
                )
            })
        } else {
            candidates
                .iter()
                .try_for_each(|definition| super::macros::classify(self.file, &definition.mac))
                .and_then(|()| super::macros::arguments(self.file, i))
        };
        if let Err(error) = result {
            self.error = Some(error);
        }
    }
    fn visit_item_macro(&mut self, _: &'ast syn::ItemMacro) {}
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
    let mut definitions = Definitions::default();
    for item in items {
        definitions.visit_item(item);
    }
    let mut nested = Nested {
        file,
        error: None,
        definitions: definitions.0,
    };
    for item in items {
        nested.visit_item(item);
    }
    nested.error.map_or(Ok(()), Err)
}

#[derive(Default)]
struct Definitions<'ast>(Vec<&'ast syn::ItemMacro>);

impl<'ast> Visit<'ast> for Definitions<'ast> {
    fn visit_item_macro(&mut self, i: &'ast syn::ItemMacro) {
        if i.ident.is_some() {
            self.0.push(i);
        }
    }
}

#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
mod tests {
    use crate::declarations::declarations;
    #[test]
    fn expression_generators_cannot_hide_password_owners() {
        for body in [
            "pub fn make() -> impl core::fmt::Debug { make_owner!() }",
            "pub fn make() -> impl core::fmt::Debug { (|| make_owner!())() }",
            "const VALUE: () = { let _owner = make_owner!(); };",
            "pub trait Make { fn make() -> impl core::fmt::Debug { make_owner!() } }",
        ] {
            let source = format!(
                "macro_rules! make_owner {{ () => {{{{ #[derive(Debug)] struct Owner {{ password: Vec<u8> }} Owner {{ password: vec![65; 16] }} }}}}; }}\n{body}"
            );
            let result = declarations("src/probe.rs", &source);
            assert!(
                result.is_err(),
                "expression generator hid password owner: {result:?}"
            );
            assert!(
                result
                    .err()
                    .is_some_and(|error| error.to_string().contains("src/probe.rs:"))
            );
        }
    }
}
