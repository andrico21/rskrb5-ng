//! Textual macro bindings are ordered independently of unordered type bindings.

use std::io;

use syn::{
    Item, ItemMacro,
    visit::{self, Visit},
};

use super::{resolve::Scope, source::unsupported};

/// Cross-file definitions have incomparable physical spans, including inline descendants.
struct Definitions<'name> {
    /// Binding whose provenance must remain local.
    name: &'name syn::Ident,
    /// A matching declaration exists in this physical source.
    found: bool,
}

impl<'ast> Visit<'ast> for Definitions<'_> {
    fn visit_item_macro(&mut self, i: &'ast ItemMacro) {
        self.found |= i.ident.as_ref() == Some(self.name);
        visit::visit_item_macro(self, i);
    }
}

/// A binding must precede its invocation in the innermost lexical scope.
pub(super) fn invocation(scope: &Scope<'_>, item: &ItemMacro) -> Result<(), io::Error> {
    let Some(name) = item.mac.path.get_ident() else {
        return Err(unsupported(
            scope.file,
            item.mac.bang_token.span,
            "external item macro",
        ));
    };
    for unit in scope.graph {
        let mut definitions = Definitions { name, found: false };
        definitions.visit_file(&unit.tree);
        if !unit.path.ends_with(scope.file) && definitions.found {
            return Err(unsupported(
                scope.file,
                item.mac.bang_token.span,
                "cross-file textual macro binding",
            ));
        }
    }
    for candidate in scope.items.iter().flat_map(|items| items.iter()) {
        if let Item::Mod(module) = candidate
            && module
                .attrs
                .iter()
                .any(|attribute| attribute.path().is_ident("macro_use"))
        {
            return Err(unsupported(
                scope.file,
                item.mac.bang_token.span,
                "macro-use textual scope",
            ));
        }
    }
    let position = item.mac.bang_token.span.start();
    for items in scope.items.iter().rev() {
        for candidate in items.iter().rev() {
            if let Item::Macro(local) = candidate
                && local.ident.as_ref() == Some(name)
                && local.mac.path.is_ident("macro_rules")
                && super::configuration::included(scope.file, &local.attrs)?
            {
                let definition = local.mac.bang_token.span.start();
                if (definition.line, definition.column) >= (position.line, position.column) {
                    continue;
                }
                if local.attrs.iter().any(|attribute| {
                    attribute.path().is_ident("cfg") || attribute.path().is_ident("cfg_attr")
                }) {
                    return Err(unsupported(
                        scope.file,
                        item.mac.bang_token.span,
                        "conditional macro binding",
                    ));
                }
                super::macros::classify(scope.file, &local.mac)?;
                return super::macros::arguments(scope.file, &item.mac);
            }
        }
    }
    Err(unsupported(
        scope.file,
        item.mac.bang_token.span,
        "unknown item macro",
    ))
}
