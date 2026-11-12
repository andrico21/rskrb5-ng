//! Lexical binding admission for standard expression-macro contracts.

extern crate alloc;

use alloc::collections::BTreeSet;
use std::io;

use syn::{
    Item, UseTree,
    visit::{self, Visit},
};

use crate::{
    configuration, nested_items,
    source::{Parsed, unsupported},
};

#[derive(Default)]
struct Bindings {
    names: BTreeSet<String>,
    wildcard: bool,
}

impl Bindings {
    fn imports(&mut self, tree: &UseTree) {
        match tree {
            UseTree::Name(name) => {
                let _inserted = self.names.insert(name.ident.to_string());
            }
            UseTree::Rename(rename) => {
                let _inserted = self.names.insert(rename.rename.to_string());
            }
            UseTree::Path(path) => self.imports(&path.tree),
            UseTree::Group(group) => {
                for item in &group.items {
                    self.imports(item);
                }
            }
            UseTree::Glob(_) => self.wildcard = true,
        }
    }
}

struct Check<'source> {
    file: &'source str,
    scopes: Vec<Bindings>,
    error: Option<io::Error>,
}

impl Check<'_> {
    fn enter<'ast>(&mut self, items: impl Iterator<Item = &'ast Item>) {
        let mut bindings = Bindings::default();
        for item in items {
            match configuration::attributes(item)
                .and_then(|attrs| configuration::included(self.file, attrs))
            {
                Ok(false) => continue,
                Err(error) => {
                    self.error = Some(error);
                    continue;
                }
                Ok(true) => {}
            }
            if let Item::Use(import) = item {
                bindings.imports(&import.tree);
            }
            if configuration::attributes(item)
                .is_ok_and(|attrs| attrs.iter().any(|attr| attr.path().is_ident("macro_use")))
            {
                bindings.wildcard = true;
            }
        }
        self.scopes.push(bindings);
    }
}

impl<'ast> Visit<'ast> for Check<'_> {
    fn visit_item(&mut self, i: &'ast Item) {
        match configuration::attributes(i)
            .and_then(|attrs| configuration::included(self.file, attrs))
        {
            Ok(true) => visit::visit_item(self, i),
            Ok(false) => {}
            Err(error) => self.error = Some(error),
        }
    }
    fn visit_item_macro(&mut self, i: &'ast syn::ItemMacro) {
        if let Some(name) = &i.ident {
            if let Some(scope) = self.scopes.last_mut() {
                let _inserted = scope.names.insert(name.to_string());
            }
        } else {
            self.visit_macro(&i.mac);
        }
    }
    fn visit_item_mod(&mut self, i: &'ast syn::ItemMod) {
        if let Some((_, items)) = &i.content {
            self.enter(items.iter());
            for item in items {
                self.visit_item(item);
            }
            drop(self.scopes.pop());
        }
    }
    fn visit_block(&mut self, i: &'ast syn::Block) {
        self.enter(i.stmts.iter().filter_map(|stmt| match stmt {
            syn::Stmt::Item(item) => Some(item),
            syn::Stmt::Local(_) | syn::Stmt::Expr(_, _) | syn::Stmt::Macro(_) => None,
        }));
        visit::visit_block(self, i);
        drop(self.scopes.pop());
    }
    fn visit_macro(&mut self, i: &'ast syn::Macro) {
        if let Some(name) = i.path.get_ident()
            && self
                .scopes
                .iter()
                .any(|scope| scope.wildcard || scope.names.contains(&name.to_string()))
            && (super::replacement_macros::expressions(i).is_some()
                || nested_items::declaration_free(i))
        {
            self.error = Some(unsupported(
                self.file,
                i.bang_token.span,
                "unproven standard expression macro binding",
            ));
        }
        if let Some(arguments) = super::replacement_macros::expressions(i) {
            for argument in &arguments {
                self.visit_expr(argument);
            }
        }
    }
}

/// Hoisted imports and ordered textual definitions follow their lexical scopes.
pub(super) fn check(file: &str, items: &[Item]) -> Result<(), io::Error> {
    let mut checker = Check {
        file,
        scopes: Vec::new(),
        error: None,
    };
    checker.enter(items.iter());
    for item in items {
        checker.visit_item(item);
    }
    checker.error.map_or(Ok(()), Err)
}

/// Physical files cannot establish textual binding order from independent spans.
pub(super) fn graph_check(file: &str, items: &[Item], graph: &[Parsed]) -> Result<(), io::Error> {
    let mut checker = Check {
        file,
        scopes: Vec::new(),
        error: None,
    };
    checker.enter(items.iter());
    for unit in graph.iter().filter(|unit| !unit.path.ends_with(file)) {
        let mut definitions = Definitions::default();
        definitions.visit_file(&unit.tree);
        if let Some(scope) = checker.scopes.first_mut() {
            scope.names.extend(definitions.0);
        }
    }
    for item in items {
        checker.visit_item(item);
    }
    checker.error.map_or(Ok(()), Err)
}

#[derive(Default)]
struct Definitions(BTreeSet<String>);

impl<'ast> Visit<'ast> for Definitions {
    fn visit_item_macro(&mut self, i: &'ast syn::ItemMacro) {
        if let Some(name) = &i.ident {
            let _inserted = self.0.insert(name.to_string());
        }
    }
}
