//! Parsed mutation boundaries on credential owners and independent wipe-test discovery.

use std::{fs, io, path::Path};

use syn::{
    Expr, ImplItem, Item, Member, Type, Visibility,
    visit::{self, Visit},
};

use super::source::parse;

/// A public method and its structurally identified receiver writes.
#[derive(Debug)]
pub(super) struct Method {
    /// Physical source, owner and method identity.
    pub identity: String,
    /// Concrete receiver name.
    pub owner: String,
    /// Assigned or mutably exposed receiver fields.
    pub fields: Vec<String>,
}

/// Collect field mutations through the real expression tree.
#[derive(Default)]
struct Writes(Vec<String>);

impl Writes {
    /// Only receiver fields count, not unrelated object members.
    fn record(&mut self, expression: &Expr) {
        if let Expr::Field(field) = expression
            && matches!(&*field.base, Expr::Path(path) if path.path.is_ident("self"))
        {
            self.0.push(match &field.member {
                Member::Named(name) => name.to_string(),
                Member::Unnamed(index) => index.index.to_string(),
            });
        }
    }
}

impl<'ast> Visit<'ast> for Writes {
    fn visit_expr_assign(&mut self, i: &'ast syn::ExprAssign) {
        self.record(&i.left);
        visit::visit_expr_assign(self, i);
    }
    fn visit_expr_reference(&mut self, i: &'ast syn::ExprReference) {
        if i.mutability.is_some() {
            self.record(&i.expr);
        }
        visit::visit_expr_reference(self, i);
    }
    fn visit_expr_method_call(&mut self, i: &'ast syn::ExprMethodCall) {
        if matches!(
            i.method.to_string().as_str(),
            "replace" | "take" | "clear" | "truncate" | "clone_from" | "insert"
        ) {
            self.record(&i.receiver);
        }
        visit::visit_expr_method_call(self, i);
    }
}

/// Extract public inherent methods from parsed impl blocks.
pub(super) fn methods(file: &str, source: &str) -> Result<Vec<Method>, io::Error> {
    Ok(parsed_methods(file, &parse(file, source)?))
}

/// Inspect each impl's concrete receiver and complete method body.
fn parsed_methods(file: &str, tree: &syn::File) -> Vec<Method> {
    let mut output = Vec::new();
    for item in &tree.items {
        if let Item::Impl(implementation) = item {
            let Type::Path(path) = &*implementation.self_ty else {
                continue;
            };
            let Some(owner) = path.path.segments.last() else {
                continue;
            };
            for member in &implementation.items {
                if let ImplItem::Fn(function) = member
                    && matches!(function.vis, Visibility::Public(_))
                {
                    let mut writes = Writes::default();
                    writes.visit_block(&function.block);
                    writes.0.sort();
                    writes.0.dedup();
                    output.push(Method {
                        identity: format!("{file}::{}::{}", owner.ident, function.sig.ident),
                        owner: owner.ident.to_string(),
                        fields: writes.0,
                    });
                }
            }
        }
    }
    output
}

/// Return the already-classified receiver mutations.
pub(super) fn replaced_fields(method: &Method) -> Vec<String> {
    method.fields.clone()
}

/// Library source graph selects production mutation boundaries independently of features.
pub(super) fn inspect(root: &Path, directory: &Path) -> Result<Vec<Method>, io::Error> {
    let mut output = Vec::new();
    for unit in super::graph::load(&directory.join("lib.rs"))? {
        let relative = unit
            .path
            .strip_prefix(root)
            .map_err(io::Error::other)?
            .to_string_lossy()
            .replace('\\', "/");
        output.extend(parsed_methods(&relative, &unit.tree));
    }
    Ok(output)
}

/// Test discovery intentionally includes unit-test source excluded from the library graph.
#[derive(Default)]
struct Tests(Vec<String>);

impl<'ast> Visit<'ast> for Tests {
    fn visit_item_fn(&mut self, i: &'ast syn::ItemFn) {
        if i.attrs
            .iter()
            .any(|attribute| attribute.path().is_ident("test"))
        {
            self.0.push(i.sig.ident.to_string());
        }
        visit::visit_item_fn(self, i);
    }
}

/// Parse actual test declarations rather than matching token windows or comments.
pub(super) fn test_names(directory: &Path) -> Result<Vec<String>, io::Error> {
    let mut names = Vec::new();
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        if path.is_dir() {
            names.extend(test_names(&path)?);
            continue;
        }
        if path.extension().is_some_and(|extension| extension == "rs") {
            let tree = parse(&path.display().to_string(), &fs::read_to_string(&path)?)?;
            let mut tests = Tests::default();
            tests.visit_file(&tree);
            names.extend(tests.0);
        }
    }
    Ok(names)
}
