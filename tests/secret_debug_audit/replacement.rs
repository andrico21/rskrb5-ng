//! Parsed mutation boundaries on credential owners and independent wipe-test discovery.

use std::{fs, io, path::Path};

use syn::{
    Expr, ImplItem, Item, Member, Type, Visibility,
    visit::{self, Visit},
};

use super::source::{parse, unsupported};

#[path = "replacement_macros.rs"]
mod replacement_macros;

#[path = "replacement_readers.rs"]
mod replacement_readers;

/// A public method and its structurally identified receiver writes.
#[derive(Debug)]
pub(super) struct Method {
    /// Physical source, owner and method identity.
    pub identity: String,
    /// Concrete receiver identity, including its physical declaration scope.
    pub owner: String,
    /// Assigned or mutably exposed receiver fields.
    pub fields: Vec<String>,
}

/// Collect field mutations through the real expression tree.
#[derive(Default)]
struct Writes {
    /// Receiver fields requiring a replacement proof.
    fields: Vec<String>,
    /// Opaque syntax cannot certify an empty write set.
    opaque: Option<proc_macro2::Span>,
    /// Fields whose resolved storage has reviewed read-only operations.
    readers: Vec<String>,
    /// The signature permits replacement through the receiver binding.
    mutable_receiver: bool,
    /// All fields of the resolved receiver declaration.
    receiver_fields: Vec<String>,
}

impl Writes {
    /// Only receiver fields count, not unrelated object members.
    fn record(&mut self, expression: &Expr) {
        match expression {
            Expr::Path(path) if self.mutable_receiver && path.path.is_ident("self") => {
                self.fields.extend(self.receiver_fields.clone());
                if self.receiver_fields.is_empty() {
                    self.opaque = path.path.segments.first().map(|part| part.ident.span());
                }
            }
            Expr::Paren(value) => self.record(&value.expr),
            Expr::Group(value) => self.record(&value.expr),
            Expr::Index(value) => self.record(&value.expr),
            Expr::Unary(value) => self.record(&value.expr),
            Expr::Reference(value) => self.record(&value.expr),
            Expr::Field(field) => {
                if matches!(&*field.base, Expr::Path(path) if path.path.is_ident("self")) {
                    self.fields.push(match &field.member {
                        Member::Named(name) => name.to_string(),
                        Member::Unnamed(index) => index.index.to_string(),
                    });
                } else {
                    self.record(&field.base);
                }
            }
            Expr::Array(_)
            | Expr::Assign(_)
            | Expr::Async(_)
            | Expr::Await(_)
            | Expr::Binary(_)
            | Expr::Block(_)
            | Expr::Break(_)
            | Expr::Call(_)
            | Expr::Cast(_)
            | Expr::Closure(_)
            | Expr::Const(_)
            | Expr::Continue(_)
            | Expr::ForLoop(_)
            | Expr::If(_)
            | Expr::Infer(_)
            | Expr::Let(_)
            | Expr::Lit(_)
            | Expr::Loop(_)
            | Expr::Macro(_)
            | Expr::Match(_)
            | Expr::MethodCall(_)
            | Expr::Path(_)
            | Expr::Range(_)
            | Expr::RawAddr(_)
            | Expr::Repeat(_)
            | Expr::Return(_)
            | Expr::Struct(_)
            | Expr::Try(_)
            | Expr::TryBlock(_)
            | Expr::Tuple(_)
            | Expr::Unsafe(_)
            | Expr::Verbatim(_)
            | Expr::While(_)
            | Expr::Yield(_)
            | _ => {}
        }
    }
}

impl<'ast> Visit<'ast> for Writes {
    fn visit_expr_call(&mut self, i: &'ast syn::ExprCall) {
        for argument in &i.args {
            if matches!(argument, Expr::Path(path) if path.path.is_ident("self")) {
                self.record(argument);
            }
        }
        visit::visit_expr_call(self, i);
    }
    fn visit_expr_binary(&mut self, i: &'ast syn::ExprBinary) {
        if matches!(
            i.op,
            syn::BinOp::AddAssign(_)
                | syn::BinOp::SubAssign(_)
                | syn::BinOp::MulAssign(_)
                | syn::BinOp::DivAssign(_)
                | syn::BinOp::RemAssign(_)
                | syn::BinOp::BitXorAssign(_)
                | syn::BinOp::BitAndAssign(_)
                | syn::BinOp::BitOrAssign(_)
                | syn::BinOp::ShlAssign(_)
                | syn::BinOp::ShrAssign(_)
        ) {
            self.record(&i.left);
        }
        visit::visit_expr_binary(self, i);
    }
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
        let mut receiver = Self::default();
        receiver.record(&i.receiver);
        if !(matches!(&*i.receiver, Expr::Path(path) if path.path.is_ident("self"))
            || (receiver
                .fields
                .iter()
                .all(|field| self.readers.contains(field))
                && replacement_readers::METHODS.contains(&i.method.to_string().as_str())))
        {
            self.record(&i.receiver);
        }
        visit::visit_expr_method_call(self, i);
    }
    fn visit_macro(&mut self, i: &'ast syn::Macro) {
        if let Some(arguments) = replacement_macros::expressions(i) {
            for argument in &arguments {
                self.visit_expr(argument);
            }
        } else {
            self.opaque = Some(i.bang_token.span);
        }
    }
}

/// Extract public inherent methods from parsed impl blocks.
pub(super) fn methods(file: &str, source: &str) -> Result<Vec<Method>, io::Error> {
    parsed_methods(
        (file, file),
        &parse(file, source)?.items,
        &super::declarations::declarations(file, source)?,
    )
}

/// Inspect each impl's concrete receiver and complete method body.
fn parsed_methods(
    (file, scope): (&str, &str),
    items: &[Item],
    owners: &[super::inventory::Owner],
) -> Result<Vec<Method>, io::Error> {
    let mut output = Vec::new();
    for item in items {
        if !super::configuration::included(file, super::configuration::attributes(item)?)? {
            continue;
        }
        if let Item::Mod(module) = item
            && let Some((_, nested)) = &module.content
        {
            output.extend(parsed_methods(
                (file, &format!("{scope}::{}", module.ident)),
                nested,
                owners,
            )?);
        }
        if let Item::Impl(implementation) = item {
            let Type::Path(path) = &*implementation.self_ty else {
                continue;
            };
            let Some(owner) = path.path.segments.last() else {
                continue;
            };
            let identity = format!("{scope}::{}", owner.ident);
            for member in &implementation.items {
                if let ImplItem::Fn(function) = member
                    && matches!(function.vis, Visibility::Public(_))
                {
                    if path.qself.is_some() || path.path.segments.len() != 1 {
                        return Err(unsupported(
                            file,
                            owner.ident.span(),
                            "unresolved receiver type",
                        ));
                    }
                    let mutable_receiver = function.sig.receiver().is_some_and(|receiver| {
                        match &receiver.kind {
                            syn::ReceiverKind::Reference(_, _, mutability) => mutability.is_some(),
                            syn::ReceiverKind::Typed(_, ty) => {
                                matches!(&**ty, Type::Reference(reference) if reference.mutability.is_some())
                            }
                            syn::ReceiverKind::Value => false,
                            _ => true,
                        }
                    });
                    let mut writes = Writes {
                        fields: Vec::new(),
                        opaque: None,
                        readers: Vec::new(),
                        mutable_receiver,
                        receiver_fields: Vec::new(),
                    };
                    for declaration in owners
                        .iter()
                        .filter(|candidate| candidate.identity == identity)
                    {
                        for (name, _, ty) in &declaration.fields {
                            writes.receiver_fields.push(name.clone());
                            if replacement_readers::classified(ty) {
                                writes.readers.push(name.clone());
                            }
                        }
                    }
                    writes.visit_block(&function.block);
                    if let Some(span) = writes.opaque {
                        return Err(unsupported(
                            file,
                            span,
                            "opaque replacement or receiver escape",
                        ));
                    }
                    writes.fields.sort();
                    writes.fields.dedup();
                    output.push(Method {
                        identity: format!("{identity}::{}", function.sig.ident),
                        owner: identity.clone(),
                        fields: writes.fields,
                    });
                }
            }
        }
    }
    Ok(output)
}

/// Return the already-classified receiver mutations.
pub(super) fn replaced_fields(method: &Method) -> Vec<String> {
    method.fields.clone()
}

/// Library source graph selects production mutation boundaries independently of features.
pub(super) fn inspect(root: &Path, directory: &Path) -> Result<Vec<Method>, io::Error> {
    let mut output = Vec::new();
    let owners = super::inventory::inspect(root, directory)?;
    for unit in super::graph::load(&directory.join("lib.rs"))? {
        let relative = unit
            .path
            .strip_prefix(root)
            .map_err(io::Error::other)?
            .to_string_lossy()
            .replace('\\', "/");
        output.extend(parsed_methods(
            (&relative, &relative),
            &unit.tree.items,
            &owners,
        )?);
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
