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

#[path = "expression_bindings.rs"]
mod expression_bindings;

#[path = "replacement_delegation.rs"]
mod replacement_delegation;

#[path = "replacement_owners.rs"]
mod replacement_owners;

#[path = "replacement_calls.rs"]
mod replacement_calls;

pub(super) fn macro_expressions(invocation: &syn::Macro) -> Option<Vec<Expr>> {
    replacement_macros::expressions(invocation)
}

pub(super) fn expression_bindings(
    scope: &super::resolve::Scope<'_>,
    items: &[Item],
) -> Result<(), io::Error> {
    expression_bindings::graph_check(scope.file, items, scope.graph)
}

/// A public method and its structurally identified receiver writes.
#[derive(Debug)]
pub(super) struct Method {
    /// Physical source, owner and method identity.
    pub identity: String,
    /// Concrete receiver identity, including its physical declaration scope.
    pub owner: String,
    /// Assigned or mutably exposed receiver fields.
    pub fields: Vec<String>,
    /// Writes in this body, before following receiver delegation.
    pub direct: Vec<String>,
    /// Fully qualified receiver-method edges and their original locations.
    pub delegates: Vec<(String, proc_macro2::Span)>,
    /// Location used for registry failures.
    pub location: String,
    /// Private boundaries remain visible when reached by a public method.
    pub public: bool,
    /// Opaque syntax is rejected only when a public root reaches this method.
    pub opaque: Option<proc_macro2::Span>,
    /// Calls passing the receiver are resolved from the callee signature and body.
    pub calls: Vec<(Vec<String>, proc_macro2::Span)>,
    /// Logical module of the method body, independent of receiver declaration location.
    pub module: String,
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
    /// Local bindings that still refer to the same receiver.
    aliases: Vec<String>,
    /// Calls resolved against the concrete receiver owner after collection.
    delegates: Vec<(String, proc_macro2::Span)>,
    calls: Vec<(Vec<String>, proc_macro2::Span)>,
}

impl Writes {
    /// Parentheses, reborrows and dereferences preserve receiver identity.
    fn receiver(&self, expression: &Expr) -> bool {
        if let Expr::Path(path) = expression {
            return path.path.is_ident("self")
                || self.aliases.iter().any(|name| path.path.is_ident(name));
        }
        if let Expr::Paren(value) = expression {
            return self.receiver(&value.expr);
        }
        if let Expr::Group(value) = expression {
            return self.receiver(&value.expr);
        }
        if let Expr::Unary(value) = expression {
            return self.receiver(&value.expr);
        }
        if let Expr::Reference(value) = expression {
            return self.receiver(&value.expr);
        }
        false
    }

    /// Only receiver fields count, not unrelated object members.
    fn record(&mut self, expression: &Expr) {
        match expression {
            Expr::Path(path) if self.mutable_receiver && self.receiver(expression) => {
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
            Expr::MethodCall(value) => self.record(&value.receiver),
            Expr::Field(field) => {
                if self.receiver(&field.base) {
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
    fn visit_block(&mut self, i: &'ast syn::Block) {
        let aliases = self.aliases.clone();
        visit::visit_block(self, i);
        self.aliases = aliases;
    }

    fn visit_local(&mut self, i: &'ast syn::Local) {
        let aliases_receiver = i
            .init
            .as_ref()
            .is_some_and(|init| self.receiver(&init.expr));
        let binding = if let syn::Pat::Ident(binding) = &i.pat {
            Some(binding)
        } else {
            None
        };
        if let Some(named) = binding {
            self.aliases.retain(|name| named.ident != *name);
            if aliases_receiver {
                self.aliases.push(named.ident.to_string());
                return;
            }
        }
        if binding.is_none() && aliases_receiver && self.mutable_receiver {
            self.opaque = Some(i.let_token.span);
        }
        visit::visit_local(self, i);
    }

    fn visit_expr_call(&mut self, i: &'ast syn::ExprCall) {
        for (index, argument) in i.args.iter().enumerate() {
            if self.mutable_receiver && self.receiver(argument) {
                if index == 0
                    && let Expr::Path(path) = &*i.func
                {
                    self.calls.push((
                        path.path
                            .segments
                            .iter()
                            .map(|segment| segment.ident.to_string())
                            .collect(),
                        i.paren_token.span.open(),
                    ));
                } else {
                    self.opaque = Some(i.paren_token.span.open());
                }
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
        if self.mutable_receiver && self.receiver(&i.receiver) {
            self.delegates.push((i.method.to_string(), i.method.span()));
        }
        let mut receiver = Self::default();
        receiver.aliases.clone_from(&self.aliases);
        receiver.record(&i.receiver);
        if matches!(&*i.receiver, Expr::MethodCall(inner) if replacement_readers::METHODS.contains(&inner.method.to_string().as_str()))
            && receiver
                .fields
                .iter()
                .all(|field| self.readers.contains(field))
        {
            visit::visit_expr_method_call(self, i);
            return;
        }
        if !(self.receiver(&i.receiver)
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
    expression_bindings::check(file, &parse(file, source)?.items)?;
    let owners = super::declarations::declarations(file, source)?;
    let mut methods = parsed_methods((file, file), &parse(file, source)?.items, &owners)?;
    for method in &mut methods {
        if !method.calls.is_empty() {
            for owner in owners.iter().filter(|owner| owner.identity == method.owner) {
                method
                    .direct
                    .extend(owner.fields.iter().map(|(name, _, _)| name.clone()));
            }
        }
    }
    replacement_delegation::resolve(methods)
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
            if implementation.trait_.is_some() {
                continue;
            }
            let Type::Path(path) = &*implementation.self_ty else {
                continue;
            };
            let Some(owner) = path.path.segments.last() else {
                continue;
            };
            let identity = format!("{scope}::{}", owner.ident);
            for member in &implementation.items {
                if let ImplItem::Fn(function) = member {
                    if path.qself.is_some() || path.path.segments.len() != 1 {
                        return Err(unsupported(
                            file,
                            owner.ident.span(),
                            "unresolved receiver type",
                        ));
                    }
                    let mutable_receiver = function.sig.receiver().is_some_and(|receiver| {
                        if let syn::ReceiverKind::Reference(_, _, mutability) = &receiver.kind {
                            return mutability.is_some();
                        }
                        if let syn::ReceiverKind::Typed(_, ty) = &receiver.kind {
                            return if let Type::Reference(reference) = &**ty {
                                reference.mutability.is_some()
                            } else {
                                true
                            };
                        }
                        false
                    });
                    let mut writes = Writes {
                        fields: Vec::new(),
                        opaque: None,
                        readers: Vec::new(),
                        mutable_receiver,
                        receiver_fields: Vec::new(),
                        aliases: Vec::new(),
                        delegates: Vec::new(),
                        calls: Vec::new(),
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
                    if function.sig.receiver().is_none_or(|receiver| {
                        !matches!(&receiver.kind, syn::ReceiverKind::Reference(_, _, None))
                    }) {
                        writes.visit_block(&function.block);
                    }
                    writes.fields.sort();
                    writes.fields.dedup();
                    output.push(Method {
                        identity: format!("{identity}::{}", function.sig.ident),
                        owner: identity.clone(),
                        direct: writes.fields.clone(),
                        fields: writes.fields,
                        delegates: writes
                            .delegates
                            .into_iter()
                            .map(|(name, span)| (format!("{identity}::{name}"), span))
                            .collect(),
                        location: format!("{file}:{}", function.sig.ident.span().start().line),
                        public: matches!(function.vis, Visibility::Public(_)),
                        opaque: writes.opaque,
                        calls: writes.calls,
                        module: scope.strip_prefix(file).unwrap_or_default().to_owned(),
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
    let graph = super::graph::load(&directory.join("lib.rs"))?;
    for unit in &graph {
        let relative = unit
            .path
            .strip_prefix(root)
            .map_err(io::Error::other)?
            .to_string_lossy()
            .replace('\\', "/");
        expression_bindings::graph_check(&relative, &unit.tree.items, &graph)?;
        let mut methods = parsed_methods((&relative, &relative), &unit.tree.items, &owners)?;
        for method in &mut methods {
            method.module = format!("{}{}", unit.module, method.module);
        }
        replacement_owners::qualify(&mut methods, unit, (&graph, root))?;
        output.extend(methods);
    }
    replacement_calls::resolve(&mut output, (&graph, root), &owners)?;
    replacement_delegation::resolve(output)
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
