//! Lexically scoped field-type and import resolution over parsed declarations.

use std::io;

use syn::{GenericArgument, Generics, Item, PathArguments, Type, UseTree};

use super::source::unsupported;

/// Type resolution retains lexical item scopes and the owning generic parameters.
pub(super) struct Scope<'ast> {
    /// Physical source name used in failure diagnostics.
    pub file: &'ast str,
    /// Innermost scope last; sibling modules never leak aliases into this stack.
    pub items: Vec<&'ast [Item]>,
    /// Generic parameters of the declaration being inspected.
    pub generics: &'ast Generics,
}

impl Scope<'_> {
    /// Resolve storage structurally; projections and opaque syntax fail closed.
    pub(super) fn resolve(&self, ty: &Type) -> Result<Vec<String>, io::Error> {
        self.expand(ty, 0)
    }

    /// Alias and wrapper recursion has a finite bound, including cyclic aliases.
    fn expand(&self, ty: &Type, depth: usize) -> Result<Vec<String>, io::Error> {
        if depth >= 32 {
            return Err(unsupported(
                self.file,
                self.generics
                    .lt_token
                    .as_ref()
                    .map_or_else(proc_macro2::Span::call_site, |token| token.span),
                "type recursion limit",
            ));
        }
        let next = depth.saturating_add(1);
        match ty {
            Type::Path(path) => {
                let first = path
                    .path
                    .segments
                    .first()
                    .ok_or_else(|| io::Error::other("empty type path"))?;
                if path.qself.is_some() {
                    return Err(unsupported(
                        self.file,
                        first.ident.span(),
                        "associated-type projection",
                    ));
                }
                let name = first.ident.to_string();
                if let Some(parameter) = self
                    .generics
                    .type_params()
                    .find(|parameter| parameter.ident == name)
                {
                    if path.path.segments.len() != 1 {
                        return Err(unsupported(
                            self.file,
                            first.ident.span(),
                            "associated-type projection",
                        ));
                    }
                    return self.parameter(parameter, next);
                }
                let mut output = if let Some(resolved) = self.binding(&name, next)? {
                    if path.path.segments.len() != 1 {
                        return Err(unsupported(
                            self.file,
                            first.ident.span(),
                            "unclassified scoped type path",
                        ));
                    }
                    resolved
                } else {
                    path.path
                        .segments
                        .iter()
                        .map(|segment| segment.ident.to_string())
                        .collect()
                };
                for segment in &path.path.segments {
                    output.extend(self.arguments(segment, next)?);
                }
                Ok(output)
            }
            Type::Array(array) => self.expand(&array.elem, next),
            Type::Slice(slice) => self.expand(&slice.elem, next),
            Type::Reference(reference) => {
                let mut output = vec!["&".to_owned()];
                output.extend(self.expand(&reference.elem, next)?);
                Ok(output)
            }
            Type::Paren(paren) => self.expand(&paren.elem, next),
            Type::Group(group) => self.expand(&group.elem, next),
            Type::Tuple(tuple) => {
                let mut output = Vec::new();
                for element in &tuple.elems {
                    output.extend(self.expand(element, next)?);
                }
                Ok(output)
            }
            Type::Never(_) => Ok(Vec::new()),
            Type::FnPtr(_)
            | Type::ImplTrait(_)
            | Type::Infer(_)
            | Type::Macro(_)
            | Type::Ptr(_)
            | Type::TraitObject(_)
            | Type::Verbatim(_)
            | _ => Err(unsupported(
                self.file,
                proc_macro2::Span::call_site(),
                "unclassified field type",
            )),
        }
    }

    /// Container arguments retain every nested storage type rather than only the basename.
    fn arguments(
        &self,
        segment: &syn::PathSegment,
        depth: usize,
    ) -> Result<Vec<String>, io::Error> {
        let mut output = Vec::new();
        match &segment.arguments {
            PathArguments::None => {}
            PathArguments::AngleBracketed(arguments) => {
                for argument in &arguments.args {
                    match argument {
                        GenericArgument::Type(inner) => output.extend(self.expand(inner, depth)?),
                        GenericArgument::Lifetime(_) | GenericArgument::Const(_) => {}
                        GenericArgument::AssocType(_)
                        | GenericArgument::AssocConst(_)
                        | GenericArgument::Constraint(_)
                        | _ => {
                            return Err(unsupported(
                                self.file,
                                segment.ident.span(),
                                "associated generic argument",
                            ));
                        }
                    }
                }
            }
            PathArguments::Parenthesized(_) => {
                return Err(unsupported(
                    self.file,
                    segment.ident.span(),
                    "unclassified callable storage",
                ));
            }
        }
        Ok(output)
    }

    /// Only a proven scalar default can classify a generic owner as nonsecret.
    fn parameter(
        &self,
        parameter: &syn::TypeParam,
        depth: usize,
    ) -> Result<Vec<String>, io::Error> {
        let Some((_, default)) = &parameter.default else {
            return Err(unsupported(
                self.file,
                parameter.ident.span(),
                "unresolved generic owner storage",
            ));
        };
        let resolved = self.expand(default, depth)?;
        if resolved.iter().all(|word| {
            matches!(
                word.as_str(),
                "bool"
                    | "char"
                    | "u8"
                    | "u16"
                    | "u32"
                    | "u64"
                    | "u128"
                    | "usize"
                    | "i8"
                    | "i16"
                    | "i32"
                    | "i64"
                    | "i128"
                    | "isize"
                    | "f32"
                    | "f64"
            )
        }) {
            return Ok(resolved);
        }
        Err(unsupported(
            self.file,
            parameter.ident.span(),
            "unclassified generic owner default",
        ))
    }

    /// Search actual type/use declarations only, never impl-associated aliases.
    fn binding(&self, name: &str, depth: usize) -> Result<Option<Vec<String>>, io::Error> {
        if depth >= 32 {
            return Err(unsupported(
                self.file,
                proc_macro2::Span::call_site(),
                "import cycle or depth limit",
            ));
        }
        for items in self.items.iter().rev() {
            for item in *items {
                match item {
                    Item::Type(alias) if alias.ident == name => {
                        if !alias.generics.params.is_empty() {
                            return Err(unsupported(
                                self.file,
                                alias.ident.span(),
                                "unresolved generic alias",
                            ));
                        }
                        return self.expand(&alias.ty, depth).map(Some);
                    }
                    Item::Use(import) => {
                        if let Some(path) = import_path(&import.tree, name, Vec::new()) {
                            let Some(root) = path.first() else {
                                return Ok(None);
                            };
                            if matches!(root.as_str(), "core" | "std") && self.items.iter().any(|scope| scope.iter().any(|entry| matches!(entry, Item::Mod(module) if module.ident == root))) {
                                return Err(unsupported(self.file, import.use_token.span, "local standard module shadowing"));
                            }
                            if path.len() == 2 && root == "self" {
                                return self.binding(
                                    path.last().map_or("", String::as_str),
                                    depth.saturating_add(1),
                                );
                            }
                            return Ok(Some(path));
                        }
                    }
                    Item::Const(_)
                    | Item::Enum(_)
                    | Item::ExternCrate(_)
                    | Item::Fn(_)
                    | Item::ForeignMod(_)
                    | Item::Impl(_)
                    | Item::Macro(_)
                    | Item::Mod(_)
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
        Ok(None)
    }
}

/// Find the path bound by a named use-tree leaf, including grouped renames.
fn import_path(tree: &UseTree, name: &str, mut prefix: Vec<String>) -> Option<Vec<String>> {
    match tree {
        UseTree::Path(path) => {
            prefix.push(path.ident.to_string());
            import_path(&path.tree, name, prefix)
        }
        UseTree::Name(leaf) if leaf.ident == name => {
            prefix.push(leaf.ident.to_string());
            Some(prefix)
        }
        UseTree::Rename(leaf) if leaf.rename == name => {
            prefix.push(leaf.ident.to_string());
            Some(prefix)
        }
        UseTree::Group(group) => group
            .items
            .iter()
            .find_map(|branch| import_path(branch, name, prefix.clone())),
        UseTree::Name(_) | UseTree::Rename(_) | UseTree::Glob(_) => None,
    }
}
