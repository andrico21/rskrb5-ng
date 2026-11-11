//! Lexically scoped field-type and import resolution over parsed declarations.

use std::io;

use syn::{GenericArgument, Generics, Item, PathArguments, Type, UseTree};

use super::source::{Parsed, type_span, unsupported};

/// Type resolution retains lexical item scopes and the owning generic parameters.
pub(super) struct Scope<'ast> {
    /// Physical source name used in failure diagnostics.
    pub file: &'ast str,
    /// Innermost scope last; sibling modules never leak aliases into this stack.
    pub items: Vec<&'ast [Item]>,
    /// Generic parameters of the declaration being inspected.
    pub generics: &'ast Generics,
    /// Other physical source units in the same library graph.
    pub graph: &'ast [Parsed],
    /// Logical module containing the current declaration.
    pub module: &'ast str,
}

impl Scope<'_> {
    /// Resolve file-module aliases in their defining scope, retaining their diagnostic file.
    fn graph_alias(&self, path: &[String], depth: usize) -> Result<Option<Vec<String>>, io::Error> {
        if depth >= 32 {
            return Err(unsupported(
                self.file,
                proc_macro2::Span::call_site(),
                "cross-module alias cycle",
            ));
        }
        let Some((name, prefix)) = path.split_last() else {
            return Ok(None);
        };
        if prefix.is_empty() {
            return Ok(None);
        }
        let mut segments: Vec<_> = self
            .module
            .split("::")
            .filter(|part| !part.is_empty())
            .map(str::to_owned)
            .collect();
        let mut parts = prefix.iter();
        match parts.next().map(String::as_str) {
            Some("crate") => segments.clear(),
            Some("self") | None => {}
            Some("super") => {
                drop(segments.pop());
            }
            Some(first) => segments.push(first.to_owned()),
        }
        for part in parts {
            segments.push(part.clone());
        }
        let module = format!("::{}", segments.join("::"));
        for unit in self.graph.iter().filter(|unit| unit.module == module) {
            for item in &unit.tree.items {
                if let Item::Type(alias) = item
                    && alias.ident == name
                {
                    let file = unit.path.display().to_string();
                    if !alias.generics.params.is_empty() {
                        return Err(unsupported(
                            &file,
                            alias.ident.span(),
                            "unresolved generic alias",
                        ));
                    }
                    let scope = Scope {
                        file: &file,
                        items: self
                            .graph
                            .iter()
                            .filter(|candidate| candidate.module == module)
                            .map(|candidate| candidate.tree.items.as_slice())
                            .collect(),
                        generics: &alias.generics,
                        graph: self.graph,
                        module: &unit.module,
                    };
                    return scope.expand(&alias.ty, depth.saturating_add(1)).map(Some);
                }
            }
        }
        Ok(None)
    }

    /// Resolve storage structurally; projections and opaque syntax fail closed.
    pub(super) fn resolve(&self, ty: &Type) -> Result<Vec<String>, io::Error> {
        self.expand(ty, 0)
    }

    /// Alias and wrapper recursion has a finite bound, including cyclic aliases.
    fn expand(&self, ty: &Type, depth: usize) -> Result<Vec<String>, io::Error> {
        if depth >= 32 {
            return Err(unsupported(
                self.file,
                type_span(ty),
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
                self.known(&path.path, next)?;
                let path_names = names(&path.path);
                if let Some(resolved) = self.graph_alias(&path_names, next)? {
                    return Ok(resolved);
                }
                self.qualified(&path.path)?;
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
                    return self.parameter(parameter);
                }
                let mut output = self.binding(&name, next)?.map_or_else(
                    || {
                        path.path
                            .segments
                            .iter()
                            .map(|segment| segment.ident.to_string())
                            .collect()
                    },
                    |mut qualified| {
                        qualified.extend(
                            path.path
                                .segments
                                .iter()
                                .skip(1)
                                .map(|segment| segment.ident.to_string()),
                        );
                        qualified
                    },
                );
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
            Type::TraitObject(object) => self.trait_object(object, next),
            Type::FnPtr(_)
            | Type::ImplTrait(_)
            | Type::Infer(_)
            | Type::Macro(_)
            | Type::Ptr(_)
            | Type::Verbatim(_)
            | _ => Err(unsupported(
                self.file,
                type_span(ty),
                "unclassified field type",
            )),
        }
    }

    /// Unknown local names cannot silently become scalar storage.
    fn known(&self, path: &syn::Path, depth: usize) -> Result<(), io::Error> {
        if path.segments.len() != 1 {
            return Ok(());
        }
        let Some(segment) = path.segments.first() else {
            return Ok(());
        };
        let name = segment.ident.to_string();
        if self.binding(&name, depth)?.is_some()
            || self
                .generics
                .type_params()
                .any(|parameter| parameter.ident == name)
        {
            return Ok(());
        }
        self.private_storage(segment, depth)?;
        for item in self.items.iter().flat_map(|items| items.iter()) {
            if matches!(item, Item::Struct(owner) if owner.ident == name)
                || matches!(item, Item::Enum(owner) if owner.ident == name)
                || matches!(item, Item::Union(owner) if owner.ident == name)
            {
                return Ok(());
            }
        }
        if matches!(
            name.as_str(),
            "bool"
                | "char"
                | "str"
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
                | "Vec"
                | "String"
                | "Option"
                | "Result"
                | "Box"
                | "Self"
                | "Zeroizing"
        ) {
            return Ok(());
        }
        Err(unsupported(
            self.file,
            segment.ident.span(),
            "unresolved field type",
        ))
    }

    /// Referenced private storage must be proven nonsecret before it can remain unlisted.
    fn private_storage(&self, segment: &syn::PathSegment, depth: usize) -> Result<(), io::Error> {
        let name = segment.ident.to_string();
        for item in self.items.iter().flat_map(|items| items.iter()) {
            let private_fields = match item {
                Item::Struct(owner)
                    if owner.ident == name && !matches!(owner.vis, syn::Visibility::Public(_)) =>
                {
                    Some(&owner.fields)
                }
                Item::Enum(owner)
                    if owner.ident == name
                        && !matches!(owner.vis, syn::Visibility::Public(_))
                        && owner
                            .variants
                            .iter()
                            .any(|variant| !variant.fields.is_empty()) =>
                {
                    return Err(unsupported(
                        self.file,
                        segment.ident.span(),
                        "unclassified private enum storage",
                    ));
                }
                Item::Union(owner)
                    if owner.ident == name && !matches!(owner.vis, syn::Visibility::Public(_)) =>
                {
                    return Err(unsupported(
                        self.file,
                        segment.ident.span(),
                        "unclassified private union storage",
                    ));
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
                | Item::Use(_)
                | Item::Verbatim(_)
                | _ => None,
            };
            if let Some(fields) = private_fields {
                for field in fields {
                    let storage = self.expand(&field.ty, depth.saturating_add(1))?;
                    let field_name = field
                        .ident
                        .as_ref()
                        .map_or_else(String::new, ToString::to_string);
                    if super::inventory::secret_field(&field_name, &storage)
                        && !super::nonsecret::contains(
                            &format!("{}::{name}", self.file),
                            &field_name,
                        )
                    {
                        return Err(unsupported(
                            self.file,
                            segment.ident.span(),
                            "unclassified private credential owner",
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    /// Qualified local aliases and concrete associated projections require explicit resolution.
    fn qualified(&self, path: &syn::Path) -> Result<(), io::Error> {
        if path.segments.len() < 2 {
            return Ok(());
        }
        let Some(first) = path.segments.first() else {
            return Ok(());
        };
        let root = if matches!(first.ident.to_string().as_str(), "self" | "super" | "crate") {
            path.segments.iter().nth(1).unwrap_or(first)
        } else {
            first
        };
        for item in self.items.iter().rev().flat_map(|items| items.iter()) {
            let concrete = match item {
                Item::Struct(owner) => owner.ident == first.ident,
                Item::Enum(owner) => owner.ident == first.ident,
                Item::Union(owner) => owner.ident == first.ident,
                Item::Type(alias) => alias.ident == first.ident,
                Item::Mod(module) if module.ident == root.ident => {
                    if module.content.is_some() {
                        return Err(unsupported(
                            self.file,
                            first.ident.span(),
                            "unresolved module alias",
                        ));
                    }
                    false
                }
                Item::Const(_)
                | Item::ExternCrate(_)
                | Item::Fn(_)
                | Item::ForeignMod(_)
                | Item::Impl(_)
                | Item::Macro(_)
                | Item::Mod(_)
                | Item::Static(_)
                | Item::Trait(_)
                | Item::TraitAlias(_)
                | Item::Use(_)
                | Item::Verbatim(_)
                | _ => false,
            };
            if concrete {
                return Err(unsupported(
                    self.file,
                    first.ident.span(),
                    "associated-type projection",
                ));
            }
        }
        Ok(())
    }

    /// Trait-object paths preserve generic arguments and refuse opaque bounds.
    fn trait_object(
        &self,
        object: &syn::TypeTraitObject,
        depth: usize,
    ) -> Result<Vec<String>, io::Error> {
        let mut output = Vec::new();
        for bound in &object.bounds {
            match bound {
                syn::TypeParamBound::Trait(trait_bound) => {
                    output.extend(
                        trait_bound
                            .path
                            .segments
                            .iter()
                            .map(|segment| segment.ident.to_string()),
                    );
                    for segment in &trait_bound.path.segments {
                        output.extend(self.arguments(segment, depth)?);
                    }
                }
                syn::TypeParamBound::Lifetime(_) => {}
                syn::TypeParamBound::PreciseCapture(_) | syn::TypeParamBound::Verbatim(_) | _ => {
                    return Err(unsupported(
                        self.file,
                        object
                            .dyn_token
                            .as_ref()
                            .map_or_else(proc_macro2::Span::call_site, |token| token.span),
                        "unclassified trait storage",
                    ));
                }
            }
        }
        Ok(output)
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

    /// Defaults do not constrain explicit instantiations of generic storage.
    fn parameter(&self, parameter: &syn::TypeParam) -> Result<Vec<String>, io::Error> {
        if parameter.default.is_none() {
            return Ok(vec!["GenericStorage".to_owned()]);
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
                            let parsed =
                                syn::parse_str::<syn::Path>(&path.join("::")).map_err(|error| {
                                    unsupported(
                                        self.file,
                                        import.use_token.span,
                                        &error.to_string(),
                                    )
                                })?;
                            self.qualified(&parsed)?;
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
                            if let Some(resolved) =
                                self.graph_alias(&path, depth.saturating_add(1))?
                            {
                                return Ok(Some(resolved));
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

/// Preserve every segment when resolving a path through the source graph.
fn names(path: &syn::Path) -> Vec<String> {
    path.segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect()
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
