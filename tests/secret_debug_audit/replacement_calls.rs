//! Receiver escapes into local helpers retain source-derived replacement obligations.

use std::{io, path::Path};

use syn::{FnArg, Item, Pat, Type, visit::Visit as _};

use super::{
    super::{inventory::Owner, source::Parsed},
    Method, Writes,
};

pub(super) fn resolve(
    methods: &mut Vec<Method>,
    (graph, root): (&[Parsed], &Path),
    owners: &[Owner],
) -> Result<(), io::Error> {
    let mut index = 0;
    while index < methods.len() {
        let method = methods
            .get(index)
            .ok_or_else(|| io::Error::other("method index"))?;
        let owner = method.owner.clone();
        let module = method.module.clone();
        let location = method.location.clone();
        let calls = method.calls.clone();
        let mut edges = Vec::new();
        for (path, span) in calls {
            let Some((name, prefix)) = path.split_last() else {
                continue;
            };
            let mut segments = module
                .split("::")
                .filter(|part| !part.is_empty())
                .map(str::to_owned)
                .collect::<Vec<_>>();
            for segment in prefix {
                match segment.as_str() {
                    "crate" => segments.clear(),
                    "self" => {}
                    "super" => {
                        drop(segments.pop());
                    }
                    _ => segments.push(segment.clone()),
                }
            }
            let target = format!("::{}", segments.join("::"));
            let candidate = graph
                .iter()
                .filter(|unit| unit.module == target)
                .find_map(|unit| {
                    unit.tree.items.iter().find_map(|item| match item {
                        Item::Fn(function) if function.sig.ident == name => Some((unit, function)),
                        _ => None,
                    })
                });
            let Some((unit, function)) = candidate else {
                return Err(io::Error::other(format!(
                    "{location}: unresolved receiver escape {}",
                    path.join("::")
                )));
            };
            let Some(FnArg::Typed(argument)) = function.sig.inputs.first() else {
                return Err(io::Error::other(format!(
                    "{location}: unresolved helper receiver"
                )));
            };
            let Type::Reference(reference) = &*argument.ty else {
                return Err(io::Error::other(format!(
                    "{location}: unresolved helper receiver type"
                )));
            };
            if reference.mutability.is_none() {
                continue;
            }
            let Pat::Ident(binding) = &*argument.pat else {
                return Err(io::Error::other(format!(
                    "{location}: unresolved helper binding"
                )));
            };
            let relative = unit
                .path
                .strip_prefix(root)
                .map_err(io::Error::other)?
                .to_string_lossy()
                .replace('\\', "/");
            let identity = format!("{relative}::{}", function.sig.ident);
            edges.push((identity.clone(), span));
            if methods.iter().any(|method| method.identity == identity) {
                continue;
            }
            let mut writes = Writes::default();
            writes.mutable_receiver = true;
            writes.aliases.push(binding.ident.to_string());
            for declaration in owners
                .iter()
                .filter(|declaration| declaration.identity == owner)
            {
                for (field, _, ty) in &declaration.fields {
                    writes.receiver_fields.push(field.clone());
                    if super::replacement_readers::classified(ty) {
                        writes.readers.push(field.clone());
                    }
                }
            }
            writes.visit_block(&function.block);
            methods.push(Method {
                identity,
                owner: owner.clone(),
                fields: writes.fields.clone(),
                direct: writes.fields,
                delegates: writes
                    .delegates
                    .into_iter()
                    .map(|(name, span)| (format!("{owner}::{name}"), span))
                    .collect(),
                location: format!("{relative}:{}", function.sig.ident.span().start().line),
                public: false,
                opaque: writes.opaque,
                calls: writes.calls,
                module: unit.module.clone(),
            });
        }
        methods
            .get_mut(index)
            .ok_or_else(|| io::Error::other("method index"))?
            .delegates
            .extend(edges);
        index = index.saturating_add(1);
    }
    Ok(())
}
