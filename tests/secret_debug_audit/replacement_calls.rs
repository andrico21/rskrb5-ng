//! Receiver escapes into local helpers retain source-derived replacement obligations.

use std::{io, path::Path};

use syn::{FnArg, Item, ItemFn, Pat, Type, visit::Visit as _};

use super::{
    super::{inventory::Owner, source::Parsed},
    Method, Writes,
};

/// Resolve a receiver-escape path against the logical module graph.
fn lookup<'graph>(
    graph: &'graph [Parsed],
    module: &str,
    path: &[String],
) -> Option<(&'graph Parsed, &'graph ItemFn)> {
    let (name, prefix) = path.split_last()?;
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
    graph
        .iter()
        .filter(|unit| unit.module == target)
        .find_map(|unit| {
            unit.tree.items.iter().find_map(|item| {
                if let Item::Fn(function) = item
                    && function.sig.ident == *name
                {
                    Some((unit, function))
                } else {
                    None
                }
            })
        })
}

/// The helper's mutable receiver binding; shared receivers certify nothing.
fn mutable_binding(function: &ItemFn, location: &str) -> Result<Option<String>, io::Error> {
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
        return Ok(None);
    }
    let Pat::Ident(binding) = &*argument.pat else {
        return Err(io::Error::other(format!(
            "{location}: unresolved helper binding"
        )));
    };
    Ok(Some(binding.ident.to_string()))
}

/// Analyse one helper body as a method of the receiver's owner.
fn helper_method(
    (unit, function, binding): (&Parsed, &ItemFn, String),
    (owner, identity, relative): (&str, String, String),
    owners: &[Owner],
) -> Method {
    let mut writes = Writes {
        mutable_receiver: true,
        aliases: vec![binding],
        ..Writes::default()
    };
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
    Method {
        identity,
        owner: owner.to_owned(),
        fields: writes.fields.clone(),
        direct: writes.fields,
        delegates: writes
            .delegates
            .into_iter()
            .map(|(callee, callee_span)| (format!("{owner}::{callee}"), callee_span))
            .collect(),
        location: format!("{relative}:{}", function.sig.ident.span().start().line),
        public: false,
        opaque: writes.opaque,
        calls: writes.calls,
        module: unit.module.clone(),
    }
}

pub(super) fn resolve(
    methods: &mut Vec<Method>,
    (graph, root): (&[Parsed], &Path),
    owners: &[Owner],
) -> Result<(), io::Error> {
    let mut index = 0;
    while let Some(method) = methods.get(index) {
        let owner = method.owner.clone();
        let module = method.module.clone();
        let location = method.location.clone();
        let calls = method.calls.clone();
        let mut edges = Vec::new();
        for (path, span) in calls {
            if path.is_empty() {
                continue;
            }
            let Some((unit, function)) = lookup(graph, &module, &path) else {
                return Err(io::Error::other(format!(
                    "{location}: unresolved receiver escape {}",
                    path.join("::")
                )));
            };
            let Some(binding) = mutable_binding(function, &location)? else {
                continue;
            };
            let relative = unit
                .path
                .strip_prefix(root)
                .map_err(io::Error::other)?
                .to_string_lossy()
                .replace('\\', "/");
            let identity = format!("{relative}::{}", function.sig.ident);
            edges.push((identity.clone(), span));
            if methods.iter().any(|known| known.identity == identity) {
                continue;
            }
            methods.push(helper_method(
                (unit, function, binding),
                (&owner, identity, relative),
                owners,
            ));
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
