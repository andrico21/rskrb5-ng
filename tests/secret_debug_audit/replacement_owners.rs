//! Resolve inherent receiver imports to their declaration's physical identity.

use std::{io, path::Path};

use syn::{Item, UseTree};

use super::{super::source::Parsed, Method};

pub(super) fn qualify(
    methods: &mut [Method],
    unit: &Parsed,
    (graph, root): (&[Parsed], &Path),
) -> Result<(), io::Error> {
    for method in methods {
        let (_, owner) = method
            .owner
            .split_once("::")
            .ok_or_else(|| io::Error::other("receiver identity"))?;
        let mut segments = owner.split("::").map(str::to_owned).collect::<Vec<_>>();
        let name = segments
            .pop()
            .ok_or_else(|| io::Error::other("receiver name"))?;
        let module = if segments.is_empty() {
            unit.module.clone()
        } else {
            format!("{}::{}", unit.module, segments.join("::"))
        };
        let resolved = resolve(graph, &module, &[name], 0)?;
        let Some((path, nested)) = resolved else {
            if method.public && !method.delegates.is_empty() {
                return Err(io::Error::other(format!(
                    "{}: unresolved receiver owner {}",
                    method.location, method.owner
                )));
            }
            continue;
        };
        let relative = path
            .strip_prefix(root)
            .map_err(io::Error::other)?
            .to_string_lossy()
            .replace('\\', "/");
        let identity = format!("{relative}::{nested}");
        let old = method.owner.clone();
        method.identity = method.identity.replacen(&old, &identity, 1);
        for (delegate, _) in &mut method.delegates {
            *delegate = delegate.replacen(&old, &identity, 1);
        }
        method.owner = identity;
    }
    Ok(())
}

fn resolve<'graph>(
    graph: &'graph [Parsed],
    module: &str,
    path: &[String],
    depth: usize,
) -> Result<Option<(&'graph Path, String)>, io::Error> {
    if depth >= 32 {
        return Err(io::Error::other("receiver owner alias cycle"));
    }
    let Some((name, prefix)) = path.split_last() else {
        return Ok(None);
    };
    let mut segments = module
        .split("::")
        .filter(|part| !part.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let mut prefix = prefix.iter().peekable();
    while let Some(part) = prefix.peek() {
        match part.as_str() {
            "crate" => segments.clear(),
            "self" => {}
            "super" => {
                drop(
                    segments
                        .pop()
                        .ok_or_else(|| io::Error::other("receiver path escapes crate"))?,
                );
            }
            _ => break,
        }
        let _segment = prefix.next();
    }
    segments.extend(prefix.cloned());
    let target = if segments.is_empty() {
        String::new()
    } else {
        format!("::{}", segments.join("::"))
    };
    for unit in graph {
        if target != unit.module && !target.starts_with(&format!("{}::", unit.module)) {
            continue;
        }
        let suffix = target.strip_prefix(&unit.module).unwrap_or_default();
        let mut items = unit.tree.items.as_slice();
        let mut inline = Vec::new();
        for segment in suffix.split("::").filter(|segment| !segment.is_empty()) {
            let Some(nested) = items.iter().find_map(|item| match item {
                Item::Mod(value) if value.ident == segment => {
                    value.content.as_ref().map(|(_, items)| items.as_slice())
                }
                _ => None,
            }) else {
                items = &[];
                break;
            };
            inline.push(segment);
            items = nested;
        }
        for item in items {
            match item {
                Item::Struct(value) if value.ident == name => {
                    inline.push(name);
                    return Ok(Some((&unit.path, inline.join("::"))));
                }
                Item::Enum(value) if value.ident == name => {
                    inline.push(name);
                    return Ok(Some((&unit.path, inline.join("::"))));
                }
                Item::Use(value) => {
                    if let Some(imported) = import(&value.tree, name, Vec::new()) {
                        return resolve(graph, &target, &imported, depth.saturating_add(1));
                    }
                }
                _ => {}
            }
        }
    }
    Ok(None)
}

fn import(tree: &UseTree, name: &str, mut prefix: Vec<String>) -> Option<Vec<String>> {
    match tree {
        UseTree::Path(path) => {
            prefix.push(path.ident.to_string());
            import(&path.tree, name, prefix)
        }
        UseTree::Name(value) if value.ident == name => {
            prefix.push(value.ident.to_string());
            Some(prefix)
        }
        UseTree::Rename(value) if value.rename == name => {
            prefix.push(value.ident.to_string());
            Some(prefix)
        }
        UseTree::Group(group) => group
            .items
            .iter()
            .find_map(|tree| import(tree, name, prefix.clone())),
        UseTree::Name(_) | UseTree::Rename(_) | UseTree::Glob(_) => None,
    }
}
