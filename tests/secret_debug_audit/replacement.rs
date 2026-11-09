//! Inventory public mutation boundaries on credential owners.

use std::{fs, io, path::Path};

use super::lex::{closing, tokens};

/// A public method that can replace owned credential storage.
#[derive(Debug)]
pub(super) struct Method {
    /// Full file, owner and method identity.
    pub identity: String,
    /// Concrete owner name.
    pub owner: String,
    /// Signature and body tokens for assignment classification.
    pub body: Vec<String>,
}

pub(super) fn test_names(directory: &Path) -> Result<Vec<String>, io::Error> {
    let mut names = Vec::new();
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        if path.is_dir() {
            names.extend(test_names(&path)?);
            continue;
        }
        if path.extension().is_some_and(|extension| extension == "rs") {
            let words = tokens(&fs::read_to_string(path)?)?;
            for window in words.windows(6) {
                if matches!(window, [hash, open, test, close, function, name] if hash == "#" && open == "[" && test == "test" && close == "]" && function == "fn" && !name.is_empty())
                {
                    names.push(
                        window
                            .last()
                            .cloned()
                            .ok_or_else(|| io::Error::other("test name"))?,
                    );
                }
            }
        }
    }
    Ok(names)
}

/// Return assigned receiver fields, including direct writes and replacement primitives.
pub(super) fn replaced_fields(method: &Method) -> Vec<String> {
    let mut fields = Vec::new();
    for (index, word) in method.body.iter().enumerate() {
        if word != "self"
            || method
                .body
                .get(index.saturating_add(1))
                .is_none_or(|part| part != ".")
        {
            continue;
        }
        let Some(field) = method.body.get(index.saturating_add(2)) else {
            continue;
        };
        let following = method.body.get(index.saturating_add(3)).map(String::as_str);
        let assignment = following == Some("=")
            && method
                .body
                .get(index.saturating_add(4))
                .is_none_or(|part| part != "=");
        let mutable = index
            .checked_sub(1)
            .and_then(|position| method.body.get(position))
            .is_some_and(|part| part == "mut");
        let method_write = following == Some(".")
            && method
                .body
                .get(index.saturating_add(4))
                .is_some_and(|part| {
                    matches!(
                        part.as_str(),
                        "replace" | "take" | "clear" | "truncate" | "clone_from" | "insert"
                    )
                });
        if assignment || mutable || method_write {
            fields.push(field.clone());
        }
    }
    fields.sort();
    fields.dedup();
    fields
}

/// Extract public methods from impl blocks, retaining assignments and receiver types.
pub(super) fn methods(file: &str, words: &[String]) -> Result<Vec<Method>, io::Error> {
    let mut output = Vec::new();
    let mut index = 0_usize;
    while let Some(word) = words.get(index) {
        if word != "impl" {
            index = index.saturating_add(1);
            continue;
        }
        let open = words
            .iter()
            .enumerate()
            .skip(index)
            .find(|(_, item)| item.as_str() == "{")
            .map(|(position, _)| position)
            .ok_or_else(|| io::Error::other("impl body"))?;
        let end = closing(words, open)?;
        let header = words
            .get(index.saturating_add(1)..open)
            .ok_or_else(|| io::Error::other("impl header"))?;
        let mut depth = 0_usize;
        let mut owner = None;
        for token in header {
            match token.as_str() {
                "<" => depth = depth.saturating_add(1),
                ">" => depth = depth.saturating_sub(1),
                "for" if depth == 0 => owner = None,
                name if depth == 0 && name.chars().next().is_some_and(char::is_uppercase) => {
                    owner = Some(name.to_owned());
                }
                "bool" | "u8" | "u16" | "u32" | "u64" | "usize" | "str" => {
                    owner = Some(token.clone());
                }
                _ => {}
            }
        }
        let body = words
            .get(open.saturating_add(1)..end)
            .ok_or_else(|| io::Error::other("impl extent"))?;
        if !body.iter().any(|token| token == "pub") {
            index = end.saturating_add(1);
            continue;
        }
        let concrete = owner.ok_or_else(|| {
            io::Error::other(format!(
                "{file}: unclassified impl owner: {}",
                header.join(" ")
            ))
        })?;
        output.extend(public_methods(file, &concrete, body)?);
        index = end.saturating_add(1);
    }
    Ok(output)
}

/// Inspect each public function's complete signature and body, not its name alone.
fn public_methods(file: &str, owner: &str, words: &[String]) -> Result<Vec<Method>, io::Error> {
    let mut output = Vec::new();
    let mut index = 0_usize;
    while let Some(word) = words.get(index) {
        if word != "pub"
            || words
                .get(index.saturating_add(1))
                .is_some_and(|item| item == "(")
        {
            index = index.saturating_add(1);
            continue;
        }
        let start = index;
        index = index.saturating_add(1);
        while words
            .get(index)
            .is_some_and(|item| matches!(item.as_str(), "async" | "const"))
        {
            index = index.saturating_add(1);
        }
        if words.get(index).is_none_or(|item| item != "fn") {
            return Err(io::Error::other("unclassified public impl item"));
        }
        let name = words
            .get(index.saturating_add(1))
            .ok_or_else(|| io::Error::other("method name"))?;
        let open = words
            .iter()
            .enumerate()
            .skip(index)
            .find(|(_, item)| item.as_str() == "{")
            .map(|(position, _)| position)
            .ok_or_else(|| io::Error::other("method body"))?;
        let end = closing(words, open)?;
        output.push(Method {
            identity: format!("{file}::{owner}::{name}"),
            owner: owner.to_owned(),
            body: words
                .get(start..=end)
                .ok_or_else(|| io::Error::other("method extent"))?
                .to_vec(),
        });
        index = end.saturating_add(1);
    }
    Ok(output)
}

/// Walk all source paths so cfg-disabled mutation boundaries remain audited.
pub(super) fn inspect(root: &Path, directory: &Path) -> Result<Vec<Method>, io::Error> {
    let mut output = Vec::new();
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        if path.is_dir() {
            output.extend(inspect(root, &path)?);
            continue;
        }
        if path.extension().is_some_and(|extension| extension == "rs") {
            let relative = path
                .strip_prefix(root)
                .map_err(io::Error::other)?
                .to_string_lossy()
                .replace('\\', "/");
            output.extend(methods(&relative, &tokens(&fs::read_to_string(path)?)?)?);
        }
    }
    Ok(output)
}
