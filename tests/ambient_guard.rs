//! Tokenizing inventories for the audited ambient-input boundary.
// allow: SIZE_OK — this self-contained source-guard test owns its lexer, item model and adversarial fixtures.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
pub(crate) mod tests {
    extern crate alloc;

    use alloc::collections::BTreeMap;
    use core::{iter::Peekable, str::Chars};
    use std::{fs, io, path::Path};

    /// Path, qualified owner, variable and accepted argument spelling.
    const READERS: &[(&str, &str, &str, &str)] = &[
        (
            "src/config/credential_names.rs",
            "resolve_credential_template",
            "TMPDIR",
            "TMPDIR",
        ),
        (
            "src/config/credential_names.rs",
            "resolve_credential_template",
            "TEMP",
            "TEMP",
        ),
        (
            "src/config/credential_names.rs",
            "resolve_credential_template",
            "APPDATA",
            "APPDATA",
        ),
        (
            "src/config.rs",
            "Config::load_from_env",
            "KRB5_CONFIG",
            "KRB5_CONFIG_ENV",
        ),
        (
            "src/config.rs",
            "Config::load_default",
            "KRB5_CONFIG",
            "KRB5_CONFIG_ENV",
        ),
        (
            "src/config.rs",
            "Config::load_default_or_parse",
            "KRB5_CONFIG",
            "KRB5_CONFIG_ENV",
        ),
        ("src/config.rs", "LibDefaults::from_env", "HOME", "HOME"),
        (
            "src/ccache.rs",
            "CCache::load_from_env",
            "KRB5CCNAME",
            "KRB5CCNAME_ENV",
        ),
        (
            "src/ccache.rs",
            "CCache::save_to_env",
            "KRB5CCNAME",
            "KRB5CCNAME_ENV",
        ),
        (
            "src/keytab.rs",
            "Keytab::load_from_env",
            "KRB5_KTNAME",
            "KRB5_KTNAME_ENV",
        ),
        (
            "src/keytab.rs",
            "Keytab::save_to_env",
            "KRB5_KTNAME",
            "KRB5_KTNAME_ENV",
        ),
        (
            "src/keytab.rs",
            "default_keytab_name",
            "KRB5_KTNAME",
            "KRB5_KTNAME_ENV",
        ),
        (
            "src/client.rs",
            "Tokio::with_client_keytab_from_env",
            "KRB5_CLIENT_KTNAME",
            "KRB5_CLIENT_KTNAME_ENV",
        ),
        (
            "src/client.rs",
            "default_ccache_name",
            "KRB5CCNAME",
            "KRB5CCNAME_ENV",
        ),
        (
            "src/client.rs",
            "default_client_keytab_name",
            "KRB5_CLIENT_KTNAME",
            "KRB5_CLIENT_KTNAME_ENV",
        ),
    ];

    /// Structural token; literal/doc contents never become structural tokens.
    #[derive(Clone, Debug)]
    struct Token {
        text: String,
        value: String,
    }

    /// Source function with qualified identity and its unexpanded body.
    #[derive(Debug)]
    struct Function {
        file: String,
        owner: String,
        public: bool,
        docs: String,
        body: Vec<Token>,
    }

    /// Read a quoted literal without interpreting its contents as Rust.
    fn quoted(chars: &mut Peekable<Chars<'_>>) -> String {
        let mut value = String::new();
        while let Some(next) = chars.next() {
            match next {
                '\\' => {
                    value.push(next);
                    if let Some(escaped) = chars.next() {
                        value.push(escaped);
                    }
                }
                '"' => break,
                _ => value.push(next),
            }
        }
        value
    }

    /// Strip nested comments and literals, retaining doc/literal payloads separately.
    fn tokens(source: &str) -> Vec<Token> {
        let mut chars = source.chars().peekable();
        let mut result = Vec::new();
        while let Some(next) = chars.next() {
            let mut value = String::new();
            let text = match next {
                ch if ch.is_whitespace() => continue,
                '/' if chars.peek() == Some(&'/') => {
                    let _: Option<char> = chars.next();
                    let doc = chars.peek() == Some(&'/');
                    value.extend(chars.by_ref().take_while(|ch| *ch != '\n'));
                    if !doc {
                        continue;
                    }
                    "doc".to_owned()
                }
                '/' if chars.peek() == Some(&'*') => {
                    let _: Option<char> = chars.next();
                    let mut depth = 1_usize;
                    while let Some(ch) = chars.next() {
                        match (ch, chars.peek()) {
                            ('/', Some('*')) => {
                                let _: Option<char> = chars.next();
                                depth = depth.saturating_add(1);
                            }
                            ('*', Some('/')) => {
                                let _: Option<char> = chars.next();
                                depth = depth.saturating_sub(1);
                            }
                            _ => {}
                        }
                        if depth == 0 {
                            break;
                        }
                    }
                    continue;
                }
                '"' => {
                    value = quoted(&mut chars);
                    "literal".to_owned()
                }
                'r' if matches!(chars.peek(), Some('#' | '"')) => {
                    let mut probe = chars.clone();
                    let mut hashes = 0_usize;
                    while probe.peek() == Some(&'#') {
                        let _: Option<char> = probe.next();
                        hashes = hashes.saturating_add(1);
                    }
                    if probe.peek() != Some(&'"') {
                        result.push(Token {
                            text: "r".to_owned(),
                            value,
                        });
                        continue;
                    }
                    let _: Option<char> = probe.next();
                    chars = probe;
                    while let Some(ch) = chars.next() {
                        if ch == '"' {
                            let mut suffix = chars.clone();
                            if suffix.by_ref().take(hashes).all(|mark| mark == '#') {
                                chars = suffix;
                                break;
                            }
                        }
                        value.push(ch);
                    }
                    "literal".to_owned()
                }
                '\'' => {
                    let mut probe = chars.clone();
                    if probe.next() == Some('\\') {
                        let _: Option<char> = probe.next();
                    }
                    if probe.next() == Some('\'') {
                        chars = probe;
                        "literal".to_owned()
                    } else {
                        "'".to_owned()
                    }
                }
                ch if ch.is_alphabetic() || ch == '_' => {
                    let mut word = ch.to_string();
                    while chars
                        .peek()
                        .is_some_and(|letter| letter.is_alphanumeric() || *letter == '_')
                    {
                        if let Some(letter) = chars.next() {
                            word.push(letter);
                        }
                    }
                    word
                }
                ch => ch.to_string(),
            };
            result.push(Token { text, value });
        }
        result
    }

    /// Compare a token without indexing panics.
    fn is(words: &[Token], index: usize, text: &str) -> bool {
        words.get(index).is_some_and(|word| word.text == text)
    }

    /// Find a balanced delimiter's closing token; malformed syntax stays unclassified.
    fn closing(words: &[Token], start: usize) -> Option<usize> {
        let delimiter = match words.get(start)?.text.as_str() {
            "{" => "}",
            "[" => "]",
            "(" => ")",
            _ => return None,
        };
        let mut index = start.saturating_add(1);
        while let Some(word) = words.get(index) {
            if word.text == delimiter {
                return Some(index);
            }
            if matches!(word.text.as_str(), "{" | "[" | "(") {
                index = closing(words, index)?;
            }
            index = index.saturating_add(1);
        }
        None
    }

    /// Consume one attributed item/statement, never the following sibling.
    fn item_end(words: &[Token], start: usize) -> usize {
        let mut index = start;
        while let Some(word) = words.get(index) {
            match word.text.as_str() {
                ";" => return index.saturating_add(1),
                "{" => {
                    return closing(words, index).map_or(words.len(), |end| end.saturating_add(1));
                }
                "(" | "[" => index = closing(words, index).unwrap_or(words.len()),
                _ => {}
            }
            index = index.saturating_add(1);
        }
        index
    }

    /// Remove exact cfg(test) items, including semicolon items and statement attributes.
    fn production(words: &[Token]) -> Vec<Token> {
        let mut result = Vec::new();
        let mut index = 0_usize;
        while index < words.len() {
            if is(words, index, "#") && is(words, index.saturating_add(1), "[") {
                let end = closing(words, index.saturating_add(1)).unwrap_or(words.len());
                let attribute = words.get(index.saturating_add(2)..end).unwrap_or_default();
                let test_only = attribute
                    .iter()
                    .map(|word| word.text.as_str())
                    .eq(["cfg", "(", "test", ")"]);
                index = end.saturating_add(1);
                if test_only {
                    while is(words, index, "#") && is(words, index.saturating_add(1), "[") {
                        index = closing(words, index.saturating_add(1))
                            .map_or(words.len(), |finish| finish.saturating_add(1));
                    }
                    index = item_end(words, index);
                }
                continue;
            }
            if let Some(word) = words.get(index) {
                result.push(word.clone());
            }
            index = index.saturating_add(1);
        }
        result
    }

    /// Expand nested use trees into path/alias pairs.
    fn imports(words: &[Token], prefix: &str) -> Vec<(String, String)> {
        let mut result = Vec::new();
        let mut path = prefix.to_owned();
        let mut index = 0_usize;
        while let Some(word) = words.get(index) {
            match word.text.as_str() {
                ":" => {}
                "{" => {
                    let end = closing(words, index).unwrap_or(words.len());
                    result.extend(imports(
                        words.get(index.saturating_add(1)..end).unwrap_or_default(),
                        &path,
                    ));
                    index = end;
                    path = prefix.to_owned();
                }
                "," | ";" => {
                    if !path.is_empty() {
                        let name = path.rsplit("::").next().unwrap_or_default().to_owned();
                        result.push((path.clone(), name));
                    }
                    path = prefix.to_owned();
                }
                "as" => {
                    index = index.saturating_add(1);
                    if let Some(alias) = words.get(index) {
                        result.push((path.clone(), alias.text.clone()));
                    }
                    path = prefix.to_owned();
                }
                name => {
                    if !path.is_empty() {
                        path.push_str("::");
                    }
                    path.push_str(name);
                }
            }
            index = index.saturating_add(1);
        }
        if path != prefix {
            let name = path.rsplit("::").next().unwrap_or_default().to_owned();
            result.push((path, name));
        }
        result
    }

    /// Resolve standard-library aliases to a fixed point (including renamed roots).
    fn canonical(path: &str, aliases: &BTreeMap<String, String>) -> String {
        let mut resolved = path.to_owned();
        for _ in 0..=aliases.len() {
            let (root, suffix) = resolved.split_once("::").unwrap_or((&resolved, ""));
            let Some(replacement) = aliases.get(root) else {
                break;
            };
            let next = if suffix.is_empty() {
                replacement.clone()
            } else {
                format!("{replacement}::{suffix}")
            };
            if next == resolved {
                break;
            }
            resolved = next;
        }
        resolved
    }

    /// Collect imports separately so aliases cannot evade the access scanner.
    fn aliases(words: &[Token]) -> (BTreeMap<String, String>, Vec<usize>) {
        let mut names = BTreeMap::from([("env".to_owned(), "std::env".to_owned())]);
        let mut imported = Vec::new();
        for (index, word) in words.iter().enumerate() {
            if word.text == "extern"
                && is(words, index.saturating_add(1), "crate")
                && let Some(root) = words.get(index.saturating_add(2))
                && is(words, index.saturating_add(3), "as")
                && let Some(alias) = words.get(index.saturating_add(4))
            {
                drop(names.insert(alias.text.clone(), root.text.clone()));
            }
            if word.text == "use" {
                let end = words
                    .iter()
                    .enumerate()
                    .skip(index)
                    .find(|(_, candidate)| candidate.text == ";")
                    .map_or(words.len(), |(end, _)| end);
                for (path, name) in imports(
                    words.get(index.saturating_add(1)..=end).unwrap_or_default(),
                    "",
                ) {
                    if path != name {
                        drop(names.insert(name, path));
                    }
                }
                imported.extend(index..=end);
            }
        }
        (names, imported)
    }

    /// Extract the concrete owner from an inherent or trait impl header.
    fn impl_owner(header: &[Token]) -> String {
        let mut depth = 0_usize;
        let mut candidates = Vec::new();
        for word in header {
            match word.text.as_str() {
                "<" => depth = depth.saturating_add(1),
                ">" => depth = depth.saturating_sub(1),
                "for" if depth == 0 => candidates.clear(),
                name if depth == 0 && name.chars().next().is_some_and(char::is_uppercase) => {
                    candidates.push(name);
                }
                _ => {}
            }
        }
        candidates
            .last()
            .map_or_else(String::new, |name| (*name).to_owned())
    }

    /// Attribute functions to their actual impl/module, preserving attached rustdoc.
    fn functions(words: &[Token], context: (&str, &str), output: &mut Vec<Function>) {
        let (file, owner) = context;
        let mut index = 0_usize;
        let mut docs = String::new();
        let mut public = false;
        while let Some(word) = words.get(index) {
            match word.text.as_str() {
                "doc" => {
                    docs.push_str(&word.value);
                    docs.push('\n');
                }
                "pub" => public = !is(words, index.saturating_add(1), "("),
                "impl" | "mod" | "fn" => {
                    let end = words
                        .iter()
                        .enumerate()
                        .skip(index)
                        .find(|(_, candidate)| matches!(candidate.text.as_str(), "{" | ";"))
                        .map_or(words.len(), |(end, _)| end);
                    if is(words, end, "{") {
                        let finish = closing(words, end).unwrap_or(words.len());
                        let body = words.get(end.saturating_add(1)..finish).unwrap_or_default();
                        let name = words
                            .get(index.saturating_add(1))
                            .map_or("", |candidate| candidate.text.as_str());
                        let qualified = if owner.is_empty() {
                            name.to_owned()
                        } else {
                            format!("{owner}::{name}")
                        };
                        match word.text.as_str() {
                            "fn" => output.push(Function {
                                file: file.to_owned(),
                                owner: qualified.clone(),
                                public,
                                docs: docs.clone(),
                                body: body.to_vec(),
                            }),
                            "impl" => {
                                let concrete = impl_owner(
                                    words.get(index.saturating_add(1)..end).unwrap_or_default(),
                                );
                                let enclosing = if owner.is_empty() {
                                    concrete
                                } else {
                                    format!("{owner}::{concrete}")
                                };
                                functions(body, (file, &enclosing), output);
                            }
                            "mod" => functions(body, (file, &qualified), output),
                            _ => {}
                        }
                        if word.text == "fn" {
                            functions(body, (file, &qualified), output);
                        }
                        index = finish;
                    } else {
                        index = end;
                    }
                    docs.clear();
                    public = false;
                }
                ";" | "}" | "{" => {
                    docs.clear();
                    public = false;
                }
                _ => {}
            }
            index = index.saturating_add(1);
        }
    }

    /// Keep non-function references so nested bodies cannot cancel an unowned access.
    fn outside_functions(words: &[Token]) -> Vec<Token> {
        let mut result = Vec::new();
        let mut index = 0_usize;
        while let Some(word) = words.get(index) {
            if word.text == "fn" && !is(words, index.saturating_add(1), "(") {
                let end = words
                    .iter()
                    .enumerate()
                    .skip(index)
                    .find(|(_, candidate)| matches!(candidate.text.as_str(), "{" | ";"))
                    .map_or(words.len(), |(end, _)| end);
                index = if is(words, end, "{") {
                    closing(words, end).map_or(words.len(), |finish| finish.saturating_add(1))
                } else {
                    end.saturating_add(1)
                };
            } else {
                result.push(word.clone());
                index = index.saturating_add(1);
            }
        }
        result
    }

    /// Collect a path beginning at a token, without consuming literal contents.
    fn path_at(words: &[Token], start: usize) -> (String, usize) {
        let mut path = words
            .get(start)
            .map_or_else(String::new, |word| word.text.clone());
        let mut end = start.saturating_add(1);
        while is(words, end, ":") && is(words, end.saturating_add(1), ":") {
            let Some(word) = words.get(end.saturating_add(2)) else {
                break;
            };
            path.push_str("::");
            path.push_str(&word.text);
            end = end.saturating_add(3);
        }
        (path, end)
    }

    /// Check every ambient reference, including imports and function values.
    fn accesses(
        words: &[Token],
        function: Option<&Function>,
        context: (&str, &BTreeMap<String, String>),
    ) -> Vec<String> {
        let (file, names) = context;
        let mut failures = Vec::new();
        for (index, word) in words.iter().enumerate() {
            if word.text == "doc"
                || word.text == "literal"
                || (is(words, index.saturating_sub(1), ":")
                    && index
                        .checked_sub(3)
                        .and_then(|start| words.get(start))
                        .is_some_and(|root| root.text.chars().any(char::is_alphanumeric)))
            {
                continue;
            }
            let (path, end) = path_at(words, index);
            let resolved = canonical(&path, names);
            let Some(member) = resolved.strip_prefix("std::env::") else {
                continue;
            };
            if matches!(
                member,
                "VarError" | "VarError::NotPresent" | "VarError::NotUnicode" | "split_paths"
            ) {
                continue;
            }
            let owner = function.map_or("import/module", |item| item.owner.as_str());
            let allowed = READERS
                .iter()
                .any(|&(relative, qualified, variable, argument)| {
                    relative == file
                        && qualified == owner
                        && matches!(member, "var" | "var_os")
                        && is(words, end, "(")
                        && words.get(end.saturating_add(1)).is_some_and(|token| {
                            (token.text == "literal" && token.value == variable)
                                || token.text == argument
                        })
                        && is(words, end.saturating_add(2), ")")
                });
            if !allowed {
                failures.push(format!(
                    "{file}: {owner}: unclassified ambient access {resolved}"
                ));
            }
        }
        failures
    }

    /// Index one file and reject unowned env references as well as malformed aliases.
    fn inventory(file: &str, source: &str) -> (Vec<Function>, Vec<String>) {
        let words = production(&tokens(&source.replace("\r\n", "\n")));
        let (names, imported) = aliases(&words);
        let mut items = Vec::new();
        functions(&words, (file, ""), &mut items);
        let mut failures = Vec::new();
        for function in &items {
            failures.extend(accesses(&function.body, Some(function), (file, &names)));
        }
        for (name, path) in &names {
            let resolved = canonical(path, &names);
            if let Some(member) = resolved.strip_prefix("std::env::")
                && !matches!(
                    member,
                    "var" | "var_os" | "vars" | "vars_os" | "VarError" | "split_paths"
                )
            {
                failures.push(format!(
                    "{file}: unclassified ambient import {name} = {resolved}"
                ));
            }
        }
        // Outside function bodies only imports, constant declarations and types are valid.
        let mut outside = words.clone();
        for index in imported {
            if let Some(word) = outside.get_mut(index) {
                word.text.clear();
            }
        }
        failures.extend(accesses(&outside_functions(&outside), None, (file, &names)));
        (items, failures)
    }

    /// Classify a source file for transport regressions using the audited reader inventory.
    pub(crate) fn access_violations(file: &str, source: &str) -> Vec<String> {
        inventory(file, source).1
    }

    /// Identify call names, resolving Self and self without contaminating unrelated owners.
    fn calls(function: &Function, callee: &Function) -> bool {
        let name = callee.owner.rsplit("::").next().unwrap_or_default();
        function.body.iter().enumerate().any(|(index, word)| {
            if word.text != name || !is(&function.body, index.saturating_add(1), "(") {
                return false;
            }
            let qualifier = function
                .body
                .get(index.saturating_sub(3))
                .map(|part| part.text.as_str());
            if is(&function.body, index.saturating_sub(1), ":") {
                let owner = qualifier.unwrap_or_default();
                let concrete = if owner == "Self" {
                    function
                        .owner
                        .rsplit_once("::")
                        .map_or("", |(parent, _)| parent)
                } else {
                    owner
                };
                return callee.owner == format!("{concrete}::{name}") || callee.owner == name;
            }
            if is(&function.body, index.saturating_sub(1), ".")
                && is(&function.body, index.saturating_sub(2), "self")
            {
                return function.owner.rsplit_once("::").map(|(owner, _)| owner)
                    == callee.owner.rsplit_once("::").map(|(owner, _)| owner);
            }
            true
        })
    }

    /// Explicit non-ambient alternatives, checked only within the ambient rustdoc section.
    fn alternatives(variable: &str) -> &'static [&'static str] {
        match variable {
            "KRB5_CONFIG" => &["load", "load_paths", "parse"],
            "KRB5CCNAME" => &[
                "load_name",
                "save_name",
                "from_ccache_name",
                "from_default_ccache_name",
                "save_ccache_name",
                "save_default_ccache_name",
                "update_ccache_name",
                "update_default_ccache_name",
            ],
            "KRB5_KTNAME" => &[
                "load_name",
                "save_name",
                "from_keytab_name",
                "with_keytab_name",
            ],
            "KRB5_CLIENT_KTNAME" => &["with_keytab_name", "with_client_keytab_from_config"],
            "HOME" => &["new", "with_home"],
            "TMPDIR" | "TEMP" | "APPDATA" => &[
                "expand",
                "load",
                "save",
                "from_ccache_name",
                "from_keytab_name",
                "with_keytab_name",
                "save_ccache",
                "update_ccache_file",
            ],
            _ => &[],
        }
    }

    /// Propagate ambient variables backwards through the complete src by-name graph.
    fn documentation(items: &[Function]) -> Vec<String> {
        let mut required: Vec<Vec<&str>> = items
            .iter()
            .map(|function| {
                READERS
                    .iter()
                    .filter(|&&(file, owner, _, _)| {
                        file == function.file && owner == function.owner
                    })
                    .map(|&(_, _, variable, _)| variable)
                    .collect()
            })
            .collect();
        for _ in 0..items.len() {
            let previous = required.clone();
            for (index, function) in items.iter().enumerate() {
                for (callee, variables) in items.iter().zip(&previous) {
                    if !variables.is_empty()
                        && calls(function, callee)
                        && let Some(needs) = required.get_mut(index)
                    {
                        needs.extend(variables);
                        needs.sort_unstable();
                        needs.dedup();
                    }
                }
            }
            if previous == required {
                break;
            }
        }
        let mut failures = Vec::new();
        for (function, variables) in items.iter().zip(required) {
            if !function.public {
                continue;
            }
            let section = function
                .docs
                .split_once("# Ambient input")
                .map_or("", |(_, section)| {
                    section.split("# ").next().unwrap_or_default()
                });
            for variable in variables {
                if !section.contains(variable)
                    || !alternatives(variable).iter().any(|alternative| {
                        section
                            .split(|ch: char| !ch.is_alphanumeric() && ch != '_')
                            .any(|word| word == *alternative)
                    })
                {
                    failures.push(format!(
                        "{}: {}: # Ambient input must name {variable} and an explicit alternative",
                        function.file, function.owner
                    ));
                }
            }
        }
        failures
    }

    /// Walk src using full manifest-relative paths, never basenames.
    fn inspect(root: &Path, directory: &Path) -> Result<(Vec<Function>, Vec<String>), io::Error> {
        let mut items = Vec::new();
        let mut failures = Vec::new();
        for entry in fs::read_dir(directory)? {
            let path = entry?.path();
            let (functions, errors) = if path.is_dir() {
                inspect(root, &path)?
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                let relative = path
                    .strip_prefix(root)
                    .map_err(io::Error::other)?
                    .to_string_lossy()
                    .replace('\\', "/");
                inventory(&relative, &fs::read_to_string(&path)?)
            } else {
                continue;
            };
            items.extend(functions);
            failures.extend(errors);
        }
        Ok((items, failures))
    }

    /// All production reads and their public transitive callers are explicit.
    #[test]
    fn production_environment_reads_are_explicit() -> Result<(), io::Error> {
        // Given: the actual source tree, independent of enabled Cargo features.
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        // When: both structural inventories run.
        let (items, mut failures) = inspect(root, &root.join("src"))?;
        failures.extend(documentation(&items));
        // Then: no unclassified access or undocumented public ambient delegate exists.
        assert!(failures.is_empty(), "{}", failures.join("\n"));
        Ok(())
    }

    /// Every supplied evasion must produce a named rejection, not a vacuous pass.
    #[test]
    fn guard_rejects_reader_and_attribute_evasions() {
        assert!({
            ["var(\"HOME\")", "var_os(\"HOME\")", "vars()", "vars_os()"]
                .iter()
                .all(|member| {
                    let source = format!(
                        "extern crate std as platform; fn hidden() {{ platform::env::{member}; }}"
                    );
                    access_violations("src/config.rs", &source)
                        .iter()
                        .any(|failure| failure.contains("hidden"))
                })
        });
        assert!({
            // Given: FU-AMB-02 Proof cases plus alias and unknown-access boundaries.
            [
                (
                    "src/config.rs",
                    "fn hidden() { std::env::vars(); }",
                    "hidden",
                ),
                (
                    "src/config.rs",
                    "fn hidden() { std::env::vars_os(); }",
                    "hidden",
                ),
                (
                    "src/config.rs",
                    "use std::env::*; fn hidden() { vars(); }",
                    "import",
                ),
                (
                    "src/config.rs",
                    "#[cfg(test)] use std::env; fn hidden() { std::env::var(\"HOME\"); }",
                    "hidden",
                ),
                (
                    "src/config.rs",
                    "fn hidden() { #[cfg(test)] let marker = 1; std::env::var(\"HOME\"); }",
                    "hidden",
                ),
                (
                    "src/config.rs",
                    "impl Impostor { fn load_from_env() { std::env::var_os(\"KRB5_CONFIG\"); } }",
                    "Impostor::load_from_env",
                ),
                (
                    "src/nested/config.rs",
                    "impl Config { fn load_from_env() { std::env::var_os(\"KRB5_CONFIG\"); } }",
                    "src/nested/config.rs",
                ),
                (
                    "src/config.rs",
                    "use std::env as ambient; fn hidden() { ambient::var_os(\"HOME\"); }",
                    "hidden",
                ),
                (
                    "src/config.rs",
                    "use std::env::var as read; fn hidden() { read(\"HOME\"); }",
                    "hidden",
                ),
                (
                    "src/config.rs",
                    "use std::{env::{var_os as read}}; fn hidden() { read(\"HOME\"); }",
                    "hidden",
                ),
                (
                    "src/config.rs",
                    "use std as platform; fn hidden() { platform::env::var(\"HOME\"); }",
                    "hidden",
                ),
                ("src/config.rs", "fn hidden() { env::unknown(); }", "hidden"),
                (
                    "src/config.rs",
                    "impl Config { fn load_from_env() { env::var(\"EVIL\"); } }",
                    "Config::load_from_env",
                ),
                (
                    "src/config.rs",
                    "const HIDDEN: fn() = std::env::vars;",
                    "import/module",
                ),
            ]
            .iter()
            .all(|(file, source, rejected)| {
                // When: the same inventory used on src sees the fixture.
                let failures = access_violations(file, source);
                // Then: it rejects and identifies the forbidden owner/access.
                failures.iter().any(|failure| failure.contains(rejected))
            })
        });
    }

    /// A new public delegate cannot hide behind private helpers or another file.
    #[test]
    fn guard_rejects_undocumented_transitive_delegate() {
        assert!({
            // Given: a real allowed reader reached through two private forwarding hops.
            let (mut items, errors) = inventory(
                "src/config.rs",
                "impl LibDefaults { fn from_env() { env::var(\"HOME\"); } } fn bridge() { LibDefaults::from_env(); }",
            );
            assert!(errors.is_empty(), "{errors:?}");
            let (delegates, _) = inventory(
                "src/new.rs",
                "fn private() { bridge(); } pub fn discover() { private(); }",
            );
            items.extend(delegates);
            // When: the graph is propagated to a fixed point.
            let failures = documentation(&items);
            // Then: the undocumented public API is rejected with its variable.
            failures
                .iter()
                .any(|failure| failure.contains("discover") && failure.contains("HOME"))
        });
    }

    /// Test items and strings/comments cannot create discoveries or leak exemptions.
    #[test]
    fn guard_accepts_exact_test_items_and_literal_text() {
        assert!({
            // Given: nested test scopes, semicolon items and inert source-looking text.
            let source = r##"#[cfg(test)] mod tests { fn probe() { std::env::vars(); } }
            #[cfg(test)] use std::env::*;
            fn regular() { let text = r#"env::var(\"HOME\")"#; let byte = b"env::vars()"; }
            /* nested /* env::vars_os() */ comment */ // env::var("HOME")
        "##;
            // When: CRLF and LF spellings are scanned.
            [source.to_owned(), source.replace('\n', "\r\n")]
                .iter()
                .all(|spelling| {
                    let (_, failures) = inventory("src/config.rs", spelling);
                    // Then: only the attributed items were exempt, and inert text was ignored.
                    failures.is_empty()
                })
        });
    }
}
