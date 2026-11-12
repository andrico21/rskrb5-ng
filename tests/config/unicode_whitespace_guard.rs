//! Class guard: the profile grammar calls no Unicode-aware whitespace API unreviewed.
//!
//! MIT parses profiles with C-locale `isspace`; the parser's predicate for it is
//! `profile_syntax::tag_whitespace`. `str::trim` and its relatives also strip
//! U+0085, U+00A0, U+2028 and other Unicode spaces, so each use in `src/config.rs`
//! or `src/config/**` (including `include!`d files) must be listed below with a
//! reason. Every identifier token is scanned, macro bodies included; a file that
//! does not parse, a non-literal `include!` or a module/include target outside the
//! scanned tree fails closed with `file:line`.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::error::Error;
    use std::{
        collections::BTreeSet,
        fs, io,
        path::{Path, PathBuf},
    };

    use proc_macro2::{Ident, TokenStream, TokenTree};
    use syn::visit::{self, Visit};

    /// Unicode-aware whitespace APIs, as method, path or function-pointer uses.
    const APIS: [&str; 7] = [
        "is_whitespace",
        "split_whitespace",
        "trim",
        "trim_end",
        "trim_left",
        "trim_right",
        "trim_start",
    ];

    /// One reviewed use: file, enclosing function, API and the written reason.
    struct Allowed {
        file: &'static str,
        function: &'static str,
        api: &'static str,
        reason: &'static str,
    }

    /// The reviewed uses (todo 64 and todo 69 call inventories).
    const ALLOWLIST: [Allowed; 1] = [Allowed {
        file: "src/config.rs",
        function: "parse_duration",
        api: "split_whitespace",
        reason: "standalone public gokrb5 parse_duration compatibility API on a caller \
                 string, not profile text; profile durations decode through \
                 libdefaults/duration.rs",
    }];

    /// One use of an API in [`APIS`].
    struct Use {
        file: String,
        line: usize,
        function: String,
        api: String,
    }

    /// The scanned files (canonical paths) under one root.
    struct Tree {
        root: PathBuf,
        files: BTreeSet<PathBuf>,
    }

    impl Tree {
        /// `src/config.rs` and every `.rs` file below `src/config`.
        fn config() -> Result<Self, io::Error> {
            let root = Path::new(env!("CARGO_MANIFEST_DIR")).canonicalize()?;
            let mut files = BTreeSet::from([root.join("src/config.rs").canonicalize()?]);
            let mut pending = vec![root.join("src/config")];
            while let Some(directory) = pending.pop() {
                for entry in fs::read_dir(directory)? {
                    let path = entry?.path();
                    if path.is_dir() {
                        pending.push(path);
                    } else if path.extension().is_some_and(|extension| extension == "rs") {
                        let _: bool = files.insert(path.canonicalize()?);
                    }
                }
            }
            Ok(Self { root, files })
        }

        /// The `/`-separated label of `path` relative to the root.
        fn label(&self, path: &Path) -> String {
            let relative = path.strip_prefix(&self.root).unwrap_or(path);
            let parts: Vec<_> = relative
                .components()
                .map(|part| part.as_os_str().to_string_lossy().into_owned())
                .collect();
            parts.join("/")
        }
    }

    /// Visitor state for one file.
    struct Scan<'tree> {
        tree: &'tree Tree,
        path: &'tree Path,
        file: String,
        owner: Option<String>,
        scope: Vec<String>,
        uses: Vec<Use>,
        failures: Vec<String>,
    }

    impl Scan<'_> {
        /// Record `ident` when it names a Unicode-aware whitespace API.
        fn record(&mut self, ident: &Ident) {
            let name = ident.to_string();
            if APIS.contains(&name.as_str()) {
                self.uses.push(Use {
                    file: self.file.clone(),
                    line: ident.span().start().line,
                    function: self
                        .scope
                        .last()
                        .cloned()
                        .unwrap_or_else(|| "<module>".to_owned()),
                    api: name,
                });
            }
        }

        /// Scan every identifier of an unparsed token stream (macro or attribute body).
        fn tokens(&mut self, stream: TokenStream) {
            for tree in stream {
                match tree {
                    TokenTree::Group(group) => self.tokens(group.stream()),
                    TokenTree::Ident(ident) => self.record(&ident),
                    TokenTree::Punct(_) | TokenTree::Literal(_) => {}
                }
            }
        }

        /// A module or include target must be a literal path inside the scanned tree.
        fn target(&mut self, line: usize, literal: Option<String>) {
            let resolved = literal.and_then(|relative| {
                let parent = self.path.parent()?;
                parent.join(relative).canonicalize().ok()
            });
            if !resolved.is_some_and(|path| self.tree.files.contains(&path)) {
                self.failures.push(format!(
                    "{}:{line}: include or module path is not a literal target in the scanned tree",
                    self.file
                ));
            }
        }

        /// Run `body` with `name` as the enclosing function.
        fn within(&mut self, name: String, body: impl FnOnce(&mut Self)) {
            self.scope.push(name);
            body(self);
            drop(self.scope.pop());
        }
    }

    impl<'ast> Visit<'ast> for Scan<'_> {
        fn visit_ident(&mut self, i: &'ast Ident) {
            self.record(i);
        }

        fn visit_item_fn(&mut self, i: &'ast syn::ItemFn) {
            self.within(i.sig.ident.to_string(), |scan| {
                visit::visit_item_fn(scan, i)
            });
        }

        fn visit_item_impl(&mut self, i: &'ast syn::ItemImpl) {
            let owner = if let syn::Type::Path(path) = &*i.self_ty {
                path.path
                    .segments
                    .last()
                    .map(|segment| segment.ident.to_string())
            } else {
                None
            };
            let outer = core::mem::replace(&mut self.owner, owner);
            visit::visit_item_impl(self, i);
            self.owner = outer;
        }

        fn visit_item_trait(&mut self, i: &'ast syn::ItemTrait) {
            let outer = self.owner.replace(i.ident.to_string());
            visit::visit_item_trait(self, i);
            self.owner = outer;
        }

        fn visit_impl_item_fn(&mut self, i: &'ast syn::ImplItemFn) {
            let owner = self.owner.clone().unwrap_or_else(|| "<impl>".to_owned());
            let name = format!("{owner}::{}", i.sig.ident);
            self.within(name, |scan| visit::visit_impl_item_fn(scan, i));
        }

        fn visit_trait_item_fn(&mut self, i: &'ast syn::TraitItemFn) {
            let owner = self.owner.clone().unwrap_or_else(|| "<trait>".to_owned());
            let name = format!("{owner}::{}", i.sig.ident);
            self.within(name, |scan| visit::visit_trait_item_fn(scan, i));
        }

        fn visit_item_mod(&mut self, i: &'ast syn::ItemMod) {
            for attribute in i.attrs.iter().filter(|a| a.path().is_ident("path")) {
                let literal = if let syn::Meta::NameValue(syn::MetaNameValue {
                    value:
                        syn::Expr::Lit(syn::ExprLit {
                            lit: syn::Lit::Str(text),
                            ..
                        }),
                    ..
                }) = &attribute.meta
                {
                    Some(text.value())
                } else {
                    None
                };
                self.target(attribute.pound_token.span.start().line, literal);
            }
            visit::visit_item_mod(self, i);
        }

        fn visit_macro(&mut self, i: &'ast syn::Macro) {
            if i.path.is_ident("include") {
                let literal = syn::parse2::<syn::LitStr>(i.tokens.clone()).ok();
                self.target(
                    i.bang_token.span.start().line,
                    literal.map(|text| text.value()),
                );
            }
            visit::visit_macro(self, i);
            self.tokens(i.tokens.clone());
        }

        fn visit_meta_list(&mut self, i: &'ast syn::MetaList) {
            visit::visit_meta_list(self, i);
            self.tokens(i.tokens.clone());
        }
    }

    /// Scan one file's source, returning its API uses and fail-closed failures.
    fn scan(tree: &Tree, path: &Path, source: &str) -> (Vec<Use>, Vec<String>) {
        let mut state = Scan {
            tree,
            path,
            file: tree.label(path),
            owner: None,
            scope: Vec::new(),
            uses: Vec::new(),
            failures: Vec::new(),
        };
        match syn::parse_file(source) {
            Ok(file) => state.visit_file(&file),
            Err(error) => state.failures.push(format!(
                "{}:{}: unparseable source: {error}",
                state.file,
                error.span().start().line
            )),
        }
        (state.uses, state.failures)
    }

    /// Unlisted uses and stale allowlist entries, appended to the scan failures.
    fn verdict(uses: &[Use], mut failures: Vec<String>, allowlist: &[Allowed]) -> Vec<String> {
        let listed = |entry: &Allowed, found: &Use| {
            entry.file == found.file && entry.function == found.function && entry.api == found.api
        };
        for found in uses
            .iter()
            .filter(|found| !allowlist.iter().any(|entry| listed(entry, found)))
        {
            failures.push(format!(
                "{}:{}: `{}` in `{}` has no reviewed allowlist entry",
                found.file, found.line, found.api, found.function
            ));
        }
        for entry in allowlist
            .iter()
            .filter(|entry| !uses.iter().any(|found| listed(entry, found)))
        {
            failures.push(format!(
                "stale allowlist entry {}::{} `{}` ({})",
                entry.file, entry.function, entry.api, entry.reason
            ));
        }
        failures
    }

    /// Check one fixture source named `fixture.rs` against `allowlist`.
    fn fixture(source: &str, allowlist: &[Allowed]) -> Vec<String> {
        let tree = Tree {
            root: PathBuf::new(),
            files: BTreeSet::new(),
        };
        let (uses, failures) = scan(&tree, Path::new("fixture.rs"), source);
        verdict(&uses, failures, allowlist)
    }

    /// Every Unicode-aware whitespace use in the profile grammar is reviewed.
    #[test]
    fn profile_grammar_uses_only_reviewed_whitespace_apis() -> Result<(), Box<dyn Error>> {
        let tree = Tree::config()?;
        let mut uses = Vec::new();
        let mut failures = Vec::new();
        for path in &tree.files {
            let (found, failed) = scan(&tree, path, &fs::read_to_string(path)?);
            uses.extend(found);
            failures.extend(failed);
        }
        let failures = verdict(&uses, failures, &ALLOWLIST);
        assert!(failures.is_empty(), "{}", failures.join("\n"));
        Ok(())
    }

    /// Negative control: an unlisted `.trim()` fails and names `file:line`.
    #[test]
    fn unlisted_trim_fails() {
        let source = "fn f(s: &str) -> &str {\n    s.trim()\n}\n";
        assert_eq!(
            fixture(source, &[]),
            ["fixture.rs:2: `trim` in `f` has no reviewed allowlist entry"]
        );
    }

    /// Control: an allowlisted use passes; the same entry for another function is stale.
    #[test]
    fn allowlisted_trim_passes() {
        let source = "fn f(s: &str) -> &str {\n    s.trim()\n}\n";
        let entry = |function| Allowed {
            file: "fixture.rs",
            function,
            api: "trim",
            reason: "fixture",
        };
        assert!(fixture(source, &[entry("f")]).is_empty());
        assert_eq!(fixture(source, &[entry("g")]).len(), 2);
    }

    /// Negative control: `char::is_whitespace` as a path or function pointer fails.
    #[test]
    fn char_is_whitespace_path_fails() {
        let source = "fn g(s: &str) -> bool {\n    s.contains(char::is_whitespace)\n}\n";
        assert_eq!(
            fixture(source, &[]),
            ["fixture.rs:2: `is_whitespace` in `g` has no reviewed allowlist entry"]
        );
    }

    /// Negative control: macro bodies and method impls are scanned with their owner.
    #[test]
    fn macro_bodies_in_methods_fail() {
        let source = "impl S {\n    fn h(s: &str) -> String {\n        format!(\"{}\", s.trim_end())\n    }\n}\n";
        assert_eq!(
            fixture(source, &[]),
            ["fixture.rs:3: `trim_end` in `S::h` has no reviewed allowlist entry"]
        );
    }

    /// Negative control: non-literal includes, foreign module paths and bad syntax fail closed.
    #[test]
    fn unclassifiable_sources_fail_closed() {
        let include = fixture("include!(concat!(\"a\", \".rs\"));\n", &[]);
        let module = fixture("#[path = \"../other.rs\"]\nmod other;\n", &[]);
        let broken = fixture("fn f( {\n", &[]);
        for (failures, prefix) in [
            (include, "fixture.rs:1: include or module path"),
            (module, "fixture.rs:1: include or module path"),
            (broken, "fixture.rs:1: unparseable source"),
        ] {
            assert!(
                failures.len() == 1 && failures.iter().all(|failure| failure.starts_with(prefix)),
                "{failures:?}"
            );
        }
    }
}
