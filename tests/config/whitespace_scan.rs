//! Scanner for Unicode-aware whitespace APIs in the profile grammar.
//!
//! MIT parses profiles with C-locale `isspace`; the parser's predicate for it is
//! `profile_syntax::tag_whitespace`. `str::trim` and its relatives also strip
//! U+0085, U+00A0, U+2028 and other Unicode spaces; the `*ascii*` variants are
//! narrower but still not MIT's set (no vertical tab, form feed accepted), which
//! is how `parse_ip_addresses` and `spake_preauth_groups` diverged. Every identifier token of
//! `src/config.rs` and `src/config/**` is scanned, macro and attribute bodies
//! included; a file that does not parse, a non-literal `include!` or a module or
//! include target outside the scanned tree fails closed with `file:line`.

extern crate alloc;

use alloc::collections::BTreeSet;
use std::{
    fs, io,
    path::{Path, PathBuf},
};

use proc_macro2::{Ident, TokenStream, TokenTree};
use syn::visit::{self, Visit};

/// Whitespace APIs whose set is not MIT's C-locale `isspace`, as method, path or
/// function-pointer uses: the Unicode-aware ones and the ASCII variants.
const APIS: [&str; 12] = [
    "is_ascii_whitespace",
    "is_whitespace",
    "split_ascii_whitespace",
    "split_whitespace",
    "trim",
    "trim_ascii",
    "trim_ascii_end",
    "trim_ascii_start",
    "trim_end",
    "trim_left",
    "trim_right",
    "trim_start",
];

/// One reviewed use: file, enclosing function, API and the written reason.
pub(crate) struct Allowed {
    /// `/`-separated path relative to the crate root.
    pub file: &'static str,
    /// Enclosing function, `Owner::method` inside an impl or trait.
    pub function: &'static str,
    /// The API name from [`APIS`].
    pub api: &'static str,
    /// Why this use is not profile-grammar whitespace.
    pub reason: &'static str,
}

/// One use of an API in [`APIS`].
pub(crate) struct Use {
    file: String,
    line: usize,
    function: String,
    api: String,
}

/// The scanned files (canonical paths) under one root.
pub(crate) struct Tree {
    /// Canonical crate root.
    pub root: PathBuf,
    /// Canonical paths of the scanned files.
    pub files: BTreeSet<PathBuf>,
}

impl Tree {
    /// `src/config.rs` and every `.rs` file below `src/config`.
    ///
    /// # Errors
    /// Returns the I/O error of a directory walk or path canonicalization.
    pub(crate) fn config() -> Result<Self, io::Error> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).canonicalize()?;
        let mut files = BTreeSet::from([root.join("src/config.rs").canonicalize()?]);
        let mut pending = vec![root.join("src/config")];
        while let Some(directory) = pending.pop() {
            for entry in fs::read_dir(directory)? {
                let path = entry?.path();
                if path.is_dir() {
                    pending.push(path);
                    continue;
                }
                if path.extension().is_some_and(|extension| extension == "rs") {
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
            visit::visit_item_fn(scan, i);
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
        let outer = self.owner.take();
        self.owner = owner;
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
        self.within(name, |scan| {
            visit::visit_impl_item_fn(scan, i);
        });
    }

    fn visit_trait_item_fn(&mut self, i: &'ast syn::TraitItemFn) {
        let owner = self.owner.clone().unwrap_or_else(|| "<trait>".to_owned());
        let name = format!("{owner}::{}", i.sig.ident);
        self.within(name, |scan| {
            visit::visit_trait_item_fn(scan, i);
        });
    }

    fn visit_item_mod(&mut self, i: &'ast syn::ItemMod) {
        for attribute in i
            .attrs
            .iter()
            .filter(|candidate| candidate.path().is_ident("path"))
        {
            let literal = if let syn::Meta::NameValue(syn::MetaNameValue {
                path: _,
                eq_token: _,
                value:
                    syn::Expr::Lit(syn::ExprLit {
                        attrs: _,
                        lit: syn::Lit::Str(text),
                    }),
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
pub(crate) fn scan(tree: &Tree, path: &Path, source: &str) -> (Vec<Use>, Vec<String>) {
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
pub(crate) fn verdict(
    uses: &[Use],
    mut failures: Vec<String>,
    allowlist: &[Allowed],
) -> Vec<String> {
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
