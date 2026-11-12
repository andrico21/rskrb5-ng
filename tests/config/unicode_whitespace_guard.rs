//! Class guard: the profile grammar calls no non-C-locale whitespace API unreviewed.
//!
//! Each `trim`, `trim_start`, `trim_end`, `trim_left`, `trim_right`,
//! `split_whitespace`, `is_whitespace` or ASCII variant (`is_ascii_whitespace`,
//! `split_ascii_whitespace`, `trim_ascii`, `trim_ascii_start`, `trim_ascii_end`)
//! use in `src/config.rs` or `src/config/**`
//! (including `include!`d files) must be listed in [`tests::ALLOWLIST`] with a
//! reason; the profile grammar itself uses the C-locale `tag_whitespace` predicate.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    extern crate alloc;

    use alloc::collections::BTreeSet;
    use core::error::Error;
    use std::{
        fs, io,
        path::{Path, PathBuf},
    };

    use crate::whitespace_scan::{Allowed, Tree, scan, verdict};

    /// The reviewed uses (todo 64 and todo 69 call inventories).
    const ALLOWLIST: [Allowed; 1] = [Allowed {
        file: "src/config.rs",
        function: "parse_duration",
        api: "split_whitespace",
        reason: "standalone public gokrb5 parse_duration compatibility API on a caller \
                 string, not profile text; profile durations decode through \
                 libdefaults/duration.rs",
    }];

    /// Check one fixture source named `fixture.rs` against `allowlist`.
    fn fixture(source: &str, allowlist: &[Allowed]) -> Vec<String> {
        let tree = Tree {
            root: PathBuf::new(),
            files: BTreeSet::new(),
        };
        let (uses, failures) = scan(&tree, Path::new("fixture.rs"), source);
        verdict(&uses, failures, allowlist)
    }

    /// Scan `src/config.rs` and `src/config/**` and check every use against `allowlist`.
    fn check_config(allowlist: &[Allowed]) -> Result<Vec<String>, io::Error> {
        let tree = Tree::config()?;
        let mut uses = Vec::new();
        let mut failures = Vec::new();
        for path in &tree.files {
            let (found, failed) = scan(&tree, path, &fs::read_to_string(path)?);
            uses.extend(found);
            failures.extend(failed);
        }
        Ok(verdict(&uses, failures, allowlist))
    }

    /// Every Unicode-aware whitespace use in the profile grammar is reviewed.
    #[test]
    fn profile_grammar_uses_only_reviewed_whitespace_apis() -> Result<(), Box<dyn Error>> {
        let unreviewed = check_config(&ALLOWLIST)?;
        assert!(unreviewed.is_empty(), "{}", unreviewed.join("\n"));
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
        assert_eq!(fixture(source, &[entry("f")]), Vec::<String>::new());
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

    /// Negative control: each ASCII-whitespace API (method, path or function pointer) fails.
    #[test]
    fn ascii_whitespace_apis_fail() {
        for (body, api) in [
            ("s.split(|ch: char| ch == ',' || ch.is_ascii_whitespace())", "is_ascii_whitespace"),
            ("s.contains(u8::is_ascii_whitespace)", "is_ascii_whitespace"),
            ("s.split_ascii_whitespace().next()", "split_ascii_whitespace"),
            ("s.trim_ascii()", "trim_ascii"),
            ("s.trim_ascii_start()", "trim_ascii_start"),
            ("s.trim_ascii_end()", "trim_ascii_end"),
        ] {
            let source = format!("fn k(s: &str) {{\n    let _ = {body};\n}}\n");
            assert_eq!(
                fixture(&source, &[]),
                [format!("fixture.rs:2: `{api}` in `k` has no reviewed allowlist entry")],
                "{body}"
            );
        }
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
        for source in [
            "include!(concat!(\"a\", \".rs\"));\n",
            "#[path = \"../other.rs\"]\nmod other;\n",
        ] {
            assert!(
                matches!(fixture(source, &[]).as_slice(), [failure]
                    if failure.starts_with("fixture.rs:1: include or module path")),
                "{source:?}"
            );
        }
        assert!(matches!(fixture("fn f( {\n", &[]).as_slice(), [failure]
            if failure.starts_with("fixture.rs:1: unparseable source")));
    }
}
