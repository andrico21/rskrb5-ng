#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
# How to run: python3 scripts/lint-gates/exception_gate.py --enforce
"""Admit only the six sanctioned lint exceptions, each on its item kind.

Every `#[expect]`/`#![expect]` in the Rust tree, including one nested in
`cfg_attr`, must be exactly one of:

1. a test pair on a `mod` under `#[cfg(test)]`:
   `clippy::missing_errors_doc`, `clippy::missing_panics_doc` and/or
   `clippy::too_long_first_doc_paragraph` with "test code is not rendered API
   documentation", or `clippy::panic_in_result_fn` with "a test fails by
   panicking";
2. `missing_copy_implementations` on a type, "secret material must not be
   implicitly copied";
3. the crate-root facade `#![expect(clippy::pub_use, reason = "public facade")]`
   in `src/lib.rs`;
4. `clippy::missing_const_for_fn` on a `fn`, "deliberate: <path> - <why>";
5. `clippy::unused_async_trait_impl` on a `fn` or `impl`,
   "deliberate: <path> - <foreign trait> mandates async";
6. `#![cfg_attr(test, expect(dead_code_pub_in_binary, reason = "public API:
   unused inside the unit-test harness"))]` in `src/lib.rs`.

`#[deny(lint, reason = "...")]` opt-ins of excluded lints are not exceptions and
pass. `#[allow]` is the allow gate's business.

Whitespace between `#`, `!` and `[` does not hide an attribute. A spelling the
lexer cannot see through (a macro metavariable in or as an attribute, an
`expect(..)` token tree handed to a macro, `include!` or `#[path]` of a file the
gates do not scan) is reported: fail closed.
"""

from __future__ import annotations

import argparse
import re
import sys
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Final

import common

TEST_DOCS: Final = frozenset(
    {
        "clippy::missing_errors_doc",
        "clippy::missing_panics_doc",
        "clippy::too_long_first_doc_paragraph",
    }
)
TEST_DOCS_REASON: Final = "test code is not rendered API documentation"
TEST_PANIC_REASON: Final = "a test fails by panicking"
SECRET_REASON: Final = "secret material must not be implicitly copied"
FACADE_REASON: Final = "public facade"
HARNESS_REASON: Final = "public API: unused inside the unit-test harness"
DELIBERATE_CONST: Final = re.compile(r"deliberate: \S*::\S* - \S.*", re.S)
DELIBERATE_ASYNC: Final = re.compile(
    r"deliberate: \S*::\S* - \S.* mandates async", re.S
)
TYPE_KINDS: Final = frozenset({"struct", "enum", "union"})
CRATE_ROOT: Final = "src/lib.rs"


def is_cfg_test(body: str) -> bool:
    predicate = re.sub(r"\s+", "", body)
    return predicate == "cfg(test)" or predicate.startswith("cfg(all(test,")


def under_cfg_test(stripped: str, items: list[common.Item], item: common.Item) -> bool:
    """The item, or an item enclosing it, carries `#[cfg(test)]`."""
    return any(
        outer.start <= item.start and item.end <= outer.end
        for outer in items
        for _, _, inner, body in common.iter_attributes(
            stripped[outer.start : outer.keyword]
        )
        if not inner and is_cfg_test(body)
    )


def outer_item(items: list[common.Item], offset: int) -> common.Item | None:
    """The item an outer attribute at `offset` belongs to."""
    return max(
        (item for item in items if item.start <= offset < item.keyword),
        key=lambda item: item.start,
        default=None,
    )


def check(
    call: common.AttributeCall,
    file: str,
    stripped: str,
    items: list[common.Item],
) -> str | None:
    """Return why `call` is not a sanctioned exception, or None."""
    lints, reason = call.lints, call.reason
    if reason.startswith(("lint-migration:", "invariant:")):
        return f"transition reason form {reason.split(':', 1)[0]!r} is forbidden"
    if call.inner:
        enclosing = common.owner(items, call.start)
        crate_level = file == CRATE_ROOT and enclosing is None
        if lints == ("clippy::pub_use",) and reason == FACADE_REASON:
            if crate_level and call.predicate == "always":
                return None
            return "the facade is allowed only as a plain inner attribute of src/lib.rs"
        if lints == ("dead_code_pub_in_binary",) and reason == HARNESS_REASON:
            if crate_level and call.predicate == "test":
                return None
            return (
                "form (6) is allowed only as the inner "
                "cfg_attr(test, expect(..)) attribute of src/lib.rs"
            )
        return "only the facade and form (6) may be inner attributes"
    item = outer_item(items, call.start)
    kind = item.kind if item is not None else "statement"
    test_docs = (
        lints
        and len(set(lints)) == len(lints)
        and set(lints) <= TEST_DOCS
        and reason == TEST_DOCS_REASON
    )
    test_panic = (
        lints == ("clippy::panic_in_result_fn",) and reason == TEST_PANIC_REASON
    )
    if test_docs or test_panic:
        if item is not None and kind == "mod" and under_cfg_test(stripped, items, item):
            return None
        return f"a test pair is allowed only on a mod under #[cfg(test)], not on {kind}"
    if lints == ("missing_copy_implementations",) and reason == SECRET_REASON:
        return (
            None if kind in TYPE_KINDS else f"the secret pair needs a type, not {kind}"
        )
    if lints == ("clippy::missing_const_for_fn",) and DELIBERATE_CONST.fullmatch(
        reason
    ):
        return None if kind == "fn" else f"deliberate const needs a fn, not {kind}"
    if lints == ("clippy::unused_async_trait_impl",) and DELIBERATE_ASYNC.fullmatch(
        reason
    ):
        return None if kind in ("fn", "impl") else f"deliberate async on {kind}"
    if lints == ("clippy::pub_use",) and reason == FACADE_REASON:
        return "the facade is allowed only as an inner attribute of src/lib.rs"
    if lints == ("dead_code_pub_in_binary",) and reason == HARNESS_REASON:
        return "form (6) is allowed only as an inner attribute of src/lib.rs"
    return "not one of the six sanctioned exception forms"


def scan(file: str, source: str) -> list[str]:
    stripped = common.strip_comments_and_strings(source)
    items = common.scan_items(source)
    hits = []
    for call in common.attribute_calls(source, stripped):
        if call.form != "expect":
            continue
        problem = check(call, file, stripped, items)
        if problem is not None:
            line = common.line_of(source, call.kw_start)
            hits.append(
                f"{file}:{line}: expect({', '.join(call.lints)}, "
                f"reason = {call.reason!r}) [{call.predicate}]: {problem}"
            )
    for offset, why in common.unscannable(source, stripped):
        hits.append(f"{file}:{common.line_of(source, offset)}: {why}")
    return hits


def report(root: Path) -> list[str]:
    return [
        hit
        for path in common.iter_rust_files(root)
        for hit in scan(path.relative_to(root).as_posix(), path.read_text())
    ]


ACCEPTED: Final = (
    (
        "src/client.rs",
        "#[cfg(test)]\n#[expect(\n    clippy::missing_errors_doc,\n"
        '    clippy::too_long_first_doc_paragraph,\n    reason = "test code is not rendered API documentation"\n)]\n'
        "mod tests {}\n",
    ),
    (
        "tests/kdc.rs",
        '#[cfg(test)]\n#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]\n'
        "mod tests {}\n",
    ),
    (
        "src/crypto.rs",
        '/// Key bytes.\n#[expect(missing_copy_implementations, reason = "secret material must not be implicitly copied")]\n'
        "pub struct Key { bytes: [u8; 16] }\n",
    ),
    (
        "src/lib.rs",
        '//! Crate.\n#![forbid(unsafe_code)]\n#![expect(clippy::pub_use, reason = "public facade")]\n'
        "pub use crate::client::Client;\n",
    ),
    (
        "src/client.rs",
        "impl Client {\n    #[expect(\n        clippy::missing_const_for_fn,\n"
        '        reason = "deliberate: crate::Client::new - may allocate later"\n    )]\n'
        "    pub fn new() -> Self { Self }\n}\n",
    ),
    (
        "src/http.rs",
        "impl Service for Layer {\n    #[expect(\n        clippy::unused_async_trait_impl,\n"
        '        reason = "deliberate: crate::http::Layer::call - tower::Service mandates async"\n    )]\n'
        "    async fn call(&self) {}\n}\n",
    ),
    (
        "src/lib.rs",
        "#![cfg_attr(\n    test,\n    expect(\n        dead_code_pub_in_binary,\n"
        '        reason = "public API: unused inside the unit-test harness"\n    )\n)]\n',
    ),
    (
        "src/io.rs",
        '#[deny(clippy::missing_trait_methods, reason = "every Read method must delegate")]\n'
        "impl Read for Audited {}\n",
    ),
)

REJECTED: Final = (
    (
        "invariant:",
        "src/der.rs",
        '#[expect(clippy::indexing_slicing, reason = "invariant: checked above")]\nfn f() {}\n',
    ),
    (
        "lint-migration:",
        "src/der.rs",
        '#[cfg_attr(test, expect(dead_code, reason = "lint-migration: upstream baseline at abc1234"))]\nfn f() {}\n',
    ),
    (
        "test pair on a non-test item",
        "src/der.rs",
        '#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]\nmod tests {}\n'
        '#[cfg(test)]\n#[expect(clippy::missing_panics_doc, reason = "test code is not rendered API documentation")]\nfn helper() {}\n',
    ),
    (
        "facade outside lib.rs",
        "src/client.rs",
        '#![expect(clippy::pub_use, reason = "public facade")]\npub use crate::Thing;\n',
    ),
    (
        "form (6) outside lib.rs",
        "src/main.rs",
        '#![cfg_attr(test, expect(dead_code_pub_in_binary, reason = "public API: unused inside the unit-test harness"))]\n',
    ),
)


EVASIONS: Final = (
    (
        "spaced '# [expect]'",
        "src/der.rs",
        '#[rustfmt::skip]\n# [expect(dead_code, reason = "x")]\nfn f() {}\n',
    ),
    ("spaced inner", "src/der.rs", '# ! [expect(dead_code, reason = "x")]\n'),
    (
        "raw identifier",
        "src/der.rs",
        '#[r#expect(dead_code, reason = "x")]\nfn f() {}\n',
    ),
    (
        "meta fragment",
        "src/der.rs",
        "macro_rules! m { ($a:meta) => { #[$a] fn f() {} } }\n"
        'm!(expect(dead_code, reason = "x"));\n',
    ),
    (
        "tt fragment",
        "src/der.rs",
        "macro_rules! m { ($t:tt) => { #$t fn f() {} } }\n",
    ),
    (
        "foreign macro argument",
        "src/der.rs",
        'other_crate::with_attr!(expect(dead_code, reason = "x"), fn f() {});\n',
    ),
    ("include! of a .txt", "src/der.rs", 'include!("d.txt");\n'),
    ("path to a .txt", "src/der.rs", '#[path = "d.txt"]\nmod d;\n'),
    (
        "sanctioned reason, spaced, on the wrong item",
        "src/der.rs",
        '# [expect(missing_copy_implementations, reason = "secret material must not be implicitly copied")]\nfn f() {}\n',
    ),
)

# A forbidden lint beside a sanctioned one, spelled so that a parser reading
# only `\w+(::\w+)*` arguments drops it: `clippy-driver -D clippy::unwrap_used`
# honours both attributes (U6-01), so each must be a hit naming `unwrap_used`.
HIDDEN_LINT: Final = (
    "#[expect(clippy::missing_const_for_fn, {lint},\n"
    '    reason = "deliberate: crate::f - runtime API")]\n'
    "pub fn f(o: Option<u8>) -> u8 {{ o.unwrap() }}\n"
)
HIDDEN_LINTS: Final = (
    ("spaced lint path", "clippy :: unwrap_used"),
    ("raw lint path segment", "clippy::r#unwrap_used"),
    ("spaced raw lint path", "clippy ::\n    r#unwrap_used"),
    ("unparsed argument", "clippy::unwrap_used()"),
)


WHY: Final = {
    "invariant:": "transition reason form 'invariant'",
    "lint-migration:": "transition reason form 'lint-migration'",
    "test pair on a non-test item": "only on a mod under #[cfg(test)]",
    "facade outside lib.rs": "only as a plain inner attribute of src/lib.rs",
    "form (6) outside lib.rs": "form (6) is allowed only as the inner",
}


def self_test() -> int:
    for file, source in ACCEPTED:
        assert scan(file, source) == [], (file, source, scan(file, source))
    for label, file, source in REJECTED:
        hits = scan(file, source)
        expected = 2 if label == "test pair on a non-test item" else 1
        assert len(hits) == expected, (label, hits)
        assert all(WHY[label] in hit for hit in hits), (label, hits)
    # Near misses of the sanctioned forms are rejected too.
    for file, source in (
        ("src/der.rs", '#[expect(clippy::unwrap_used, reason = "x")]\nfn f() {}\n'),
        ("src/lib.rs", '#![expect(clippy::pub_use, reason = "public facade!")]\n'),
        (
            "src/lib.rs",
            '#![expect(dead_code_pub_in_binary, reason = "public API: unused inside the unit-test harness")]\n',
        ),
        (
            "src/lib.rs",
            'mod inner {\n    #![expect(clippy::pub_use, reason = "public facade")]\n}\n',
        ),
        (
            "src/crypto.rs",
            '#[expect(missing_copy_implementations, reason = "secret material must not be implicitly copied")]\nfn f() {}\n',
        ),
        (
            "src/client.rs",
            '#[expect(clippy::missing_const_for_fn, reason = "deliberate: new - no path")]\nfn new() {}\n',
        ),
        (
            "src/client.rs",
            '#[cfg(test)]\n#[expect(clippy::missing_errors_doc, clippy::missing_errors_doc, reason = "test code is not rendered API documentation")]\nmod tests {}\n',
        ),
    ):
        assert len(scan(file, source)) == 1, (file, source, scan(file, source))
    # Lexical evasions from the Wave 4 review compile clean and must be hits.
    for label, file, source in EVASIONS:
        assert len(scan(file, source)) >= 1, (label, scan(file, source))
    for label, lint in HIDDEN_LINTS:
        hits = scan("src/der.rs", HIDDEN_LINT.format(lint=lint))
        assert len(hits) == 1 and "unwrap_used" in hits[0], (label, hits)
    # The canonical spelling of a sanctioned lint still passes.
    spaced_ok = HIDDEN_LINT.replace(
        "clippy::missing_const_for_fn, {lint},", "clippy :: r#missing_const_for_fn,"
    )
    assert scan("src/der.rs", spaced_ok.format()) == [], scan(
        "src/der.rs", spaced_ok.format()
    )
    # Spacing alone neither hides nor breaks a sanctioned form.
    assert scan("src/crypto.rs", ACCEPTED[2][1].replace("#[expect", "# [expect")) == []
    # A test pair on a mod nested in a cfg(test) mod is under cfg(test).
    nested = (
        "#[cfg(test)]\nmod tests {\n"
        '    #[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]\n'
        "    mod inner {}\n}\n"
    )
    assert scan("src/der.rs", nested) == []
    with TemporaryDirectory() as directory:
        root = Path(directory)
        (root / "src").mkdir()
        (root / "src/der.rs").write_text(REJECTED[0][2])
        assert main(["--enforce", "--root", str(root)]) == 1
        (root / "src/der.rs").write_text(ACCEPTED[1][1])
        assert main(["--enforce", "--root", str(root)]) == 0
        # A build script and a custom-path Cargo target are scanned too.
        (root / "tools").mkdir()
        (root / "Cargo.toml").write_text(
            '[package]\nname = "p"\nbuild = "build.rs"\n'
            '[[bin]]\nname = "probe"\npath = "tools/probe.rs"\n'
        )
        (root / "build.rs").write_text(REJECTED[0][2])
        (root / "tools/probe.rs").write_text(
            HIDDEN_LINT.format(lint="clippy::unwrap_used")
        )
        printed = StringIO()
        with redirect_stdout(printed):
            assert main(["--enforce", "--root", str(root)]) == 1
        assert "build.rs:1:" in printed.getvalue(), printed.getvalue()
        assert "tools/probe.rs:1:" in printed.getvalue(), printed.getvalue()
        # U6-01: macro names (also repeated) cannot load unscanned siblings.
        (root / "tools/probe.rs").write_text("fn main() {}\n")
        (root / "hidden.rs").write_text(
            '#[expect(clippy::print_stdout, reason = "not sanctioned")]\n'
            'pub fn emit() { println!("hidden"); }\n'
        )
        accepted = []
        for source in (
            "macro_rules! load { ($name:ident) => { mod $name; } }\nload!(hidden);\n",
            "macro_rules! load { ($($name:ident),*) => { $(mod $name;)* } }\nload!(hidden);\n",
            "macro_rules! load { ($kind:ident $name:ident) => { $kind $name; } }\nload!(mod hidden);\n",
            "macro_rules! load { ($($token:tt)*) => { $($token)* } }\nload!(mod hidden);\n",
            "other_crate::load!(hidden);\n",
            "use other_crate::load as println;\nprintln!(hidden);\n",
            "use other_crate::*;\nprintln!(hidden);\n",
        ):
            (root / "build.rs").write_text(source + "fn main() { hidden::emit(); }\n")
            with redirect_stdout(StringIO()) as printed:
                result = main(["--enforce", "--root", str(root)])
            if result != 1:
                accepted.append((source, result, printed.getvalue()))
        assert not accepted, ("macro sibling source loading accepted", accepted)
        (root / "build.rs").write_text(
            "macro_rules! load { ($name:ident) => { mod $name {} } }\n"
            "load!(inline);\nfn main() {}\n"
        )
        with redirect_stdout(StringIO()):
            assert main(["--enforce", "--root", str(root)]) == 0
        (root / "build.rs").write_text(
            'fn main() { println!("cargo:rerun-if-changed=build.rs"); '
            'let _ = format!("{}", env!("CARGO_PKG_NAME")); }\n'
        )
        with redirect_stdout(StringIO()):
            assert main(["--enforce", "--root", str(root)]) == 0
        # REL-01: root single-file targets cannot hide included exceptions.
        (root / "tools/probe.rs").write_text("fn main() {}\n")
        (root / "build_impl.rs").write_text(REJECTED[0][2])
        for source in (
            'include!("build_impl.rs");\n',
            'r#include! { "build_impl.rs" }\n',
            '#[path = "hidden"] mod inline { include!("build_impl.rs"); }\n',
            '#[cfg_attr(all(), path = "hidden")] mod inline {}\n',
        ):
            (root / "build.rs").write_text(source)
            with redirect_stdout(StringIO()) as printed:
                result = main(["--enforce", "--root", str(root)])
            assert result == 1, (
                "root source loading accepted",
                source,
                printed.getvalue(),
            )
            assert "build.rs" in printed.getvalue(), printed.getvalue()
    print(
        "exception_gate self-test: ok (six sanctioned forms and a deny opt-in "
        "accepted; five rejected forms, seven near misses, "
        f"{len(EVASIONS)} lexical evasions and {len(HIDDEN_LINTS)} hidden lint "
        "paths rejected)"
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=common.ROOT)
    parser.add_argument("--enforce", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    try:
        hits = report(args.root)
    except common.source_set.SourceSetError as error:
        print(f"exception_gate: {error}")
        return 1
    print(
        "\n".join(
            hits
            + [
                f"exception_gate: {len(hits)} unsanctioned expect(s) "
                "or unscannable construct(s)"
            ]
        )
    )
    return int(args.enforce and bool(hits))


if __name__ == "__main__":
    sys.exit(main())
