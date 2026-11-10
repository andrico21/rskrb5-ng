#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
# How to run: python3 scripts/lint-gates/allow_gate.py --self-test
"""Forbid Rust allow attributes; ported from rmcp-server-kit (MIT/Apache-2.0).

Spelling that the lexer cannot see through (a macro metavariable in or as an
attribute, an `allow(..)` token tree handed to a macro, `include!` or
`#[path]` of a file the gates do not scan) is reported too: fail closed.
"""

from __future__ import annotations

import argparse
import sys
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Final

import common


def scan(files: list[Path]) -> list[str]:
    hits = []
    for path in files:
        original, stripped = common.read_source(path)
        for call in common.attribute_calls(original, stripped):
            if call.form == "allow":
                hits.append(
                    f"{path}:{common.line_of(original, call.kw_start)}: allow({', '.join(call.lints)}) [{call.predicate}]"
                )
        for offset, why in common.unscannable(original, stripped):
            hits.append(f"{path}:{common.line_of(original, offset)}: {why}")
    return hits


# Lexical evasions from the Wave 4 review: each compiles clean under
# `clippy -D warnings`, so each must be a hit here.
EVASIONS: Final = (
    ("spaced outer", "#[rustfmt::skip]\n# [allow(dead_code)]\nfn f() {}\n"),
    ("spaced inner", "#![cfg_attr(rustfmt, rustfmt::skip)]\n# ! [allow(dead_code)]\n"),
    ("comment between", "#/* c */[allow(dead_code)]\nfn f() {}\n"),
    ("raw identifier", "#[r#allow(dead_code)]\nfn f() {}\n"),
    (
        "meta fragment",
        "macro_rules! m { ($a:meta) => { #[$a] fn f() {} } }\nm!(allow(dead_code));\n",
    ),
    (
        "tt fragment",
        "macro_rules! m { ($t:tt) => { #$t fn f() {} } }\nm!([allow(dead_code)]);\n",
    ),
    (
        "cfg_attr fragment",
        "macro_rules! m { ($($t:tt)*) => { #[cfg_attr(all(), $($t)*)] fn f() {} } }\n",
    ),
    (
        "foreign macro argument",
        "other_crate::with_attr!(allow(dead_code), fn f() {});\n",
    ),
    ("include! of a .txt", 'include!("d.txt");\n'),
    ("include! of a computed path", 'include!(concat!(env!("OUT_DIR"), "/d.rs"));\n'),
    ("include! outside the tree", 'include!("../../d.rs");\n'),
    ("path to a .txt", '#[path = "d.txt"]\nmod d;\n'),
    ("path in cfg_attr", '#[cfg_attr(all(), path = "d.txt")]\nmod d;\n'),
    ("non-path attribute", "#[[<al low>](dead_code)]\nfn f() {}\n"),
)


def self_test() -> int:
    with TemporaryDirectory() as directory:
        root = Path(directory)
        path = root / "fixture.rs"
        path.write_text(
            '// #[allow(fake)]\nconst X: &str = "#[allow(fake)]";\n'
            "#[cfg_attr(test, allow(dead_code), derive(Debug))]\nfn f() {}\n"
            "#![allow(unused)]\n#[allow(a,b)]\n"
        )
        hits = scan([path])
        assert len(hits) == 3 and ":3:" in hits[0]
        assert "a, b" in hits[-1]
        (root / "fuzz/fuzz_targets").mkdir(parents=True)
        (root / "fuzz/fuzz_targets/probe.rs").write_text("#![allow(unused)]")
        assert len(scan(list(common.iter_rust_files(root)))) == 1
        with redirect_stdout(StringIO()):
            assert main(["--files", str(path)]) == 0
            assert main(["--enforce", "--files", str(path)]) == 1
        path.write_text(
            '//! docs\n#![cfg_attr(test, expect(dead_code_pub_in_binary, reason = "lint-migration: upstream baseline at abc1234"))]\npub fn f() {}\n'
        )
        assert scan([path]) == []
        for label, source in EVASIONS:
            path.write_text(source)
            assert len(scan([path])) >= 1, (label, source)
            with redirect_stdout(StringIO()):
                assert main(["--enforce", "--files", str(path)]) == 1, label
        path.write_text(
            '#[path = "support/env.rs"]\nmod env;\nconst S: &str = include_str!("d.txt");\n'
            'fn f() { x.expect("y"); Option::expect(o, "y"); }\nfn expect() {}\n'
        )
        assert scan([path]) == [], scan([path])
        # A build script and a custom-path Cargo target are scanned too.
        package = root / "package"
        (package / "src").mkdir(parents=True)
        (package / "tools").mkdir()
        (package / "Cargo.toml").write_text(
            '[package]\nname = "p"\n[[bin]]\nname = "probe"\npath = "tools/probe.rs"\n'
        )
        (package / "src/lib.rs").write_text("pub fn f() {}\n")
        (package / "build.rs").write_text("#![allow(unused)]\nfn main() {}\n")
        (package / "tools/probe.rs").write_text("#[allow(dead_code)]\nfn main() {}\n")
        with redirect_stdout(StringIO()) as printed:
            assert main(["--enforce", "--root", str(package)]) == 1
        assert "build.rs:1:" in printed.getvalue(), printed.getvalue()
        assert "probe.rs:1:" in printed.getvalue(), printed.getvalue()
        assert "allow_gate: 2 " in printed.getvalue(), printed.getvalue()
        # U6-01: macro names (also repeated) cannot load unscanned siblings.
        (package / "tools/probe.rs").write_text("fn main() {}\n")
        (package / "hidden.rs").write_text(
            '#[allow(clippy::print_stdout)]\npub fn emit() { println!("hidden"); }\n'
        )
        accepted = []
        for source in (
            "macro_rules! load { ($name:ident) => { mod $name; } }\nload!(hidden);\n",
            "macro_rules! load { ($($name:ident),*) => { $(mod $name;)* } }\nload!(hidden);\n",
        ):
            (package / "build.rs").write_text(
                source + "fn main() { hidden::emit(); }\n"
            )
            with redirect_stdout(StringIO()) as printed:
                result = main(["--enforce", "--root", str(package)])
            if result != 1:
                accepted.append((source, result, printed.getvalue()))
        assert not accepted, ("macro sibling source loading accepted", accepted)
        (package / "build.rs").write_text(
            "macro_rules! load { ($name:ident) => { mod $name {} } }\n"
            "load!(inline);\nfn main() {}\n"
        )
        with redirect_stdout(StringIO()):
            assert main(["--enforce", "--root", str(package)]) == 0
        # REL-01: root single-file targets cannot hide included source.
        (package / "tools/probe.rs").write_text("fn main() {}\n")
        (package / "build_impl.rs").write_text(
            '#[allow(clippy::print_stdout)]\nfn main() { println!("hidden"); }\n'
        )
        for source in (
            'include!("build_impl.rs");\n',
            'r#include! { "build_impl.rs" }\n',
            '#[path = "hidden"] mod inline { include!("build_impl.rs"); }\n',
            '#[cfg_attr(all(), path = "hidden")] mod inline {}\n',
        ):
            (package / "build.rs").write_text(source)
            with redirect_stdout(StringIO()) as printed:
                result = main(["--enforce", "--root", str(package)])
            assert result == 1, (
                "root source loading accepted",
                source,
                printed.getvalue(),
            )
            assert "build.rs" in printed.getvalue(), printed.getvalue()
        # An empty source set is an error, never a clean pass.
        (package / "src/lib.rs").unlink()
        (package / "build.rs").unlink()
        (package / "tools/probe.rs").unlink()
        (package / "Cargo.toml").write_text('[package]\nname = "p"\n')
        with redirect_stdout(StringIO()):
            assert main(["--enforce", "--root", str(package)]) == 1
    print(f"allow_gate self-test: ok ({len(EVASIONS)} lexical evasions rejected)")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--enforce", action="store_true")
    parser.add_argument("--files", nargs="+")
    parser.add_argument("--root", type=Path, default=common.ROOT)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    try:
        files = (
            [Path(p) for p in args.files]
            if args.files
            else common.iter_rust_files(args.root)
        )
    except common.source_set.SourceSetError as error:
        print(f"allow_gate: {error}")
        return 1
    hits = scan(files)
    print(
        "\n".join(
            hits
            + [
                f"allow_gate: {len(hits)} allow attribute(s) or unscannable construct(s)"
            ]
        )
    )
    return int(args.enforce and bool(hits))


if __name__ == "__main__":
    sys.exit(main())
