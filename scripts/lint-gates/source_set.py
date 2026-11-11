#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
# How to run: python3 scripts/lint-gates/source_set.py --self-test
"""Every Rust source file Cargo can compile in a checkout, derived from its manifests.

Each `Cargo.toml` of the checkout (outside `target/`, hidden and `vendor/`
directories) contributes its auto-discovery directories (`src`, `tests`,
`examples`, `benches`), its build script and every explicit target `path`. A
target outside such a directory adds its own directory; one that sits directly
in the package directory (a root `build.rs`) is scanned as a file and must not
load further source files through `mod`, `include!` or `#[path]`. A path outside
the checkout, source loading in such a file, or an empty result is an error:
the gates fail closed.
"""

from __future__ import annotations

import os
import re
import sys
import tomllib
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Final

from rust_lex import iter_attributes, match_bracket, strip_comments_and_strings

AUTO_DIRS: Final = ("src", "tests", "examples", "benches")
TARGET_TABLES: Final = ("bin", "example", "test", "bench")
SKIPPED_DIRS: Final = frozenset({"target", "vendor", "node_modules"})
OUT_OF_LINE_MOD: Final = re.compile(r"(?<![\w$])mod\s+(?:\$\s*)?(?:r#)?\w+\s*;")
INCLUDE: Final = re.compile(r"(?<![\w$])(?:r#)?include\s*!\s*[(\[{]")
PATH_ATTRIBUTE: Final = re.compile(r"[\[(,]\s*(?:r#)?path\s*=")
MACRO_CALL: Final = re.compile(
    r"(?<![\w$])((?:::\s*)?(?:r#)?\w+(?:\s*::\s*(?:r#)?\w+)*)\s*!\s*[(\[{]"
)
# These standard macros produce expressions/statements or literal data, never
# source-loading items. Qualified calls are opaque (a foreign macro may shadow
# any of these names). Local definitions also take precedence over this set.
ORDINARY_MACROS: Final = frozenset(
    {
        "assert",
        "assert_eq",
        "assert_ne",
        "debug_assert",
        "debug_assert_eq",
        "debug_assert_ne",
        "cfg",
        "column",
        "compile_error",
        "concat",
        "dbg",
        "env",
        "eprint",
        "eprintln",
        "file",
        "format",
        "format_args",
        "include_bytes",
        "include_str",
        "line",
        "matches",
        "module_path",
        "option_env",
        "panic",
        "print",
        "println",
        "stringify",
        "todo",
        "unimplemented",
        "unreachable",
        "vec",
        "write",
        "writeln",
    }
)


def opaque_root_macros(stripped: str) -> bool:
    """Admit only inspectable local expansions and standard non-item macros.

    A local transcriber may splice a module *name* after literal `mod` only
    when followed by an inline body. Other metavariables are opaque: they can
    supply item keywords, complete items, or calls to other source generators.
    All transcribers and nested calls are checked, even in unused rules.
    """
    # Imports share the macro namespace. Without name resolution, an imported
    # alias/glob or macro_use can shadow any supposedly standard macro name.
    imported = bool(re.search(r"\buse\b|\bmacro_use\b", stripped))
    local = set()
    for definition in re.finditer(
        r"\bmacro_rules\s*!\s*(?:r#)?(\w+)\s*[(\[{]", stripped
    ):
        local.add(definition[1])
        close = match_bracket(stripped, definition.end() - 1)
        if close is None:
            return True
        body = stripped[definition.end() : close]
        for rule in re.finditer(r"=>\s*[(\[{]", body):
            end = match_bracket(body, rule.end() - 1)
            if end is None:
                return True
            expansion = body[rule.end() : end]
            visible = re.sub(r"\bmod\s+\$\s*\w+\s*(?=\{)", "mod inline ", expansion)
            if "$" in visible:
                return True
    for call in MACRO_CALL.finditer(stripped):
        name = re.sub(r"\s+|r#", "", call[1])
        if name not in local and (imported or name not in ORDINARY_MACROS):
            return True
    return False


class SourceSetError(ValueError):
    """The checkout's Rust sources cannot all be scanned."""


def manifests(root: Path) -> list[Path]:
    found = []
    for directory, subdirectories, files in os.walk(root):
        subdirectories[:] = sorted(
            name
            for name in subdirectories
            if name not in SKIPPED_DIRS and not name.startswith(".")
        )
        if "Cargo.toml" in files:
            found.append(Path(directory) / "Cargo.toml")
    return found


def target_paths(manifest: dict) -> list[str]:
    package = manifest.get("package", {})
    paths = [manifest.get("lib", {}).get("path")]
    paths += [
        target.get("path")
        for table in TARGET_TABLES
        for target in manifest.get(table, [])
    ]
    build = package.get("build", True)
    paths.append(build if isinstance(build, str) else "build.rs" if build else None)
    return [path for path in paths if isinstance(path, str)]


def package_sources(root: Path, manifest_path: Path) -> tuple[set[Path], set[Path]]:
    """(directories scanned recursively, single files) of one package."""
    package = manifest_path.parent
    directories = {package / name for name in AUTO_DIRS}
    files: set[Path] = set()
    manifest = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
    for relative in target_paths(manifest):
        path = (package / relative).resolve()
        if not path.is_relative_to(root.resolve()):
            raise SourceSetError(
                f"{manifest_path}: target {relative} is outside the checkout"
            )
        if not path.exists():
            continue
        if path.parent == package.resolve():
            files.add(path)
        elif not any(path.is_relative_to(d.resolve()) for d in directories):
            directories.add(path.parent)
    return directories, files


def rust_sources(given: Path, baseline: tuple[str, ...] = ()) -> list[Path]:
    """Sorted Rust sources of every package under `given`, plus the `baseline`
    directories; raises when a source cannot be scanned or none exists."""
    root = given.resolve()
    directories = {root / name for name in baseline}
    files: set[Path] = set()
    for manifest_path in manifests(root):
        package_directories, package_files = package_sources(root, manifest_path)
        directories |= {d.resolve() for d in package_directories}
        files |= package_files
    for path in files:
        stripped = strip_comments_and_strings(path.read_text(encoding="utf-8"))
        if OUT_OF_LINE_MOD.search(stripped):
            raise SourceSetError(
                f"{path}: an out-of-line `mod` outside a scanned directory"
            )
        if INCLUDE.search(stripped) or any(
            PATH_ATTRIBUTE.search(stripped[start:end])
            for start, end, _, _ in iter_attributes(stripped)
        ):
            raise SourceSetError(
                f"{path}: source loading (`include!` or `#[path]`) outside a scanned directory"
            )
        if opaque_root_macros(stripped):
            raise SourceSetError(
                f"{path}: opaque macro expansion outside a scanned directory"
            )
    found = files | {
        path
        for directory in directories
        if directory.is_dir()
        for path in directory.rglob("*.rs")
    }
    if not found:
        raise SourceSetError(f"no Rust source found under {root}")
    return sorted(given / path.relative_to(root) for path in found)


def self_test() -> int:
    with TemporaryDirectory() as directory:
        root = Path(directory).resolve()
        (root / "src").mkdir()
        (root / "tools/nested").mkdir(parents=True)
        (root / "target/package").mkdir(parents=True)
        (root / "Cargo.toml").write_text(
            '[package]\nname = "p"\n[[bin]]\nname = "probe"\npath = "tools/probe.rs"\n'
        )
        for name in ("src/lib.rs", "build.rs", "tools/probe.rs", "tools/nested/m.rs"):
            (root / name).write_text("fn f() {}\n")
        (root / "target/package/Cargo.toml").write_text('[[bin]]\npath = "../x.rs"\n')
        (root / "stray.rs").write_text("fn f() {}\n")
        relative = [p.relative_to(root).as_posix() for p in rust_sources(root)]
        assert relative == [
            "build.rs",
            "src/lib.rs",
            "tools/nested/m.rs",
            "tools/probe.rs",
        ], relative
        (root / "Cargo.toml").write_text('[package]\nname = "p"\nbuild = false\n')
        assert "build.rs" not in [p.name for p in rust_sources(root)]
        for manifest, why in (
            (
                '[package]\nname = "p"\n[[bin]]\nname = "x"\npath = "../x.rs"\n',
                "outside",
            ),
            ('[package]\nname = "p"\nbuild = "gen.rs"\n', "out-of-line"),
        ):
            (root / "gen.rs").write_text("mod generated;\nfn main() {}\n")
            (root / "Cargo.toml").write_text(manifest)
            try:
                rust_sources(root)
            except SourceSetError as error:
                assert why in str(error), error
            else:
                raise AssertionError(f"accepted: {manifest!r}")
    with TemporaryDirectory() as directory:
        (Path(directory) / "Cargo.toml").write_text('[package]\nname = "p"\n')
        try:
            rust_sources(Path(directory))
        except SourceSetError as error:
            assert "no Rust source" in str(error)
        else:
            raise AssertionError("an empty source set was accepted")
    print(
        "source_set self-test: ok (build script, custom target dir, outside path, out-of-line mod, empty set)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(self_test() if "--self-test" in sys.argv else 2)
