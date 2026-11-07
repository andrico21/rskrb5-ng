#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
# How to run: python3 scripts/lint-gates/fuzz_coverage.py --self-test
"""Check the attacker-facing parser inventory of docs/review/fuzz.md.

Two checks, both reading the inventory table of `docs/review/fuzz.md`
(columns: function | source file | fuzz target | reason):

* `--inventory` (`--enforce` in CI): the table exists and is not empty; every
  function the step-4 search finds
  (`fn (parse|decode|load_bytes|from_bytes|read)\\w*` under `src/`), plus
  `find_pac_in_authorization_data`, is a row, keyed by its fully qualified
  name and its source file; every row's function is still defined in that
  file; every row names exactly one of a target or a reason; and every named
  target is a `[[bin]]` of `fuzz/Cargo.toml` (what `cargo fuzz list` prints).
* `--coverage DIR`: every row that names a target is proved by that target's
  own coverage. `DIR/<target>.json` is the `llvm-cov export` of the target's
  coverage binary with its `coverage.profdata` (write them with `--export
  DIR`). A row matches a coverage record only when the demangled symbol,
  normalized (crate disambiguators, generic arguments and the inherent-impl
  `<Type>::` brackets removed), equals the row's qualified name, the record's
  defining file is the row's source file, and its execution count is above
  zero. Another type's method of the same name never matches. `--record
  FILE` saves the matched symbol, file and count of every mapping;
  `--source-root` names the checkout the binaries were built from when it
  differs from `--root`.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Final, Iterable

import common
from rust_lex import match_bracket, strip_comments_and_strings

DOC: Final = Path("docs/review/fuzz.md")
NIGHTLY: Final = "+nightly-2026-10-03"
SEARCH: Final = re.compile(r"\bfn ((?:parse|decode|load_bytes|from_bytes|read)\w*)")
ALWAYS: Final = (("rskrb5_ng::pac::find_pac_in_authorization_data", "src/pac.rs"),)
NO_TARGET: Final = {"", "-", "—"}
EMPTY: Final = "the inventory table of docs/review/fuzz.md is missing or empty"


@dataclass(frozen=True)
class Row:
    function: str
    source: str
    target: str
    reason: str


def cell(text: str) -> str:
    return text.strip().strip("`").strip()


def parse_table(markdown: str) -> list[Row]:
    """Rows of the first table whose header starts with `Function | Source`."""
    rows: list[Row] = []
    in_table = False
    for line in markdown.splitlines():
        stripped = line.strip()
        if not stripped.startswith("|"):
            if in_table:
                break
            continue
        cells = [part.strip() for part in stripped.strip("|").split("|")]
        if not in_table:
            if [cell(part).lower() for part in cells[:2]] == ["function", "source"]:
                in_table = True
            continue
        if all(set(part) <= set("-: ") for part in cells):
            continue
        if len(cells) != 4:
            raise ValueError(f"inventory row needs 4 cells: {line!r}")
        rows.append(
            Row(cell(cells[0]), cell(cells[1]), cell(cells[2]), cells[3].strip())
        )
    return rows


def module_path(relative: str) -> list[str]:
    parts = Path(relative).with_suffix("").parts
    if parts[0] != "src":
        raise ValueError(f"not a source file: {relative}")
    names = list(parts[1:])
    if names in (["lib"], ["main"]):
        return []
    if names[-1] == "mod":
        names.pop()
    return names


def match_angle(text: str, open_index: int) -> int | None:
    """Index of the `>` closing the `<` at `open_index` (`->` is not a bracket)."""
    depth = 0
    for index in range(open_index, len(text)):
        char = text[index]
        if char == "<":
            depth += 1
        elif char == ">" and text[index - 1 : index] != "-":
            depth -= 1
            if depth == 0:
                return index
    return None


def strip_generics(text: str) -> str:
    """Drop `<...>` argument lists that follow a name; keep a leading `<`."""
    out: list[str] = []
    depth = 0
    index = 0
    while index < len(text):
        char = text[index]
        if depth:
            if char == "<":
                depth += 1
            elif char == ">":
                depth -= 1
            index += 1
            continue
        previous = out[-1] if out else ""
        if char == "<" and previous and (previous.isalnum() or previous in "_:'"):
            depth = 1
            if text[index - 2 : index] == "::":
                del out[-2:]
            index += 1
            continue
        out.append(char)
        index += 1
    return "".join(out).strip()


def scopes(stripped: str) -> list[tuple[int, int, str, str]]:
    """Every `impl` and `mod` block: (open, close, kind, name)."""
    found = []
    for match in re.finditer(r"(?<![\w$])(impl|mod)\b", stripped):
        kind = match[1]
        brace = stripped.find("{", match.end())
        semicolon = stripped.find(";", match.end())
        if brace < 0 or (0 <= semicolon < brace):
            continue
        close = match_bracket(stripped, brace)
        if close is None:
            continue
        header = stripped[match.end() : brace]
        if kind == "mod":
            name = header.strip()
        else:
            header = header.split(" where ")[0].strip()
            if header.startswith("<"):
                end = match_angle(header, 0)
                header = header[(end or 0) + 1 :].strip()
            if re.search(r"\sfor\s", header):
                kind = "trait-impl"
            name = strip_generics(header)
        found.append((brace, close, kind, name))
    return found


def qualified_functions(relative: str, original: str) -> list[tuple[str, int]]:
    """Fully qualified names of the step-4 search hits in one file.

    A hit in a trait impl is `<path::Type as Trait>::name`, with only the
    trait's last path segment, as `defined_functions` names it.
    """
    stripped = strip_comments_and_strings(original)
    blocks = scopes(stripped)
    hits = []
    for match in SEARCH.finditer(stripped):
        position = match.start()
        enclosing = sorted(
            (block for block in blocks if block[0] < position < block[1]),
            key=lambda b: b[0],
        )
        path = ["rskrb5_ng", *module_path(relative)]
        trait = None
        for _, _, kind, name in enclosing:
            if kind == "trait-impl":
                trait_path, _, self_type = name.partition(" for ")
                trait = trait_path.strip().rsplit("::", 1)[-1]
                path.append(self_type.strip())
            else:
                path.append(name)
        qualified = "::".join(path)
        name = (
            f"<{qualified} as {trait}>::{match[1]}"
            if trait
            else f"{qualified}::{match[1]}"
        )
        hits.append((name, stripped.count("\n", 0, position) + 1))
    return hits


def short_trait(function: str) -> str:
    """A row name with its trait reduced to the last path segment."""
    return re.sub(r" as (?:\w+::)*(\w+)>", r" as \1>", function)


def defined_functions(relative: str, original: str) -> set[str]:
    """Every `fn` of one file, named as inventory rows name it.

    A trait-impl method is `<path::Type as Trait>::name`, with only the trait's
    last path segment, so a row's fully qualified trait matches its source.
    """
    stripped = strip_comments_and_strings(original)
    blocks = scopes(stripped)
    names = set()
    for match in re.finditer(r"\bfn\s+(?:r#)?(\w+)", stripped):
        path = ["rskrb5_ng", *module_path(relative)]
        trait = None
        for _, _, kind, name in sorted(
            (block for block in blocks if block[0] < match.start() < block[1]),
            key=lambda block: block[0],
        ):
            if kind == "trait-impl":
                trait_path, _, self_type = name.partition(" for ")
                trait = trait_path.strip().rsplit("::", 1)[-1]
                path.append(self_type.strip())
            else:
                path.append(name)
        qualified = "::".join(path)
        names.add(
            f"<{qualified} as {trait}>::{match[1]}"
            if trait
            else f"{qualified}::{match[1]}"
        )
    return names


def check_live(rows: list[Row], read: Callable[[str], str | None]) -> list[str]:
    """Rows whose function is no longer defined in the row's source file."""
    defined: dict[str, set[str]] = {}
    errors = []
    for row in rows:
        if row.source not in defined:
            text = read(row.source)
            defined[row.source] = (
                set() if text is None else defined_functions(row.source, text)
            )
        if short_trait(row.function) not in defined[row.source]:
            errors.append(
                f"stale inventory row: {row.function} is not defined in {row.source}"
            )
        if row.target not in NO_TARGET:
            text = strip_comments_and_strings(read(row.source) or "")
            test_functions = set(
                re.findall(
                    r"#\s*\[\s*cfg\s*\(\s*test\s*\)\s*\]\s*(?:#\[[^\]]*\]\s*)*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?(?:const\s+)?fn\s+(\w+)",
                    text,
                )
            )
            if row.function.rsplit("::", 1)[-1] in test_functions:
                errors.append(f"test-only function has fuzz target: {row.function}")
    return errors


def inventory_keys(root: Path) -> dict[tuple[str, str], int]:
    keys: dict[tuple[str, str], int] = {}
    for path in sorted((root / "src").rglob("*.rs")):
        relative = path.relative_to(root).as_posix()
        for name, line in qualified_functions(
            relative, path.read_text(encoding="utf-8")
        ):
            keys.setdefault((name, relative), line)
    for name, relative in ALWAYS:
        keys.setdefault((name, relative), 0)
    return keys


def check_rows(
    rows: list[Row], keys: Iterable[tuple[str, str]], targets: set[str]
) -> list[str]:
    if not rows:
        return [EMPTY]
    errors = []
    present = {(short_trait(row.function), row.source) for row in rows}
    for name, relative in sorted(set(keys) - present):
        errors.append(f"missing inventory row: {name} ({relative})")
    seen = set()
    for row in rows:
        key = (row.function, row.source)
        if key in seen:
            errors.append(f"duplicate inventory row: {row.function} ({row.source})")
        seen.add(key)
        has_target = row.target not in NO_TARGET
        has_reason = row.reason not in NO_TARGET
        if has_target == has_reason:
            errors.append(
                f"row needs exactly one of a target or a reason: {row.function}"
            )
        if has_target and row.target not in targets:
            errors.append(
                f"target {row.target!r} of {row.function} is not in `cargo fuzz list`"
            )
    return errors


def normalize_symbol(demangled: str) -> str:
    name = re.sub(r"\[[0-9a-f]+\]", "", demangled)
    name = re.sub(r"::h[0-9a-f]{16}$", "", name)
    name = strip_generics(name)
    if name.startswith("<"):
        close = match_angle(name, 0)
        if (
            close is not None
            and " as " not in name[1:close]
            and name[close + 1 :].startswith("::")
        ):
            name = name[1:close] + name[close + 1 :]
    return name


def demangle(names: list[str]) -> list[str]:
    tool = shutil.which("c++filt") or shutil.which("llvm-cxxfilt")
    if tool is None:
        raise RuntimeError(
            "c++filt or llvm-cxxfilt is needed to demangle coverage symbols"
        )
    result = subprocess.run(
        [tool],
        input="\n".join(names) + "\n",
        capture_output=True,
        text=True,
        check=True,
    )
    lines = result.stdout.splitlines()
    if len(lines) != len(names):
        raise RuntimeError("the demangler changed the number of symbols")
    return lines


def coverage_index(
    export: dict, root: Path, demangled: list[str] | None = None
) -> dict:
    """Map normalized symbol -> list of (demangled symbol, relative file, count)."""
    functions = [
        function
        for data in export["data"]
        for function in data["functions"]
        if "rskrb5_ng" in function["name"]
    ]
    names = demangled or demangle([function["name"] for function in functions])
    index: dict[str, list[tuple[str, str, int]]] = {}
    prefix = root.resolve().as_posix().rstrip("/") + "/"
    for function, symbol in zip(functions, names):
        filename = function["filenames"][0] if function["filenames"] else ""
        relative = filename[len(prefix) :] if filename.startswith(prefix) else filename
        index.setdefault(normalize_symbol(symbol), []).append(
            (symbol, relative, int(function["count"]))
        )
    return index


def match_row(row: Row, index: dict) -> tuple[str, str, int] | None:
    for symbol, relative, count in index.get(row.function, []):
        if relative == row.source and count > 0:
            return symbol, relative, count
    return None


def check_coverage(
    rows: list[Row], indexes: dict[str, dict]
) -> tuple[list[str], list[str]]:
    if not rows:
        return [EMPTY], []
    errors, records = [], []
    for row in rows:
        if row.target in NO_TARGET:
            continue
        index = indexes.get(row.target)
        if index is None:
            errors.append(f"no coverage export for target {row.target}")
            continue
        matched = match_row(row, index)
        if matched is None:
            errors.append(f"{row.target} does not reach {row.function} ({row.source})")
            continue
        symbol, relative, count = matched
        records.append(f"{row.target}\t{row.function}\t{symbol}\t{relative}\t{count}")
    return errors, records


def manifest_targets(manifest: str) -> set[str]:
    """The `[[bin]]` names of the fuzz manifest: what `cargo fuzz list` prints."""
    return {
        target["name"]
        for target in tomllib.loads(manifest).get("bin", [])
        if isinstance(target.get("name"), str)
    }


def fuzz_targets(root: Path) -> set[str]:
    targets = manifest_targets((root / "fuzz/Cargo.toml").read_text(encoding="utf-8"))
    if not targets:
        raise RuntimeError("fuzz/Cargo.toml declares no [[bin]] fuzz target")
    return targets


def export_coverage(
    root: Path, rows: list[Row], out: Path, target_dir: Path | None
) -> int:
    sysroot = subprocess.run(
        ["rustc", NIGHTLY, "--print", "sysroot"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    host = re.search(
        r"(?m)^host: (\S+)",
        subprocess.run(
            ["rustc", NIGHTLY, "-vV"], capture_output=True, text=True, check=True
        ).stdout,
    )[1]
    llvm_cov = Path(sysroot) / "lib/rustlib" / host / "bin/llvm-cov"
    if target_dir is None:
        metadata = json.loads(
            subprocess.run(
                [
                    "cargo",
                    "metadata",
                    "--manifest-path",
                    "fuzz/Cargo.toml",
                    "--format-version",
                    "1",
                    "--no-deps",
                ],
                cwd=root,
                capture_output=True,
                text=True,
                check=True,
            ).stdout
        )
        target_dir = Path(metadata["target_directory"]) / host / "coverage"
    out.mkdir(parents=True, exist_ok=True)
    for target in sorted({row.target for row in rows if row.target not in NO_TARGET}):
        binary = target_dir / host / "release" / target
        profdata = root / "fuzz/coverage" / target / "coverage.profdata"
        command = [
            str(llvm_cov),
            "export",
            "-format=text",
            "-instr-profile",
            str(profdata),
            str(binary),
        ]
        print("$ " + " ".join(command) + f" > {out / (target + '.json')}", flush=True)
        with (out / f"{target}.json").open("w") as handle:
            code = subprocess.run(command, stdout=handle).returncode
        if code:
            return code
    return 0


def self_test() -> int:
    table = """
| Function | Source | Fuzz target | Reason |
| --- | --- | --- | --- |
| `rskrb5_ng::pac::Pac::parse` | `src/pac.rs` | `pac_parse` | |
| `rskrb5_ng::pac::CredentialData::parse` | `src/pac.rs` | `pac_parse` | |
| `rskrb5_ng::krb_error::decode_der` | `src/krb_error.rs` | `kdc_reply` | |
| `rskrb5_ng::config::tests::parse_x` | `src/config.rs` | - | unit test |
"""
    rows = parse_table(table)
    assert [row.function for row in rows][0] == "rskrb5_ng::pac::Pac::parse"
    # Normalization of v0 and legacy demangled symbols.
    assert (
        normalize_symbol("<rskrb5_ng[1261e1a1]::pac::Pac>::parse")
        == "rskrb5_ng::pac::Pac::parse"
    )
    assert (
        normalize_symbol(
            "rskrb5_ng[12]::krb_error::decode_der::<alloc[3]::vec::Vec<rasn_kerberos[4]::PaData>>"
        )
        == "rskrb5_ng::krb_error::decode_der"
    )
    assert (
        normalize_symbol(
            "<rskrb5_ng[12]::pac::reader::Reader>::read_array::<16: usize>"
        )
        == "rskrb5_ng::pac::reader::Reader::read_array"
    )
    assert (
        normalize_symbol("rskrb5_ng::pac::Pac::parse::h0123456789abcdef")
        == "rskrb5_ng::pac::Pac::parse"
    )
    trait_impl = "<rskrb5_ng[1]::pac::Sid as core[2]::fmt::Display>::fmt"
    assert (
        normalize_symbol(trait_impl)
        == "<rskrb5_ng::pac::Sid as core::fmt::Display>::fmt"
    )
    # Negative: the PAC header `parse` is covered, the NDR credential-data
    # `parse` is not, so only the header mapping is proved.
    export = {
        "data": [
            {
                "functions": [
                    {"name": "a", "count": 3, "filenames": ["/r/src/pac.rs"]},
                    {"name": "b", "count": 0, "filenames": ["/r/src/pac.rs"]},
                    {"name": "c", "count": 2, "filenames": ["/r/src/krb_error.rs"]},
                ]
            }
        ]
    }
    demangled = [
        "<rskrb5_ng[9]::pac::Pac>::parse",
        "<rskrb5_ng[9]::pac::CredentialData>::parse",
        "rskrb5_ng[9]::krb_error::decode_der::<rasn_kerberos[8]::KrbError>",
    ]
    for name in ("a", "b", "c"):
        export["data"][0]["functions"][("a", "b", "c").index(name)]["name"] = (
            "rskrb5_ng_" + name
        )
    index = coverage_index(export, Path("/r"), demangled)
    errors, records = check_coverage(rows, {"pac_parse": index, "kdc_reply": index})
    assert errors == [
        "pac_parse does not reach rskrb5_ng::pac::CredentialData::parse (src/pac.rs)"
    ], errors
    assert len(records) == 2 and records[0].startswith(
        "pac_parse\trskrb5_ng::pac::Pac::parse\t<rskrb5_ng[9]::pac::Pac>::parse\tsrc/pac.rs\t3"
    )
    # Negative: the right symbol in another file does not count.
    moved = [Row("rskrb5_ng::pac::Pac::parse", "src/pac/ndr.rs", "pac_parse", "")]
    assert check_coverage(moved, {"pac_parse": index})[0], (
        "a file mismatch must be rejected"
    )
    # Inventory: qualified names from impl and mod scopes.
    source = (
        "impl<'a> Reader<'a> {\n    pub fn read_u8(&mut self) {}\n}\n"
        "pub fn decode(bytes: &[u8]) {}\n"
        "mod tests {\n    fn parse_x() {}\n}\n"
        "// fn parse_in_comment() {}\n"
    )
    names = [name for name, _ in qualified_functions("src/pac/reader.rs", source)]
    assert names == [
        "rskrb5_ng::pac::reader::Reader::read_u8",
        "rskrb5_ng::pac::reader::decode",
        "rskrb5_ng::pac::reader::tests::parse_x",
    ], names
    # A search hit in a trait impl is a key named with the trait's last
    # segment; a row naming the full trait path satisfies it, no row is missing.
    impl_source = "impl Decode for Bytes {\n    fn decode_with_tag(d: &mut D) {}\n}\n"
    impl_keys = {
        (name, "src/kadmin/password.rs")
        for name, _ in qualified_functions("src/kadmin/password.rs", impl_source)
    }
    assert impl_keys == {
        (
            "<rskrb5_ng::kadmin::password::Bytes as Decode>::decode_with_tag",
            "src/kadmin/password.rs",
        )
    }, impl_keys
    impl_row = Row(
        "<rskrb5_ng::kadmin::password::Bytes as rasn::de::Decode>::decode_with_tag",
        "src/kadmin/password.rs",
        "krb_messages",
        "",
    )
    assert check_rows([impl_row], impl_keys, {"krb_messages"}) == []
    assert check_rows(rows, impl_keys, {"pac_parse", "kdc_reply"}) == [
        "missing inventory row: <rskrb5_ng::kadmin::password::Bytes as Decode>::decode_with_tag (src/kadmin/password.rs)"
    ]
    keys = {(row.function, row.source) for row in rows}
    assert check_rows(rows, keys, {"pac_parse", "kdc_reply"}) == []
    missing = check_rows(rows[1:], keys, {"pac_parse", "kdc_reply"})
    assert missing == [
        "missing inventory row: rskrb5_ng::pac::Pac::parse (src/pac.rs)"
    ], missing
    unknown = check_rows(rows, keys, {"pac_parse"})
    assert unknown == [
        "target 'kdc_reply' of rskrb5_ng::krb_error::decode_der is not in `cargo fuzz list`"
    ], unknown
    both = [Row("x", "src/x.rs", "pac_parse", "reason"), Row("y", "src/y.rs", "-", "")]
    assert len(check_rows(both, set(), {"pac_parse"})) == 2
    # A missing or empty inventory table is an error for both checks.
    for text in (
        "not a table",
        "| Function | Source | Fuzz target | Reason |\n| --- | --- | --- | --- |\n",
    ):
        assert check_rows(parse_table(text), set(), {"pac_parse"}) == [EMPTY], text
        assert check_coverage(parse_table(text), {})[0] == [EMPTY], text
    # Targets come from the fuzz manifest, so CI needs no cargo-fuzz.
    manifest = '[package]\nname = "f"\n[[bin]]\nname = "pac_parse"\npath = "fuzz_targets/pac_parse.rs"\n'
    assert manifest_targets(manifest) == {"pac_parse"}
    # A row whose function is no longer defined in its file is stale, for a
    # target row and a reason-only row alike; helpers outside the search
    # regex and trait-impl rows stay valid.
    config = (
        "impl LibDefaults {\n    fn validate_explicit_enctypes(&mut self) {}\n}\n"
        "fn brace_delta(line: &str) -> i32 { 0 }\n"
        "impl<'a> Iterator for Segments<'a> {\n    type Item = u8;\n    fn next(&mut self) -> Option<u8> { None }\n}\n"
    )
    live = [
        Row(
            "rskrb5_ng::config::LibDefaults::validate_explicit_enctypes",
            "src/config.rs",
            "krb5_conf",
            "",
        ),
        Row("rskrb5_ng::config::brace_delta", "src/config.rs", "krb5_conf", ""),
        Row(
            "<rskrb5_ng::config::Segments as core::iter::traits::iterator::Iterator>::next",
            "src/config.rs",
            "krb5_conf",
            "",
        ),
    ]
    stale = [
        Row(
            "rskrb5_ng::config::parse_explicit_enctypes",
            "src/config.rs",
            "krb5_conf",
            "",
        ),
        Row(
            "rskrb5_ng::config::Config::load_removed",
            "src/config.rs",
            "-",
            "reads a file",
        ),
        Row("rskrb5_ng::config::LibDefaults::next", "src/config.rs", "-", "wrong impl"),
    ]
    sources = {"src/config.rs": config}
    test_only = [
        Row("rskrb5_ng::config::test_parser", "src/config.rs", "krb5_conf", "")
    ]
    assert check_live(
        test_only, {"src/config.rs": "#[cfg(test)]\npub(crate) fn test_parser() {}"}.get
    )
    assert check_live(live, sources.get) == [], check_live(live, sources.get)
    assert check_live(stale, sources.get) == [
        f"stale inventory row: {row.function} is not defined in {row.source}"
        for row in stale
    ], check_live(stale, sources.get)
    assert check_live(
        [Row("rskrb5_ng::gone::f", "src/gone.rs", "-", "x")], sources.get
    ) == ["stale inventory row: rskrb5_ng::gone::f is not defined in src/gone.rs"]
    print(
        "fuzz_coverage self-test: ok (another type's parse, another file, a missing row, "
        "an empty table and stale rows are rejected; targets from the manifest)"
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--root", type=Path, default=common.ROOT)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--inventory", action="store_true")
    parser.add_argument(
        "--enforce", action="store_true", help="the CI gate: same as --inventory"
    )
    parser.add_argument("--coverage", type=Path, metavar="DIR")
    parser.add_argument("--export", type=Path, metavar="DIR")
    parser.add_argument("--coverage-target-dir", type=Path)
    parser.add_argument("--record", type=Path)
    parser.add_argument(
        "--source-root",
        type=Path,
        help="checkout the coverage binaries were built from (default: --root)",
    )
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    root = args.root
    rows = parse_table((root / DOC).read_text(encoding="utf-8"))
    if args.export:
        return export_coverage(root, rows, args.export, args.coverage_target_dir)
    errors: list[str] = []
    if args.inventory or args.enforce:
        keys = inventory_keys(root)
        errors += check_rows(rows, keys, fuzz_targets(root))
        errors += check_live(
            rows,
            lambda relative: (
                (root / relative).read_text(encoding="utf-8")
                if (root / relative).is_file()
                else None
            ),
        )
        print(f"inventory: {len(keys)} searched functions, {len(rows)} rows")
    if args.coverage:
        indexes = {}
        for target in sorted(
            {row.target for row in rows if row.target not in NO_TARGET}
        ):
            path = args.coverage / f"{target}.json"
            if path.exists():
                indexes[target] = coverage_index(
                    json.loads(path.read_text()), args.source_root or root
                )
        coverage_errors, records = check_coverage(rows, indexes)
        errors += coverage_errors
        print(f"coverage: {len(records)} mappings proved")
        if args.record:
            args.record.write_text(
                "target\tfunction\tsymbol\tfile\tcount\n" + "\n".join(records) + "\n"
            )
    for error in errors:
        print(f"error: {error}", file=sys.stderr)
    if not (args.inventory or args.enforce or args.coverage):
        parser.error(
            "choose --self-test, --inventory (--enforce), --coverage DIR or --export DIR"
        )
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
