#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
# ─── How to run ───
# python3 scripts/lint-gates/common.py --self-test (no installation needed)
"""Shared source helpers; parser API ported from rmcp-server-kit (MIT/Apache-2.0).

The item-scanner adapter imports todo 13's scanner explicitly.
Offsets here are Python character offsets, never compiler UTF-8 byte offsets.
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Final

import source_set

ROOT: Final = Path(__file__).resolve().parents[2]
CORE_REL: Final = Path("docs/rust-guidelines/RUST_GUIDELINES.md")
ROOTS: Final = ("src", "tests", "examples", "benches", "fuzz/fuzz_targets")


from rust_lex import (
    AttributeCall,
    attribute_calls,
    iter_attributes,
    line_of,
    match_bracket,
    opaque_constructs,
    split_top_level,
    strip_comments_and_strings,
)


def iter_rust_files(root: Path) -> list[Path]:
    """The fixed roots plus every source the checkout's Cargo manifests compile."""
    return source_set.rust_sources(root, ROOTS)


def read_source(path: Path) -> tuple[str, str]:
    text = path.read_bytes().decode("utf-8")
    return text, strip_comments_and_strings(text)


# A path that stays inside the including file's directory and names a `.rs`
# file: `iter_rust_files` then scans the target as a file of its own.
SCANNED_PATH: Final = re.compile(r"(?!/)(?:(?!\.\.(?:/|\Z))[\w.-]+/)*[\w.-]+\.rs")


def foreign_sources(original: str, stripped: str) -> list[tuple[int, str]]:
    """Report code pulled in from a file the gates do not scan.

    `include!` and `#[path = ..]` (also inside `cfg_attr`) must name, as one plain
    string literal, a relative `.rs` path without `..`; anything else (a `.txt`
    file, `concat!`/`env!`, a metavariable, a parent directory) is reported.
    `include_str!`/`include_bytes!` yield a literal, never code, and pass.
    """
    found = []
    for match in re.finditer(r"(?<![\w$])(?:r#)?include\s*!\s*[(\[{]", stripped):
        close = match_bracket(stripped, match.end() - 1)
        argument = original[match.end() : close if close is not None else len(original)]
        literal = re.fullmatch(r'\s*"([^"\\]*)"\s*,?\s*', argument)
        if literal is None or not SCANNED_PATH.fullmatch(literal[1]):
            found.append(
                (
                    match.start(),
                    f"include!({argument.strip()}) is not a scanned .rs file",
                )
            )
    for start, end, _, _ in iter_attributes(stripped):
        for match in re.finditer(r"[\[(,]\s*(?:r#)?path\s*=", stripped[start:end]):
            at = start + match.end()
            literal = re.match(r'\s*"([^"\\]*)"', original[at:end])
            if literal is None or not SCANNED_PATH.fullmatch(literal[1]):
                value = original[at:end].split(",", 1)[0].strip().rstrip(")]")
                found.append((start, f"#[path = {value}] is not a scanned .rs file"))
    return found


def unscannable(original: str, stripped: str) -> list[tuple[int, str]]:
    """Per-file opaque constructs; root expansion admission is owned by source_set."""
    return sorted(opaque_constructs(stripped) + foreign_sources(original, stripped))


def blank_ranges(text: str, ranges: list[tuple[int, int]]) -> str:
    out = list(text)
    for a, b in ranges:
        out[a:b] = [c if c in "\r\n" else " " for c in text[a:b]]
    return "".join(out)


@dataclass(frozen=True, slots=True)
class Item:
    start: int
    end: int
    keyword: int
    kind: str
    name: str
    identity: str


def scan_items(source: str) -> list[Item]:
    """Adapt todo 13 scanner byte ranges to the gate parser character offsets."""
    import scanner

    data = source.encode()
    result = []
    for item in scanner.scan_items(data):
        start = len(data[: item.start].decode())
        end = len(data[: item.end].decode())
        clean = strip_comments_and_strings(source[start:end])
        clean = blank_ranges(clean, [(a, b) for a, b, _, _ in iter_attributes(clean)])
        match = re.search(r"\b" + re.escape(item.kind) + r"\b", clean)
        if match is None:
            continue
        name = item.identity.rsplit("::fn ", 1)[-1].removeprefix("fn ")
        result.append(
            Item(start, end, start + match.start(), item.kind, name, item.identity)
        )
    return result


def owner(items: list[Item], offset: int) -> Item | None:
    return min(
        (item for item in items if item.start <= offset < item.end),
        key=lambda item: item.end - item.start,
        default=None,
    )


def cfg_test_line_ranges(stripped: str) -> list[tuple[int, int]]:
    ranges = []
    items = scan_items(stripped)
    for a, b, _, body in iter_attributes(stripped):
        predicate = body.strip()
        if predicate == "cfg(test)" or re.match(r"cfg\(all\(\s*test\s*[,)]", predicate):
            item = owner(items, b)
            if item is not None:
                ranges.append((line_of(stripped, a), line_of(stripped, item.end)))
    return ranges


def in_ranges(line: int, ranges: list[tuple[int, int]]) -> bool:
    return any(a <= line <= b for a, b in ranges)


def self_test() -> int:
    source = "// #[allow(fake)]\nconst S: &str = r#\"{ /* }\"#;\n#[cfg_attr(test, allow(dead_code), derive(Debug))]\nfn f<'a>() { let c = '{'; }\n"
    calls = attribute_calls(source)
    assert len(calls) == 1 and calls[0].lints == ("dead_code",)
    assert calls[0].predicate == "test"
    assert len(strip_comments_and_strings(source)) == len(source)
    assert (
        attribute_calls(
            "#[cfg_attr(test, cfg_attr(unix, allow(x)), allow(y), derive(Debug))]"
        )[0].predicate
        == "all(test, unix)"
    )
    # Tokens may be spaced: the reason is still read from the right offset.
    spaced = attribute_calls('# ! [ expect ( dead_code , reason = "why" ) ]')
    assert len(spaced) == 1 and spaced[0].inner and spaced[0].reason == "why"
    spaced = attribute_calls("#\n[cfg_attr(test, r#allow(x))]")
    assert [(c.form, c.lints, c.inner) for c in spaced] == [("allow", ("x",), False)]
    hidden = attribute_calls('#[allow(a, clippy :: r#b, c::d(), reason = "r")]')
    assert hidden[0].lints == ("a", "clippy::b", "<unparsed: c::d()>"), hidden
    for opaque in (
        "#[$m]",
        "# $t",
        "#[cfg_attr(test, $($t)*)]",
        "m!(expect(x));",
        "#[[x]]",
    ):
        assert unscannable(opaque, strip_comments_and_strings(opaque)), opaque
    for plain in (
        '#[path = "a/b.rs"] mod b;',
        'include!("x.rs");',
        "a.expect(1); A::expect(b);",
    ):
        assert not unscannable(plain, strip_comments_and_strings(plain)), plain
    print(
        "common self-test: ok (cfg_attr siblings, lexemes, spacing, unscannable forms)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(self_test() if "--self-test" in sys.argv else 2)
