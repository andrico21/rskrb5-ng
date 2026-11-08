#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
# How to run: python3 scripts/lint-gates/workflow_yaml.py --self-test
"""A strict reader for the block-style YAML of the CI workflows (stdlib only).

Flow collections, anchors, merges and tab indentation are rejected rather than
guessed at, so a gate never reads a structure YAML would parse differently.
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from typing import Final


@dataclass(frozen=True, slots=True)
class Line:
    """One structural line of a block-style YAML workflow."""

    number: int
    indent: int
    item: bool
    key: str | None
    value: str
    plain_key: bool = True


_KEY = re.compile(
    r"""(?P<key>"(?:[^"\\]|\\.)*"|'(?:[^']|'')*'|[^\s"'#:\[\]{},&*!|>%@`-][^:#]*?|-[^\s:#][^:#]*?)"""
    r"""\s*:(?:[ \t]+(?P<value>.*)|)$"""
)


def scalar(text: str, where: str) -> str:
    """Read one flow scalar: quoted, or plain, with an optional trailing comment."""
    text = text.strip()
    if text[:1] == '"':
        match = re.fullmatch(r'"([^"\\]*)"\s*(?:#.*)?', text)
        if match is None:
            raise RuntimeError(f"{where}: unsupported double-quoted scalar: {text}")
        return match[1]
    if text[:1] == "'":
        match = re.fullmatch(r"'((?:[^']|'')*)'\s*(?:#.*)?", text)
        if match is None:
            raise RuntimeError(f"{where}: unsupported single-quoted scalar: {text}")
        return match[1].replace("''", "'")
    value = re.split(r"\s+#", text, maxsplit=1)[0].strip()
    if not value or value[0] in "[]{},&*!|>%@`#" or ": " in value:
        raise RuntimeError(f"{where}: unsupported scalar: {text}")
    return value


def structure(text: str) -> list[Line]:
    """Split a block-style workflow into keyed and list-item lines.

    Comments, blank lines and the bodies of `|`/`>` block scalars are dropped,
    so a script line such as `closures:` inside `run: |` is never a key. Tabs in
    indentation, flow collections and anchors are rejected, not guessed at.
    """
    lines: list[Line] = []
    block: int | None = None
    scopes: list[tuple[int, set[str]]] = []
    for number, raw in enumerate(text.splitlines(), 1):
        body = raw.lstrip(" ")
        indent = len(raw) - len(body)
        if block is not None:
            if not body.strip() or indent > block:
                continue
            block = None
        if not body.strip() or body.startswith("#"):
            continue
        if body.startswith("\t") or raw.startswith("\t"):
            raise RuntimeError(f"ci.yml:{number}: tab in indentation")
        item = False
        if re.match(r"-(?:\s|$)", body):
            item = True
            rest = body[1:].lstrip(" ")
            indent += len(body) - len(rest)
            body = rest
        match = _KEY.match(body.rstrip())
        if match is None:
            if not item:
                raise RuntimeError(f"ci.yml:{number}: unsupported mapping form")
            scalar(body, f"ci.yml:{number}")
            lines.append(Line(number, indent, item, None, body.rstrip()))
            continue
        key = scalar(match["key"], f"ci.yml:{number} key")
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]*", key):
            raise RuntimeError(f"ci.yml:{number}: unsupported mapping key")
        while scopes and scopes[-1][0] > indent:
            scopes.pop()
        if not scopes or scopes[-1][0] < indent:
            scopes.append((indent, set()))
        if item:
            scopes[-1][1].clear()
        if key in scopes[-1][1]:
            raise RuntimeError(f"ci.yml:{number}: duplicate mapping key {key}")
        scopes[-1][1].add(key)
        value = (match["value"] or "").strip()
        if value.startswith(("&", "*", "<<", "!")) or key == "<<":
            raise RuntimeError(
                f"ci.yml:{number}: anchors, tags and merges are not supported"
            )
        if value.startswith("{"):
            raise RuntimeError(f"ci.yml:{number}: flow mappings are unsupported")
        if value.startswith("[") and not re.fullmatch(
            r"""\[\s*(?:(?:"[^"\\]*"|'[^']*'|[A-Za-z0-9_.-]+)\s*(?:,\s*(?:"[^"\\]*"|'[^']*'|[A-Za-z0-9_.-]+)\s*)*)?\]\s*(?:#.*)?""",
            value,
        ):
            raise RuntimeError(f"ci.yml:{number}: unsupported flow sequence")
        if re.match(r"[|>][-+0-9]*\s*(?:#.*)?$", value):
            block = indent
        lines.append(Line(number, indent, item, key, value, match["key"] == key))
    return lines


def children(lines: list[Line], parent: int) -> list[int]:
    """Indexes of the direct children of `lines[parent]`."""
    end = parent + 1
    while end < len(lines) and lines[end].indent > lines[parent].indent:
        end += 1
    if end == parent + 1:
        return []
    depth = lines[parent + 1].indent
    return [i for i in range(parent + 1, end) if lines[i].indent == depth]


def subtree(lines: list[Line], parent: int) -> list[Line]:
    end = parent + 1
    while end < len(lines) and lines[end].indent > lines[parent].indent:
        end += 1
    return lines[parent + 1 : end]


def only(lines: list[Line], indexes: list[int], key: str, where: str) -> int:
    found = [i for i in indexes if lines[i].key == key and not lines[i].item]
    if len(found) != 1:
        raise RuntimeError(
            f"{where} needs exactly one `{key}:` key, found {len(found)}"
        )
    return found[0]


def self_test() -> int:
    text = (
        "name: CI\njobs:\n  a:\n    steps:\n      - run: |\n          closures:\n"
        "      - name: x # c\n        run: 'it''s'\n"
    )
    lines = structure(text)
    jobs = only(
        lines, [i for i, line in enumerate(lines) if line.indent == 0], "jobs", "t"
    )
    job = children(lines, jobs)[0]
    assert lines[job].key == "a" and [line.key for line in subtree(lines, job)] == [
        "steps",
        "run",
        "name",
        "run",
    ]
    assert scalar(lines[-1].value, "t") == "it's"
    for bad in (
        "a: &x 1\n",
        "a:\n\tb: 1\n",
        "a: *x\n",
        "a: !!str value\n",
        "a: 1\na: 2\n",
        "steps:\n  - run: first\n    run: second\n",
        "<<: *x\n",
        '? "if"\n: false\n',
        '{"if": false}\n',
        '&alias "if": false\n',
        "*alias: false\n",
        '!!str "if": false\n',
        '"i\\u0066": false\n',
        '"if\\n": false\n',
        "'i''f': false\n",
    ):
        try:
            structure(bad)
        except RuntimeError:
            pass
        else:
            raise AssertionError(f"accepted {bad!r}")
    print(
        "workflow_yaml self-test: ok (block scalars skipped, quoting, anchors and tabs rejected)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(self_test() if "--self-test" in sys.argv else 2)
