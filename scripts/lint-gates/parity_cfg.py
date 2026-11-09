#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
# How to run: python3 scripts/lint-gates/parity_cfg.py --self-test
"""Remove evidence outside supported non-test builds, retaining source offsets.

Unknown cfg predicates are not evidence of a shipped API. Known feature/platform
predicates are evaluated together so contradictory attributes cannot certify it.
Other lint gates deliberately continue scanning disabled code.
"""

from __future__ import annotations

import itertools
import re
import sys
from functools import cache
from pathlib import Path

from common import blank_ranges, scan_items
from feature_closures import Closure, load
from rust_lex import (
    iter_attributes,
    match_bracket,
    split_top_level,
    strip_comments_and_strings,
)


def predicate(expression: str, enabled: frozenset[str]) -> bool:
    expression = expression.strip()
    call = re.fullmatch(r"(all|any|not)\s*\((.*)\)", expression, re.S)
    if call:
        parts = [
            call[2][a:b].strip()
            for a, b in split_top_level(call[2])
            if call[2][a:b].strip()
        ]
        values = [predicate(part, enabled) for part in parts]
        match call[1]:
            case "all":
                return all(values)
            case "any":
                return any(values)
            case "not" if len(values) == 1:
                return not values[0]
            case _:
                raise RuntimeError(f"unsupported cfg: {expression}")
    if expression in {
        "true",
        "false",
        "test",
        "doctest",
        "unix",
        "windows",
        "debug_assertions",
    }:
        return expression == "true" or expression in enabled
    setting = re.fullmatch(
        r'(feature|target_family|target_pointer_width)\s*=\s*"([\w-]+)"', expression
    )
    if setting:
        key, value = setting.groups()
        if key == "feature":
            return f"feature={value}" in enabled
        if key == "target_family" and value in {"unix", "windows"}:
            return value in enabled
        if key == "target_pointer_width" and value in {"32", "64"}:
            return f"width={value}" in enabled
    raise RuntimeError(f"unsupported cfg: {expression}")


def admitted(attribute: str, enabled: frozenset[str]) -> bool:
    call = re.fullmatch(r"\s*(?:r#)?(cfg|cfg_attr)\s*\((.*)\)\s*", attribute, re.S)
    if not call:
        return True
    if call[1] == "cfg":
        return predicate(call[2], enabled)
    parts = [
        call[2][a:b].strip()
        for a, b in split_top_level(call[2])
        if call[2][a:b].strip()
    ]
    if len(parts) < 2:
        raise RuntimeError("cfg_attr needs a predicate and attribute")
    active = predicate(parts[0], enabled)
    nested = [admitted(part, enabled) for part in parts[1:]]
    return not active or all(nested)


@cache
def feature_universe() -> tuple[Closure, ...]:
    return tuple(load(Path(__file__).resolve().parents[2]))


def public_source(source: str) -> str:
    clean = strip_comments_and_strings(source)
    literals = strip_comments_and_strings(source, keep_literals=True)
    items = scan_items(source)
    attributes = list(iter_attributes(clean))
    ranges = [(start, end) for start, end, _, _ in attributes]
    grouped: dict[tuple[int, int], list[str]] = {}
    for start, end, inner, body in attributes:
        original = literals[end - 1 - len(body) : end - 1]
        if not re.match(r"\s*(?:r#)?cfg(?:_attr)?\b", original):
            continue
        if inner:
            candidates = [
                item for item in items if item.start < start and end < item.end
            ]
        else:
            candidates = [
                item for item in items if item.start <= start and end < item.end
            ]
        if candidates:
            item = min(candidates, key=lambda value: value.end - value.start)
            scope = (item.start, item.end)
        elif inner:
            scope = (0, len(source))
        else:
            invocation = re.match(r"\s*\w+(?:\s*::\s*\w+)*\s*!\s*[(\[{]", clean[end:])
            close = (
                match_bracket(clean, end + invocation.end() - 1) if invocation else None
            )
            if close is None:
                raise RuntimeError(
                    f"cfg attribute has no supported item owner: {source[start : start + 200]}"
                )
            ranges.append((start, close + 1))
            continue
        grouped.setdefault(scope, []).append(original)
    closures = feature_universe()
    features = frozenset().union(*(closure.features for closure in closures))
    for scope, conditions in grouped.items():
        conditions = [
            condition
            for parent, inherited in grouped.items()
            if parent[0] <= scope[0] and scope[1] <= parent[1]
            for condition in inherited
        ]
        names = sorted(
            set(re.findall(r'feature\s*=\s*"([\w-]+)"', " ".join(conditions)))
        )
        supported = set(names) <= features
        possible = False
        if supported:
            try:
                for closure in closures:
                    selected = frozenset(f"feature={name}" for name in closure.features)
                    for platform, width, debug in itertools.product(
                        ("unix", "windows"), ("32", "64"), (False, True)
                    ):
                        enabled = (
                            selected
                            | {platform, f"width={width}"}
                            | ({"debug_assertions"} if debug else set())
                        )
                        results = [
                            admitted(condition, enabled) for condition in conditions
                        ]
                        possible |= all(results)
            except RuntimeError:
                possible = False
        if not possible:
            ranges.append(scope)
    return blank_ranges(clean, ranges)


def self_test() -> int:
    for condition in (
        "any()",
        "test",
        "FALSE",
        "not(all())",
        "all(test, unix)",
        'all(feature = "serde", not(feature = "serde"))',
        'all(feature = "tower", not(feature = "http"))',
        'all(feature = "spnego", not(feature = "messages"))',
        'all(feature = "tokio", not(feature = "messages"))',
        'all(feature = "default", not(feature = "serde"))',
        'all(feature = "tower", not(any(feature = "http", feature = "messages")))',
    ):
        source = f"#[cfg({condition})]\npub struct Ghost;\npub struct Real;"
        clean = public_source(source)
        assert "Ghost" not in clean, condition
        assert "pub struct Real;" in clean, condition
    for condition in (
        "all()",
        "not(test)",
        "unix",
        'feature = "serde"',
        "any(test, windows)",
        'all(feature = "tower", feature = "http")',
        'all(not(feature = "default"), feature = "serde")',
    ):
        assert "pub struct Real;" in public_source(
            f"#[cfg({condition})]\npub struct Real;"
        ), condition
    for source in (
        "#[cfg(test)]\nimpl Real { pub fn ghost() {} }\npub struct Real;",
        "#[cfg_attr(all(), cfg(any()))]\npub struct Ghost;\npub struct Real;",
        "#[cfg(unix)]\n#[cfg(windows)]\npub struct Ghost;\npub struct Real;",
        "#[cfg(any())]\n#[derive(Debug)]\npub struct Ghost;\npub struct Real;",
        '#[cfg(feature = "tower")]\n#[cfg(not(feature = "http"))]\npub struct Ghost;\npub struct Real;',
        '#[cfg_attr(feature = "http", cfg(any()))]\n#[cfg(feature = "tower")]\npub struct Ghost;\npub struct Real;',
    ):
        clean = public_source(source)
        assert "Ghost" not in clean and "ghost" not in clean, source
        assert "pub struct Real;" in clean, source
    assert "Ghost" not in public_source("#![cfg(any())]\npub struct Ghost;")
    assert "Ghost" not in public_source("#[r#cfg(any())]\npub struct Ghost;")
    assert "ghost" not in public_source(
        "#[cfg(unix)]\nimpl Real {\n#[cfg(windows)]\npub fn ghost() {}\n}"
    )
    print(
        "parity_cfg self-test: ok (disabled, test-only, contradictory and unknown cfg)"
    )
    return 0


def main() -> int:
    if "--self-test" in sys.argv:
        return self_test()
    fields = sys.stdin.buffer.read().decode("utf-8").split("\0")[:-1]
    sys.stdout.buffer.write(
        "".join(
            (field if index % 2 == 0 else public_source(field)) + "\0"
            for index, field in enumerate(fields)
        ).encode("utf-8")
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
