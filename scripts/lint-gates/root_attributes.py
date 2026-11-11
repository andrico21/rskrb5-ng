#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
# How to run: python3 scripts/lint-gates/root_attributes.py --self-test
"""Attribute expansion admission for single-file root Cargo targets."""

from __future__ import annotations

import re
import sys
from typing import Final

from rust_lex import META_PATH, iter_attributes, match_bracket, split_top_level

# Compiler-owned non-generating attributes plus an explicitly understood tool.
ROOT_ATTRIBUTES: Final = frozenset(
    {
        "cfg",
        "allow",
        "expect",
        "warn",
        "deny",
        "forbid",
        "doc",
        "inline",
        "cold",
        "must_use",
        "deprecated",
        "repr",
        "non_exhaustive",
        "track_caller",
        "test",
        "ignore",
        "should_panic",
        "no_std",
        "no_main",
        "recursion_limit",
        "type_length_limit",
        "rustfmt::skip",
    }
)
BUILTIN_DERIVES: Final = frozenset(
    {
        "Debug",
        "Clone",
        "Copy",
        "Default",
        "Eq",
        "PartialEq",
        "Ord",
        "PartialOrd",
        "Hash",
    }
)


def opaque_root_attributes(stripped: str) -> list[tuple[int, str]]:
    """Reject unknown attributes/derives, recursively including inactive cfg_attr."""
    found: list[tuple[int, str]] = []
    imported = bool(re.search(r"\buse\b|\bmacro_use\b", stripped))
    for start, _, _, body in iter_attributes(stripped):
        pending = [body]
        while pending:
            part = pending.pop()
            head = re.match(r"\s*(" + META_PATH + r")\s*(?:([(\[{])|=|$)", part)
            if head is None:
                found.append((start, "opaque root attribute"))
                continue
            name = re.sub(r"\s+|r#", "", head[1])
            if name in {"cfg_attr", "derive"}:
                opening = head.end() - 1
                closing = match_bracket(part, opening) if head[2] == "(" else None
                if closing is None:
                    found.append((start, "opaque root attribute arguments"))
                    continue
                args = part[opening + 1 : closing]
                parts = [args[a:b].strip() for a, b in split_top_level(args)]
                if name == "cfg_attr":
                    pending.extend(parts[1:])
                elif imported or any(
                    re.sub(r"\s+|r#", "", value) not in BUILTIN_DERIVES
                    for value in parts
                    if value
                ):
                    found.append((start, "opaque root derive"))
            elif name not in ROOT_ATTRIBUTES:
                found.append((start, f"opaque root attribute {name}"))
    return found


if __name__ == "__main__":
    import source_set

    sys.exit(source_set.self_test() if "--self-test" in sys.argv else 2)
