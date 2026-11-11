#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = ["markdown-it-py==3.0.0", "mdurl==0.1.2"]
# ///
# How to run: python3 scripts/lint-gates/package_anchors.py --self-test
"""Classify package heading anchors from CommonMark tokens."""

from __future__ import annotations

import re
import unicodedata
from typing import Final

from markdown_it.token import Token
from package_markdown import markdown_parser

ANCHOR: Final = re.compile(r"""<a\s[^>]*\b(?:id|name)\s*=\s*["']([^"']+)["']""")


class UnclassifiableAnchor(ValueError):
    def __init__(self, shape: str) -> None:
        self.shape = shape
        super().__init__(f"unclassifiable anchor: {shape}")


def heading_text(tokens: list[Token]) -> str:
    parts = []
    for token in tokens:
        match token.type:
            case "text" | "code_inline":
                parts.append(token.content)
            case (
                "em_open"
                | "em_close"
                | "strong_open"
                | "strong_close"
                | "link_open"
                | "link_close"
            ):
                pass
            case shape:
                raise UnclassifiableAnchor(f"heading token {shape}")
    return "".join(parts)


def anchors(text: str) -> frozenset[str]:
    """Number duplicate rendered heading slugs; refuse unproved renderer shapes."""
    seen: dict[str, int] = {}
    found = set(ANCHOR.findall(text))
    tokens = markdown_parser().parse(text)
    for index, token in enumerate(tokens):
        if token.type != "heading_open":
            continue
        if index + 2 >= len(tokens):
            raise UnclassifiableAnchor("unfinished heading")
        inline, close = tokens[index + 1 : index + 3]
        if (
            inline.type != "inline"
            or inline.children is None
            or close.type != "heading_close"
        ):
            raise UnclassifiableAnchor("heading without inline children and close")
        title = heading_text(inline.children)
        if any(
            (ord(char) > 127 and unicodedata.category(char)[0] not in {"L", "N", "M"})
            or (char.isspace() and char != " ")
            for char in title
        ):
            raise UnclassifiableAnchor("heading Unicode symbol or whitespace")
        slug = "".join(
            char
            for char in title.lower()
            if char.isalnum()
            or unicodedata.category(char).startswith("M")
            or char in "-_ "
        ).replace(" ", "-")
        count = seen.get(slug, 0)
        candidate = slug if count == 0 else f"{slug}-{count}"
        if candidate in found:
            raise UnclassifiableAnchor("heading slug collides with another anchor")
        seen[slug] = count + 1
        found.add(candidate)
    return frozenset(found)


def self_test() -> int:
    assert anchors("## A &amp; B\n\nTitle\n=====\n") == {"a--b", "title"}
    assert anchors("## A\n\n## A\n\n## A\n") == {"a", "a-1", "a-2"}
    for heading in (
        "## A ![alt](x) B",
        "## A <span>B</span>",
        "A\nB\n===",
        "## A 😀",
        "## A\n\n## A\n\n## A-1",
    ):
        try:
            anchors(heading)
        except UnclassifiableAnchor:
            pass
        else:
            raise AssertionError(f"unsupported heading accepted: {heading}")
    print("package_anchors self-test: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(self_test())
