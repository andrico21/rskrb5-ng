#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = ["markdown-it-py==3.0.0", "mdurl==0.1.2"]
# ///
# How to run: python3 scripts/lint-gates/package_markdown.py --self-test
"""Collect package destinations from CommonMark tokens, preserving source lines."""

from __future__ import annotations

import re
from html.parser import HTMLParser
from typing import Final

from markdown_it import MarkdownIt
from markdown_it.common.utils import unescapeAll
from markdown_it.helpers import parseLinkLabel, parseLinkTitle
from markdown_it.helpers.parse_link_destination import _Result, parseLinkDestination
from markdown_it.rules_inline import StateInline
from markdown_it.token import Token

ESCAPE_OR_ENTITY: Final = re.compile(
    r'\\[!"#$%&\'()*+,\-./:;<=>?@\[\]\\^_`{|}~]|&(?:#[xX][0-9a-fA-F]+|#[0-9]+|[A-Za-z][A-Za-z0-9]{1,31});'
)
PASSIVE: Final = frozenset(
    {
        "paragraph_open",
        "paragraph_close",
        "heading_open",
        "heading_close",
        "blockquote_open",
        "blockquote_close",
        "bullet_list_open",
        "bullet_list_close",
        "ordered_list_open",
        "ordered_list_close",
        "list_item_open",
        "list_item_close",
        "em_open",
        "em_close",
        "strong_open",
        "strong_close",
        "link_close",
        "text",
        "softbreak",
        "hardbreak",
        "hr",
        "code_inline",
        "code_block",
        "fence",
    }
)


class UnclassifiableDestination(ValueError):
    def __init__(self, shape: str) -> None:
        self.shape = shape
        super().__init__(f"unclassifiable destination: {shape}")


class DestinationHelpers:
    parseLinkLabel = staticmethod(parseLinkLabel)
    parseLinkTitle = staticmethod(parseLinkTitle)

    @staticmethod
    def parseLinkDestination(source: str, start: int, maximum: int) -> _Result:
        result = parseLinkDestination(source, start, maximum)
        if not result.ok:
            return result
        raw = source[start : result.pos]
        if raw.startswith("<"):
            raw = raw[1:-1]

        def decode(match: re.Match[str]) -> str:
            spelling = match[0]
            decoded = unescapeAll(spelling)
            if not spelling.startswith("&#"):
                return decoded
            hexadecimal = spelling[2:3].lower() == "x"
            digits = spelling[3:-1] if hexadecimal else spelling[2:-1]
            if len(digits) > (6 if hexadecimal else 7):
                if decoded != spelling:
                    raise UnclassifiableDestination(spelling)
                return spelling
            # Only repair parser-left numeric references at their original span.
            # Escaped ampersands are consumed separately, so decoding is once-only.
            if decoded != spelling:
                return decoded
            value = int(digits, 16 if hexadecimal else 10)
            return (
                chr(value)
                if 0 < value <= 0x10FFFF and not 0xD800 <= value <= 0xDFFF
                else "\ufffd"
            )

        result.str = ESCAPE_OR_ENTITY.sub(decode, raw)
        return result


def markdown_parser() -> MarkdownIt:
    parser = MarkdownIt(
        "commonmark", {"html": True, "store_labels": True, "inline_definitions": True}
    )
    parser.helpers = DestinationHelpers
    # Policy, not a renderer: forbidden schemes must reach target_problem.
    parser.validateLink = lambda url: True
    parser.normalizeLink = lambda url: url
    rules = parser.inline.ruler.getRules("")

    def located(state: StateInline, silent: bool) -> bool:
        start = state.pos
        before = len(state.tokens)
        for rule in rules:
            if rule(state, silent):
                for token in state.tokens[before:]:
                    token.meta.setdefault(
                        "source_line", state.src.count("\n", 0, start)
                    )
                return True
        return False

    parser.inline.ruler.enableOnly([])
    parser.inline.ruler.push("located", located)
    return parser


class LinkAttributes(HTMLParser):
    """Mutable accumulator for actual HTML attributes, never Markdown text."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.targets: list[tuple[int, str]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        for name, value in attrs:
            if name in {"href", "src"} and value is not None:
                self.targets.append((self.getpos()[0], value))


def collect(tokens: list[Token], base: int = 1) -> list[tuple[int, str]]:
    found = []
    for token in tokens:
        line = (
            token.map[0] + 1 if token.map else base + token.meta.get("source_line", 0)
        )
        match token.type:
            case "inline":
                if token.children is None:
                    raise UnclassifiableDestination("inline without children")
                found.extend(collect(token.children, line))
            case "definition":
                destination = token.meta.get("url")
                if not isinstance(destination, str):
                    raise UnclassifiableDestination("definition without URL")
                found.append((line, destination))
            case "link_open" | "image":
                destination = token.attrGet(
                    "href" if token.type == "link_open" else "src"
                )
                if destination is None:
                    raise UnclassifiableDestination(token.type)
                if "label" not in token.meta:
                    found.append((line, destination))
            case "html_inline" | "html_block":
                html = LinkAttributes()
                html.feed(token.content)
                if html.rawdata.strip():
                    raise UnclassifiableDestination("unfinished HTML token")
                html.close()
                found.extend(
                    (line + offset - 1, value) for offset, value in html.targets
                )
            case other:
                if (
                    other not in PASSIVE
                    or token.attrGet("href") is not None
                    or token.attrGet("src") is not None
                ):
                    raise UnclassifiableDestination(other)
    return found


def link_targets(text: str) -> list[tuple[int, str]]:
    return collect(markdown_parser().parse(text))


def self_test() -> int:
    assert link_targets("[x](missing&#128;.md) [y](missing&amp;#128;.md)") == [
        (1, "missing\x80.md"),
        (1, "missing&#128;.md"),
    ]
    for spelling, expected in (
        ("&period;", "."),
        ("&#46;", "."),
        ("&#x2e;", "."),
        ("&#x80;", "\x80"),
        ("&#0;", "\ufffd"),
        ("&#xD800;", "\ufffd"),
        ("&#1114112;", "\ufffd"),
        (r"\&#128;", "&#128;"),
        ("%26%23128%3B", "%26%23128%3B"),
    ):
        assert link_targets(f"[x](missing{spelling}.md)") == [
            (1, f"missing{expected}.md")
        ], spelling
    for spelling in ("&#00000046;", "&#x000002e;"):
        try:
            link_targets(f"[x](missing{spelling}.md)")
        except UnclassifiableDestination as error:
            assert error.shape == spelling
        else:
            raise AssertionError(f"overlong reference accepted: {spelling}")
    try:
        collect([Token("unknown", "", 0)])
    except UnclassifiableDestination:
        pass
    else:
        raise AssertionError("unknown token accepted")
    print("package_markdown self-test: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(self_test())
