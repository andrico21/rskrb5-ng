#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
# How to run: python3 scripts/lint-gates/scanner.py --self-test
# noqa: SIZE_OK - Only this scanner helper is authorized; lexer fixtures stay inline.
"""Byte-oriented Rust item locator; no compiler or third-party parser required.

Offsets include outer attributes/docs. Macro token trees are opaque: an expansion
at a statement maps to its enclosing function, never to invented macro items.
This is an item scanner, not a Rust grammar or a cfg evaluator.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final


class ScanError(ValueError):
    """An input cannot safely be assigned a Rust item or attribute."""


@dataclass(frozen=True, slots=True)
class Token:
    text: str
    start: int
    end: int


@dataclass(frozen=True, slots=True)
class Item:
    kind: str
    name: str
    start: int
    end: int
    line: int
    column: int
    body_start: int = 0

    @property
    def identity(self) -> str:
        return self.name


IDENT: Final = re.compile(rb"(?:r#)?[a-zA-Z_\x80-\xff][a-zA-Z_0-9\x80-\xff]*|[0-9]+")
LITERAL: Final = re.compile(
    rb"(?:b|c)?\"(?:\\.|[^\"\\])*\"|b?'(?:\\(?:u\{[0-9a-fA-F]+\}|x[0-9a-fA-F]{2}|.)|[^'\\\n])'",
    re.DOTALL,
)
RAW: Final = re.compile(rb'(?:br|cr|r)(#*)"')
KINDS: Final = frozenset(
    "use fn impl trait struct enum union const static type mod macro_rules extern".split()
)


def tokens(source: str | bytes) -> list[Token]:
    """Tokenize UTF-8 bytes, retaining doc comments and literal boundaries."""
    data = source.encode() if isinstance(source, str) else source
    result: list[Token] = []
    i = 0
    while i < len(data):
        start = i
        if data[i : i + 1].isspace():
            i += 1
            continue
        if data.startswith(b"//", i):
            end = data.find(b"\n", i)
            i = len(data) if end < 0 else end
            if data.startswith((b"///", b"//!"), start) and not data.startswith(
                b"////", start
            ):
                result.append(Token(data[start:i].decode(), start, i))
            continue
        if data.startswith(b"/*", i):
            i += 2
            depth = 1
            while depth and i < len(data):
                if data.startswith(b"/*", i):
                    depth += 1
                    i += 2
                elif data.startswith(b"*/", i):
                    depth -= 1
                    i += 2
                else:
                    i += 1
            if depth:
                raise ScanError(f"unclosed block comment at byte {start}")
            if data.startswith((b"/**", b"/*!"), start):
                result.append(Token(data[start:i].decode(), start, i))
            continue
        raw = RAW.match(data, i)
        if raw:
            close = b'"' + raw[1]
            end = data.find(close, raw.end())
            if end < 0:
                raise ScanError(f"unclosed raw string at byte {start}")
            i = end + len(close)
        else:
            literal = LITERAL.match(data, i)
            ident = IDENT.match(data, i)
            lifetime = IDENT.match(data, i + 1) if data[i : i + 1] == b"'" else None
            i = (
                literal.end()
                if literal
                else ident.end()
                if ident
                else lifetime.end()
                if lifetime
                else i + 1
            )
        result.append(Token(data[start:i].decode(), start, i))
    return result


def pairs(ts: list[Token]) -> dict[int, int]:
    result: dict[int, int] = {}
    stack: list[int] = []
    for i, token in enumerate(ts):
        if token.text in ("(", "[", "{"):
            stack.append(i)
        elif token.text in (")", "]", "}"):
            if (
                not stack
                or ts[stack[-1]].text != {")": "(", "]": "[", "}": "{"}[token.text]
            ):
                raise ScanError(f"unbalanced delimiter at byte {token.start}")
            first = stack.pop()
            result[first] = i
    if stack:
        raise ScanError(f"unclosed delimiter at byte {ts[stack[-1]].start}")
    return result


def is_union_item(ts: list[Token], at: int, hi: int) -> bool:
    """`union` is a contextual keyword: an item only before a name and `{`, `<` or `where`."""
    return (
        at + 2 < hi
        and IDENT.fullmatch(ts[at + 1].text.encode()) is not None
        and not ts[at + 1].text[0].isdigit()
        and ts[at + 2].text in ("{", "<", "where")
    )


def scan_items(source: str | bytes) -> list[Item]:
    data = source.encode() if isinstance(source, str) else source
    ts = tokens(data)
    ends = pairs(ts)
    result: list[Item] = []

    def walk(lo: int, hi: int, parent: str) -> None:
        i = lo
        while i < hi:
            first = i
            while i < hi and (
                ts[i].text.startswith(("///", "/**")) or ts[i].text == "#"
            ):
                if ts[i].text == "#" and i + 1 < hi and ts[i + 1].text == "[":
                    i = ends[i + 1] + 1
                elif ts[i].text.startswith(("///", "/**")):
                    i += 1
                else:
                    break
            keyword = i
            while keyword < hi and ts[keyword].text in (
                "pub",
                "async",
                "unsafe",
                "default",
                "auto",
                "const",
                "extern",
            ):
                word = ts[keyword].text
                if word in ("const", "extern") and not any(
                    t.text == "fn" for t in ts[keyword + 1 : keyword + 4]
                ):
                    break
                keyword += 1
                if keyword < hi and ts[keyword].text == "(":
                    keyword = ends[keyword] + 1
                if (
                    word == "extern"
                    and keyword < hi
                    and ts[keyword].text.startswith('"')
                ):
                    keyword += 1
            if keyword >= hi:
                break
            kind = ts[keyword].text
            if (
                kind in KINDS
                and keyword + 1 < hi
                and (kind != "union" or is_union_item(ts, keyword, hi))
            ):
                j = keyword + 1
                if kind == "extern" and ts[j].text != "crate":
                    i = j
                    continue
                if kind == "const" and ts[j].text in ("{", "move", "|"):
                    i = j
                    continue
                if kind == "fn" and ts[j].text == "(":
                    i = ends[j] + 1
                    continue
                angle = 0
                while j < hi:
                    word = ts[j].text
                    if word == "<":
                        angle += 1
                    elif word == ">" and angle:
                        angle -= 1
                    if (
                        word == ";"
                        or (
                            word == "{"
                            and angle == 0
                            and kind not in ("use", "const", "static", "type")
                        )
                        or (kind == "macro_rules" and word in ("(", "["))
                    ):
                        break
                    j = ends[j] + 1 if j in ends else j + 1
                if j >= hi:
                    raise ScanError(f"unterminated {kind} at byte {ts[keyword].start}")
                body = ts[j].text == "{" or kind == "macro_rules"
                last = ends[j] if body else j
                if kind in ("impl", "use", "extern"):
                    label = kind + " " + "".join(t.text for t in ts[keyword + 1 : j])
                else:
                    name_at = keyword + (
                        2
                        if kind == "macro_rules"
                        or (kind == "static" and ts[keyword + 1].text == "mut")
                        else 1
                    )
                    label = kind + " " + ts[name_at].text
                name = f"{parent}::{label}" if parent else label
                start = ts[first].start
                result.append(
                    Item(
                        kind,
                        name,
                        start,
                        ts[last].end,
                        data.count(b"\n", 0, start) + 1,
                        len(data[data.rfind(b"\n", 0, start) + 1 : start].decode()) + 1,
                        ts[j].end if body else 0,
                    )
                )
                if body and kind in ("fn", "impl", "trait", "mod"):
                    walk(j + 1, last, name)
                i = last + 1
                continue
            # A macro's token tree is not Rust source in the enclosing scope.
            if ts[i].text == "!" and i + 1 < hi and i + 1 in ends:
                i = ends[i + 1] + 1
            elif i in ends:
                if ts[i].text == "{":
                    walk(i + 1, ends[i], parent)
                i = ends[i] + 1
            else:
                i += 1

    walk(0, len(ts), "")
    counts: dict[str, int] = {}
    totals: dict[str, int] = {}
    for item in result:
        totals[item.name] = totals.get(item.name, 0) + 1
    unique: list[Item] = []
    for item in result:
        counts[item.name] = counts.get(item.name, 0) + 1
        name = (
            item.name
            if totals[item.name] == 1
            else f"{item.name} [{counts[item.name]}]"
        )
        unique.append(
            Item(
                item.kind,
                name,
                item.start,
                item.end,
                item.line,
                item.column,
                item.body_start,
            )
        )
    return unique


def self_test() -> None:
    assert len(scan_items('fn f() { let x: &\'static str = "hi"; }')) == 1
    # Given lexical traps, when locating bytes, then only real items are returned.
    tricky = (
        b"pub fn f() { let _x = const { 3 }; let _p: fn() = f; m! { fn fake() {} } }"
    )
    assert [i.name for i in scan_items(tricky)] == ["fn f"]
    assert len(scan_items("macro_rules! parens (() => {}); fn next() {}")) == 2
    assert scan_items("struct Caf\u00e9;")[0].name == "struct Caf\u00e9"
    assert len(scan_items("impl Foo<{ 3 }> { fn f() {} }")) == 2
    source = """//! Root é
#![deny(warnings)]
/// A type
pub struct Foo;
impl Foo {
    /// braces { }
    #[inline]
    pub fn bar<'a>(x: &'a str) -> &'a str {
        /* nested /* { */ } */
        let _raw = br###"fn phantom() { }"###;
        let _ch = '}'; let _life: &'a str = x;
        println!("fn fake() {{}}");
        x
    }
}
use std::{time::Duration, fmt};
const N: usize = { 1 };
"""
    data = source.encode()

    def innermost(offset: int) -> Item:
        return min(
            (i for i in scan_items(data) if i.start <= offset < i.end),
            key=lambda i: i.end - i.start,
        )

    assert innermost(data.index(b"_raw")).name == "impl Foo::fn bar"
    assert innermost(data.index(b"std::")).kind == "use"
    assert innermost(data.index(b"pub fn")).name == "impl Foo::fn bar"
    assert len(scan_items(data)) == 5
    assert (
        scan_items("extern crate core; pub type X = fn(); static mut N: u8 = 0;")[
            1
        ].kind
        == "type"
    )
    # `union` is a contextual keyword: an item only before a name and `{`, `<` or
    # `where`; a method call, a function name or a local is an ordinary word.
    def names(text: str) -> list[str]:
        return [i.name for i in scan_items(text)]

    assert names("fn f(l: u8, r: u8) -> u8 { l.union(r) }") == ["fn f"]
    assert names("fn f() { let flags = left.union(right); }") == ["fn f"]
    assert names("impl F { pub fn union(self, o: Self) -> Self { o } }") == [
        "impl F",
        "impl F::fn union",
    ]
    assert names("fn f() { let union = 1; let _y = union + 1; }") == ["fn f"]
    assert names("pub union Bits { a: u32, b: f32 }") == ["union Bits"]
    assert names("union Pair<T: Copy> { a: T }") == ["union Pair"]
    assert names("union Pair<T> where T: Copy { a: T }") == ["union Pair"]
    print("scanner self-test: PASS")


if __name__ == "__main__":
    self_test()
