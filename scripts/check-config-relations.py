#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
# How to run: python3 scripts/check-config-relations.py [--self-test|--print|--write]
"""Generate and audit packaged configuration documentation from literal Rust tables."""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Final

sys.path.insert(0, str(Path(__file__).resolve().parent / "lint-gates"))
from rust_lex import strip_comments_and_strings

ROOT: Final = Path(__file__).resolve().parents[1]
TABLES: Final = (
    (
        "libdefaults",
        "src/config/libdefaults/relations.rs",
        "RELATIONS",
        43,
        "src/config/libdefaults/completeness.rs",
    ),
    (
        "realms",
        "src/config/realm_relations.rs",
        "REALM_RELATIONS",
        28,
        "src/config/section_inventory_tests.rs",
    ),
    ("sections", "src/config/section_decode.rs", "SECTION_RELATIONS", 6, ""),
)
STRING: Final = r'"([^"\\\r\n]+)"'
ROW: Final = re.compile(r"\s*\(\s*" + r"\s*,\s*".join([STRING] * 6) + r"\s*,?\s*\)\s*,")
HEADER: Final = """# Configuration relations

Generated from the three Rust relation tables. Do not edit by hand.
Regenerate with `python3 scripts/check-config-relations.py --write`.

Reference: [MIT krb5 1.22 documentation](https://web.mit.edu/kerberos/krb5-1.22/doc/admin/conf_files/krb5_conf.html).
Defaults below are MIT's; stricter library defaults and unavailable consumers
are noted in the classification. See [profile semantics](config-profile.md)
and [security policy](security-policy.md) for explicit divergences and limits.
Compatible mode reports deferred or unknown policy; Strict rejects every
diagnostic. Unsupported settings that would tighten current behavior fail in
both modes. Parsed values do not imply an implemented mechanism.

"""


@dataclass(frozen=True, slots=True)
class AuditError(Exception):
    detail: str

    def __str__(self) -> str:
        return self.detail


@dataclass(frozen=True, slots=True)
class Relation:
    name: str
    kind: str
    default: str
    consumer: str
    rationale: str
    test: str


def table(text: str, symbol: str, count: int) -> list[Relation]:
    """Accept only fully consumed literal tuples; opaque expressions fail closed."""
    declaration = re.search(
        rf"pub\(crate\) const {symbol}:.*?=\s*\[(.*?)\];",
        strip_comments_and_strings(text),
        re.S,
    )
    if declaration is None:
        raise AuditError(f"missing table {symbol}")
    body = text[declaration.start(1) : declaration.end(1)]
    rows: list[Relation] = []
    offset = 0
    while body[offset:].strip():
        row = ROW.match(body, offset)
        if row is None:
            raise AuditError(f"unreadable {symbol} tuple at offset {offset}")
        rows.append(Relation(*row.groups()))
        offset = row.end()
    if len(rows) != count or len({row.name for row in rows}) != count:
        raise AuditError(f"{symbol}: expected {count} unique rows, got {len(rows)}")
    return rows


def test_names(text: str) -> set[str]:
    """Recognize test declarations and this repository's checked named-test macros."""
    clean = strip_comments_and_strings(text)
    names = set(
        re.findall(r"#\[test\]\s*(?:#\[[^]]+\]\s*)*(?:async\s+)?fn\s+(\w+)", clean)
    )
    for macro in re.finditer(r"macro_rules!\s+(\w+)\s*\{(.*?)\n\s*\}", clean, re.S):
        if re.search(r"#\[test\]\s*fn\s+\$name\s*\(", macro[2]) is None:
            continue
        for invocation in re.finditer(rf"\b{macro[1]}!\s*\{{([^}}]*)\}}", clean, re.S):
            names.update(re.findall(r"(?:^|;)\s*(\w+)\s*,", invocation[1]))
    return names


def expected_names(text: str) -> list[str]:
    match = re.search(r"let expected = \[(.*?)\];", text, re.S)
    if match is None:
        raise AuditError("missing pinned expected-name inventory")
    return re.findall(STRING, match[1])


def verify(rows: list[Relation], expected: list[str], tests: set[str]) -> None:
    if [row.name for row in rows] != expected:
        raise AuditError("table differs from pinned MIT inventory")
    for row in rows:
        if row.test not in tests:
            raise AuditError(f"{row.name}: missing named test {row.test}")


def render(root: Path) -> str:
    tests: set[str] = set()
    for folder in ("src", "tests"):
        for path in sorted((root / folder).rglob("*.rs")):
            tests.update(test_names(path.read_text(encoding="utf-8")))
    output = [HEADER]
    for section, path, symbol, count, inventory in TABLES:
        rows = table((root / path).read_text(encoding="utf-8"), symbol, count)
        expected = (
            expected_names((root / inventory).read_text(encoding="utf-8"))
            if inventory
            else [
                "domain_realm",
                "capaths",
                "appdefaults",
                "disable",
                "enable_only",
                "module",
            ]
        )
        verify(rows, expected, tests)
        output.append(f"## {section} ({count})\n\n")
        output.append(
            "| Section | Relation | Typed value | MIT default | Effective consumer / package | Fail-closed classification | Test |\n"
        )
        output.append("| --- | --- | --- | --- | --- | --- | --- |\n")
        for row in rows:
            scope = section
            if section == "sections":
                scope = (
                    "plugins"
                    if row.name in ("module", "disable", "enable_only")
                    else row.name
                )
            fields = (
                scope,
                row.name,
                row.kind,
                row.default,
                row.consumer,
                row.rationale,
                row.test,
            )
            output.append(
                "| "
                + " | ".join(field.replace("|", "&#124;") for field in fields)
                + " |\n"
            )
        output.append("\n")
    return "".join(output)


def check(actual: str, generated: str) -> None:
    """Exact deterministic comparison, allowing only checkout newline conversion."""
    if actual.replace("\r\n", "\n") != generated:
        raise AuditError("docs/config-relations.md is stale; run --write")


def self_test() -> None:
    sample = 'pub(crate) const ITEMS: [(&str, &str, &str, &str, &str, &str); 1] = [("a", "b", "c", "d", "e", "proof"),];'
    assert table(sample, "ITEMS", 1)[0].test == "proof"
    for broken, count in [
        (sample.replace('"b"', "opaque!()"), 1),
        (sample, 2),
        (sample.replace("ITEMS", "MISSING"), 1),
        (sample.replace(",];", ',("a", "b", "c", "d", "e", "proof"),];'), 2),
    ]:
        try:
            table(broken, "ITEMS", count)
        except AuditError as failure:
            assert failure.detail
        else:
            raise AssertionError("malformed/incomplete/duplicate table accepted")
    assert test_names(
        '// #[test] fn decoy() {}\n"#[test] fn fake() {}"\n#[test]\nfn real() {}'
    ) == {"real"}
    assert not test_names("fn ordinary() {}")
    try:
        table("// " + sample, "ITEMS", 1)
    except AuditError as failure:
        assert "missing" in failure.detail
    else:
        raise AssertionError("commented table accepted")
    for expected, names in [(["different"], {"proof"}), (["a"], {"missing"})]:
        try:
            verify(table(sample, "ITEMS", 1), expected, names)
        except AuditError as failure:
            assert failure.detail
        else:
            raise AssertionError("missing inventory name or named test accepted")
    assert test_names(
        'macro_rules! cases {\n () => { #[test] fn $name() {} };\n}\ncases! { one, "x"; two, "y"; }'
    ) == {"one", "two"}
    check("a\r\n", "a\n")
    try:
        check("stale\n", "generated\n")
    except AuditError as failure:
        assert "stale" in failure.detail
    else:
        raise AssertionError("documentation drift accepted")
    generated = render(ROOT)
    check((ROOT / "docs/config-relations.md").read_text(encoding="utf-8"), generated)
    print(
        "config-relations self-test: PASS (malformed, missing, duplicate, decoys, drift, CRLF)"
    )


def main() -> int:
    args = sys.argv[1:]
    if args == ["--self-test"]:
        self_test()
        return 0
    generated = render(ROOT)
    if args == ["--print"]:
        sys.stdout.write(generated)
    elif args == ["--write"]:
        (ROOT / "docs/config-relations.md").write_text(
            generated, encoding="utf-8", newline="\n"
        )
    elif not args:
        check(
            (ROOT / "docs/config-relations.md").read_text(encoding="utf-8"), generated
        )
        print(
            "config-relations: 43 libdefaults, 28 realm, 6 section rows; named tests and generated document match"
        )
    else:
        raise AuditError(
            "usage: check-config-relations.py [--self-test|--print|--write]"
        )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AuditError, OSError, UnicodeError) as failure:
        print(f"config-relations: {failure}", file=sys.stderr)
        raise SystemExit(2) from failure
