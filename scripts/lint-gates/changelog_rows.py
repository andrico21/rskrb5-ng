#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
# How to run: python3 scripts/lint-gates/changelog_rows.py --enforce
"""Hold the changelog to the follow-up register's behaviour changes.

Every `fixed` row of `docs/review/followup-6586b7a.md` whose "Behaviour
change" cell does not begin with `none` must name its register ID in
`CHANGELOG.md`, so an observable change cannot ship without a release-record
entry. Only the ID is matched (as a whole token): the wording is free.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Final

ROOT: Final = Path(__file__).resolve().parents[2]
REGISTER: Final = "docs/review/followup-6586b7a.md"
CHANGELOG: Final = "CHANGELOG.md"
ROW_ID: Final = re.compile(r"FU-[A-Z]+-R?\d+")


def changed_rows(register: str) -> list[str]:
    rows = []
    for line in register.splitlines():
        cells = [cell.strip() for cell in line.split("|")]
        if len(cells) < 8 or ROW_ID.fullmatch(cells[1]) is None:
            continue
        if cells[4] == "fixed" and not cells[6].lower().startswith("none"):
            rows.append(cells[1])
    return rows


def check(root: Path) -> list[str]:
    register = (root / REGISTER).read_text(encoding="utf-8")
    changelog = (root / CHANGELOG).read_text(encoding="utf-8")
    named = set(re.findall(r"(?<![\w-])FU-[A-Z]+-R?\d+(?![\w-])", changelog))
    return [
        f"{REGISTER}: {row} records a behaviour change missing from {CHANGELOG}"
        for row in changed_rows(register)
        if row not in named
    ]


def self_test() -> int:
    header = "| ID | Sev | Title | Status | Proof | Behaviour change | Evidence |\n"
    register = header + "".join(
        f"| {row} | minor | t | {status} | p | {change} | e |\n"
        for row, status, change in (
            ("FU-CLI-R1", "fixed", "Constructor returns Result."),
            ("FU-CLI-R15", "fixed", "DER must match."),
            ("FU-DOC-R2", "fixed", "none; documentation only"),
            ("FU-GATE-R3", "dismissed", "Would have changed a gate."),
        )
    )
    cases = (
        ("- Constructors (FU-CLI-R1).\n- DER (FU-CLI-R15).\n", []),
        ("- DER (FU-CLI-R15).\n", ["FU-CLI-R1"]),
        ("- Constructors (FU-CLI-R1, FU-CLI-R15-x).\n", ["FU-CLI-R15"]),
        ("", ["FU-CLI-R1", "FU-CLI-R15"]),
    )
    with TemporaryDirectory() as directory:
        root = Path(directory)
        (root / REGISTER).parent.mkdir(parents=True)
        (root / REGISTER).write_text(register, encoding="utf-8")
        for changelog, expected in cases:
            (root / CHANGELOG).write_text(changelog, encoding="utf-8")
            found = [ROW_ID.search(problem)[0] for problem in check(root)]
            assert found == expected, (changelog, found)
    print("changelog_rows self-test passed")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--enforce", action="store_true")
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    problems = check(args.root)
    print("\n".join([*problems, f"changelog_rows: {len(problems)} problem(s)"]))
    return int(args.enforce and bool(problems))


if __name__ == "__main__":
    sys.exit(main())
