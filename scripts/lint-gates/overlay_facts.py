#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
# How to run: python3 scripts/lint-gates/overlay_facts.py --enforce
"""Hold the vendored project overlay's mutation-shard and ambient-reader facts.

* The mutation job of `ci.yml` declares `shard: [0 .. N-1]`, runs
  `--shard <k>/N` and aggregates `--expect-shards N`. The overlay sentence
  "whole crate, N shards" and the register row FU-CI-04 ("runs N shards",
  `--expect-shards N`) must give that same N.
* `READERS` of `tests/ambient_guard.rs` lists the audited environment readers.
  The overlay must name every variable in it, state the reader function count
  ("N audited reader functions") and the inventory entry count ("M
  reader/variable inventory entries") exactly.
"""

from __future__ import annotations

import argparse
import re
import sys
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Final

ROOT: Final = Path(__file__).resolve().parents[2]
CI: Final = ".github/workflows/ci.yml"
OVERLAY: Final = "docs/rust-guidelines/overlays/projects/rskrb5-ng.md"
REGISTER: Final = "docs/review/followup-6586b7a.md"
GUARD: Final = "tests/ambient_guard.rs"
ENTRY: Final = re.compile(r'\(\s*"([^"]+)",\s*"([^"]+)",\s*"([A-Z][A-Z0-9_]*)",')


def read(root: Path, relative: str) -> str:
    return (root / relative).read_text(encoding="utf-8")


def ci_shards(ci: str) -> int | None:
    """The shard count when the matrix, `--shard` and `--expect-shards` agree."""
    matrix = re.search(r"^\s*shard: \[([0-9, ]+)\]", ci, re.MULTILINE)
    runs = {int(n) for n in re.findall(r"--shard \$\{\{ matrix\.shard \}\}/(\d+)", ci)}
    expected = {int(n) for n in re.findall(r"--expect-shards (\d+)", ci)}
    if matrix is None:
        return None
    ids = [int(n) for n in matrix[1].split(",")]
    count = len(ids)
    if ids != list(range(count)) or runs != {count} or expected != {count}:
        return None
    return count


def check(root: Path) -> list[str]:
    errors: list[str] = []
    shards = ci_shards(read(root, CI))
    if shards is None:
        return [f"{CI}: mutants matrix, --shard and --expect-shards disagree"]
    overlay = " ".join(read(root, OVERLAY).split())
    stated = {int(n) for n in re.findall(r"whole crate, (\d+) shards", overlay)}
    if stated != {shards}:
        errors.append(
            f"{OVERLAY}: mutants shards {sorted(stated)}, ci.yml has {shards}"
        )
    row = next(
        (
            line
            for line in read(root, REGISTER).splitlines()
            if line.startswith("| FU-CI-04 ")
        ),
        "",
    )
    counts = {int(n) for n in re.findall(r"runs (\d+) shards", row)}
    counts |= {int(n) for n in re.findall(r"--expect-shards (\d+)", row)}
    if counts != {shards}:
        errors.append(
            f"{REGISTER}: FU-CI-04 shard counts {sorted(counts)}, ci.yml has {shards}"
        )
    entries = ENTRY.findall(read(root, GUARD))
    for variable in sorted({variable for *_, variable in entries}):
        if f"`{variable}`" not in overlay:
            errors.append(f"{OVERLAY}: ambient reader variable {variable} not named")
    for label, number in (
        (
            "audited reader functions",
            len({(path, owner) for path, owner, _ in entries}),
        ),
        ("reader/variable inventory entries", len(entries)),
    ):
        if f"{number} {label}" not in overlay:
            errors.append(f"{OVERLAY}: expected `{number} {label}`")
    return errors


def self_test() -> int:
    def sample(root: Path, shards: int, overlay: str, row: str, guard: str) -> None:
        files = {
            CI: f"        shard: [{', '.join(map(str, range(shards)))}]\n"
            f"        --shard ${{{{ matrix.shard }}}}/{shards}\n"
            f"        --expect-shards {shards}\n",
            OVERLAY: overlay,
            REGISTER: row,
            GUARD: guard,
        }
        for relative, text in files.items():
            (root / relative).parent.mkdir(parents=True, exist_ok=True)
            (root / relative).write_text(text, encoding="utf-8")

    guard = '("src/a.rs", "A::f", "TMPDIR", "T"), ("src/a.rs", "A::f", "HOME", "H"),'
    good_overlay = (
        "whole crate, 4 shards; 1 audited reader functions, 2 reader/variable "
        "inventory entries: `TMPDIR` `HOME`"
    )
    good_row = "| FU-CI-04 | runs 4 shards (`--expect-shards 4`) |"
    cases = {
        "agree": (4, good_overlay, good_row, guard, 0),
        "overlay shards": (
            4,
            good_overlay.replace("4 shards", "2 shards"),
            good_row,
            guard,
            1,
        ),
        "register shards": (
            4,
            good_overlay,
            good_row.replace("runs 4", "runs 2"),
            guard,
            1,
        ),
        "missing variable": (4, good_overlay.replace("`HOME`", ""), good_row, guard, 1),
        "reader count": (
            4,
            good_overlay.replace("1 audited", "2 audited"),
            good_row,
            guard,
            1,
        ),
        "entry count": (
            4,
            good_overlay.replace("2 reader", "3 reader"),
            good_row,
            guard,
            1,
        ),
    }
    for name, (shards, overlay, row, text, expected) in cases.items():
        with TemporaryDirectory() as directory:
            root = Path(directory)
            sample(root, shards, overlay, row, text)
            with redirect_stdout(StringIO()):
                code = main(["--enforce", "--root", str(root)])
            assert code == expected, f"{name}: exit {code}, expected {expected}"
    print(
        "overlay_facts self-test: ok (shard counts, register row, reader variables and counts)"
    )
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
    for problem in problems:
        print(f"overlay_facts: {problem}")
    print(f"overlay_facts: {len(problems)} problem(s)")
    return 1 if args.enforce and problems else 0


if __name__ == "__main__":
    sys.exit(main())
