#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
# How to run: python3 scripts/lint-gates/overlay_facts.py --enforce
"""Hold every fact the vendored project overlay states about this tree.

The overlay may state a number or a list only when this gate recomputes it:

* The mutation job of `ci.yml` declares `shard: [0 .. N-1]`, runs
  `--shard <k>/N` and aggregates `--expect-shards N`. The overlay phrase
  "`mutants` (N shards)" and the register row FU-CI-04 ("runs N shards",
  `--expect-shards N`) must give that same N.
* `READERS` of `tests/ambient_guard.rs` lists the audited environment readers.
  The overlay must name every variable in it, state the reader function count
  ("N audited reader functions") and the inventory entry count ("M
  reader/variable inventory entries") exactly.
* "N `# Ambient input` sections" is the number of `src` lines with that heading.
  "N occurrences of the sentence `NOT cancel-safe: ...`" is the number of `src`
  lines with that sentence.
* "N `.rs` files" and "M `[[bin]]` targets" are the files of
  `fuzz/fuzz_targets` and the `[[bin]]` tables of `fuzz/Cargo.toml`; every file
  that is no bin's `path` is named (`helper.rs`) as not a target.
* Project rule 8 lists the CI jobs: each blocking job is named before
  "Advisory", each `continue-on-error: true` job after it, and every other
  lower-case name in backticks there is a job of `ci.yml`.
* Every script of the `lint-gates` job of `ci.yml` is named in the overlay.
"""

from __future__ import annotations

import argparse
import re
import sys
import tomllib
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
JOB: Final = re.compile(r"^  ([a-z0-9-]+):\s*$")
JOB_NAME: Final = re.compile(r"`([a-z][a-z0-9-]*)`")
CANCEL: Final = "NOT cancel-safe: this mutates credentials on the KDC"
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


def ci_jobs(ci: str) -> tuple[set[str], set[str]]:
    """The blocking and the advisory (`continue-on-error: true`) jobs of ci.yml."""
    blocking: set[str] = set()
    advisory: set[str] = set()
    current = ""
    in_jobs = False
    for line in ci.splitlines():
        if line.startswith("jobs:"):
            in_jobs = True
        elif in_jobs and (job := JOB.match(line)):
            current = job[1]
            blocking.add(current)
        elif in_jobs and current and line.startswith("    continue-on-error: true"):
            blocking.discard(current)
            advisory.add(current)
    return blocking, advisory


def gate_scripts(ci: str) -> set[str]:
    """The file names of the scripts that the `lint-gates` job runs."""
    job = re.search(r"^  lint-gates:\n(.*?)(?=^  [a-z0-9-]+:\n)", ci, re.DOTALL | re.MULTILINE)
    text = job[1] if job else ""
    return {Path(name).name for name in re.findall(r"scripts/[\w./-]+\.(?:py|sh)\b", text)}


def lines_with(root: Path, folder: str, needle: str) -> int:
    return sum(
        needle in line
        for path in sorted((root / folder).rglob("*.rs"))
        for line in path.read_text(encoding="utf-8").splitlines()
    )


def check_counts(root: Path, overlay: str) -> list[str]:
    ambient = lines_with(root, "src", "# Ambient input")
    cancel = lines_with(root, "src", CANCEL)
    manifest = tomllib.loads(read(root, "fuzz/Cargo.toml"))
    files = {path.name for path in (root / "fuzz/fuzz_targets").glob("*.rs")}
    bins = {Path(table["path"]).name for table in manifest.get("bin", [])}
    expected = [
        f"{ambient} `# Ambient input` sections",
        f"{cancel} occurrences of the sentence `{CANCEL}`",
        f"{len(files)} `.rs` files",
        f"{len(manifest.get('bin', []))} `[[bin]]` targets",
        *(f"`{name}`" for name in sorted(files - bins)),
    ]
    return [
        f"{OVERLAY}: expected `{text}`" for text in expected if text not in overlay
    ]


def check_jobs(ci: str, overlay: str) -> list[str]:
    start, end = overlay.find("8. **CI"), overlay.find("9. **Releases")
    cut = overlay.find("Advisory", start)
    if not 0 <= start < cut < end:
        return [f"{OVERLAY}: rule 8 (CI jobs, Advisory, rule 9) not found"]
    blocking, advisory = ci_jobs(ci)
    errors: list[str] = []
    for label, text, jobs in (
        ("blocking", overlay[start:cut], blocking),
        ("advisory", overlay[cut:end], advisory),
    ):
        named = set(JOB_NAME.findall(text)) - {"continue-on-error"}
        errors += [f"{OVERLAY}: rule 8 omits {label} job {job}" for job in sorted(jobs - named)]
        errors += [
            f"{OVERLAY}: rule 8 names {name} as {label}, {CI} disagrees"
            for name in sorted(named - jobs)
        ]
    return errors


def check(root: Path) -> list[str]:
    errors: list[str] = []
    ci = read(root, CI)
    shards = ci_shards(ci)
    if shards is None:
        return [f"{CI}: mutants matrix, --shard and --expect-shards disagree"]
    overlay = " ".join(read(root, OVERLAY).split())
    stated = {int(n) for n in re.findall(r"`mutants` \((\d+) shards\)", overlay)}
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
    errors += check_counts(root, overlay)
    errors += check_jobs(ci, overlay)
    errors += [
        f"{OVERLAY}: lint-gates script {name} not named"
        for name in sorted(gate_scripts(ci))
        if name not in overlay
    ]
    return errors


def self_test() -> int:
    def sample_files(shards: int = 4) -> dict[str, str]:
        """A minimal tree on which every checked fact agrees."""
        ids = ", ".join(map(str, range(shards)))
        overlay = (
            "Fuzz: `fuzz/fuzz_targets/` holds 3 `.rs` files and `fuzz/Cargo.toml` declares "
            "2 `[[bin]]` targets; `helper.rs` is a shared helper, not a target. "
            "1 audited reader functions, 2 reader/variable "
            "inventory entries: `TMPDIR` `HOME`. 2 `# Ambient input` sections. "
            "3 occurrences of the sentence `NOT cancel-safe: this mutates credentials on the KDC`. "
            "Gates: `a_gate.py --enforce`, `b.sh self-test`. "
            "8. **CI is blocking: `fmt`, `lint-gates`. Advisory (`continue-on-error`): "
            f"`mutants` ({shards} shards). 9. **Releases"
        )
        return {
            CI: "jobs:\n  fmt:\n    name: fmt\n  lint-gates:\n    steps:\n"
            "      - run: python3 scripts/lint-gates/a_gate.py --enforce\n"
            "      - run: bash scripts/b.sh self-test\n"
            "  mutants:\n    continue-on-error: true\n"
            f"    shard: [{ids}]\n    --shard ${{{{ matrix.shard }}}}/{shards}\n"
            f"    --expect-shards {shards}\n",
            OVERLAY: overlay,
            REGISTER: f"| FU-CI-04 | runs {shards} shards (`--expect-shards {shards}`) |",
            GUARD: '("src/a.rs", "A::f", "TMPDIR", "T"), ("src/a.rs", "A::f", "HOME", "H"),',
            "src/a.rs": "/// # Ambient input\n/// # Ambient input\n"
            + "// NOT cancel-safe: this mutates credentials on the KDC\n" * 3,
            "fuzz/Cargo.toml": '[[bin]]\nname = "a"\npath = "fuzz_targets/a.rs"\n'
            '[[bin]]\nname = "b"\npath = "fuzz_targets/b.rs"\n',
            "fuzz/fuzz_targets/a.rs": "",
            "fuzz/fuzz_targets/b.rs": "",
            "fuzz/fuzz_targets/helper.rs": "",
        }

    # (name, file, old text, new text, text the problem must contain)
    cases = (
        ("agree", CI, "", "", None),
        ("overlay shards", OVERLAY, "(4 shards)", "(2 shards)", "mutants shards"),
        ("register shards", REGISTER, "runs 4", "runs 2", "FU-CI-04"),
        ("missing variable", OVERLAY, "`HOME`", "", "variable HOME"),
        ("reader count", OVERLAY, "1 audited", "2 audited", "audited reader functions"),
        ("entry count", OVERLAY, "2 reader", "3 reader", "inventory entries"),
        ("ambient sections", OVERLAY, "2 `# Ambient", "16 `# Ambient", "# Ambient input"),
        ("cancel-safe count", OVERLAY, "3 occurrences", "4 occurrences", "NOT cancel-safe"),
        ("fuzz files", OVERLAY, "3 `.rs` files", "4 `.rs` files", "`.rs` files"),
        ("fuzz bins", OVERLAY, "2 `[[bin]]`", "3 `[[bin]]`", "`[[bin]]` targets"),
        ("fuzz helper", OVERLAY, "`helper.rs`", "`other.rs`", "helper.rs"),
        ("blocking job", OVERLAY, "`fmt`, ", "", "job fmt"),
        ("stale job", OVERLAY, "shards).", "shards), `gone`.", "names gone"),
        ("advisory as blocking", OVERLAY, "`fmt`, `lint-gates`", "`fmt`, `lint-gates`, `mutants`", "names mutants"),
        ("gate script", OVERLAY, "`a_gate.py --enforce`", "", "a_gate.py"),
        ("shell script", OVERLAY, "`b.sh self-test`", "", "b.sh"),
    )
    for name, relative, old, new, expected in cases:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            files = sample_files()
            assert old in files[relative], f"{name}: sample lacks {old!r}"
            files[relative] = files[relative].replace(old, new)
            for path, text in files.items():
                (root / path).parent.mkdir(parents=True, exist_ok=True)
                (root / path).write_text(text, encoding="utf-8")
            out = StringIO()
            with redirect_stdout(out):
                code = main(["--enforce", "--root", str(root)])
            assert code == (expected is not None), f"{name}: exit {code}\n{out.getvalue()}"
            assert expected is None or expected in out.getvalue(), f"{name}: {out.getvalue()}"
    print(
        "overlay_facts self-test: ok (shards, register row, ambient readers and sections, "
        "cancel-safe sentences, fuzz files and bins, CI jobs, gate scripts)"
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
