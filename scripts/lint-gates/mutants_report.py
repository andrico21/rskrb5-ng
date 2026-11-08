#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
# How to run: python3 scripts/lint-gates/mutants_report.py --self-test
"""Check a sharded cargo-mutants campaign for completeness and triage.

`--artifacts DIR` holds one `mutants-out-shard-<k>` directory per shard (the
`mutants.out` of `cargo mutants --shard k/N`, as CI uploads it). The campaign
is incomplete when a shard is missing or did not finish: no `outcomes.json`,
`end_time` null, no successful baseline, an empty `mutants.json`, or tested
mutant identities that differ from the generated inventory.

With `--register FILE` (docs/review/mutants.md) every missed or timed-out
mutant of the campaign needs a row with a final status in the table
`| campaign | mutant (full name) | file | function | operator | outcome |
status | proof or reason |`. A row is identified by the campaign SHA and the
full cargo-mutants name with its location (`src/x.rs:12:5: replace ...`); a
`|` inside a cell is written `\\|`. Final statuses: `killed` (the proof names
the test), `equivalent` (the reason), and `hang` (only for a `timeout`
outcome, after a 600 s local re-run that still times out). `--allow-open`
tolerates `open` rows. Counts per outcome are printed; `--enforce` exits 1 on
any problem.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import Counter
from contextlib import redirect_stdout
from dataclasses import dataclass
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Final

OUTCOMES: Final = {
    "CaughtMutant": "caught",
    "MissedMutant": "missed",
    "Timeout": "timeout",
    "Unviable": "unviable",
    "Success": "success",
}
TRIAGED: Final = ("missed", "timeout")
FINAL: Final = ("killed", "equivalent", "hang")
HEADER: Final = (
    "campaign",
    "mutant (full name)",
    "file",
    "function",
    "operator",
    "outcome",
    "status",
    "proof or reason",
)


@dataclass(frozen=True, slots=True)
class Row:
    campaign: str
    mutant: str
    outcome: str
    status: str
    proof: str


def cells(line: str) -> list[str]:
    parts = re.split(r"(?<!\\)\|", line.strip().strip("|"))
    return [part.strip().replace("\\|", "|") for part in parts]


def register_rows(markdown: str) -> list[Row]:
    rows: list[Row] = []
    in_table = False
    for line in markdown.splitlines():
        if not line.strip().startswith("|"):
            in_table = False
            continue
        values = cells(line)
        if tuple(value.lower() for value in values) == HEADER:
            in_table = True
            continue
        if not in_table or all(set(value) <= set("-: ") for value in values):
            continue
        if len(values) != len(HEADER):
            raise ValueError(f"register row needs {len(HEADER)} cells: {line!r}")
        rows.append(
            Row(values[0], values[1].strip("`"), values[5], values[6], values[7])
        )
    return rows


def shard_report(directory: Path, shard: int) -> tuple[list[str], dict[str, str]]:
    """(problems, {mutant name: outcome}) of one shard's mutants.out."""
    outcomes_path = directory / "outcomes.json"
    if not directory.is_dir():
        return [f"shard {shard}: missing"], {}
    if not outcomes_path.is_file():
        return [f"shard {shard}: did not finish (no outcomes.json)"], {}
    outcomes = json.loads(outcomes_path.read_text(encoding="utf-8"))
    mutants: dict[str, str] = {}
    problems = []
    for entry in outcomes["outcomes"]:
        scenario = entry["scenario"]
        if isinstance(scenario, dict) and "Mutant" in scenario:
            name = scenario["Mutant"]["name"]
            if name in mutants:
                problems.append(f"shard {shard}: duplicate mutant outcome: {name}")
            if entry["summary"] not in {
                "CaughtMutant",
                "MissedMutant",
                "Timeout",
                "Unviable",
            }:
                problems.append(
                    f"shard {shard}: invalid mutant summary: {entry['summary']}"
                )
            mutants[scenario["Mutant"]["name"]] = OUTCOMES.get(
                entry["summary"], entry["summary"]
            )
    baselines = [
        entry["summary"]
        for entry in outcomes["outcomes"]
        if entry["scenario"] == "Baseline"
    ]
    if baselines != ["Success"]:
        problems.append(f"shard {shard}: expected one successful baseline")
    if outcomes.get("end_time") is None:
        problems.append(f"shard {shard}: did not finish (end_time is null)")
    listing = directory / "mutants.json"
    if not listing.is_file():
        problems.append(
            f"shard {shard}: no mutants.json, so its listed count is unknown"
        )
    else:
        listed = [
            entry["name"] for entry in json.loads(listing.read_text(encoding="utf-8"))
        ]
        if not listed:
            problems.append(f"shard {shard}: empty generated mutation inventory")
        if len(listed) != len(mutants):
            problems.append(
                f"shard {shard}: did not finish (tested {len(mutants)} of {len(listed)} listed)"
            )
        if set(listed) != set(mutants):
            problems.append(
                f"shard {shard}: generated and tested mutant identities differ"
            )
    return problems, mutants


def register_problems(
    mutants: dict[str, str], rows: list[Row], campaign: str, allow_open: bool
) -> list[str]:
    by_name: dict[str, list[Row]] = {}
    for row in rows:
        if row.campaign == campaign:
            by_name.setdefault(row.mutant, []).append(row)
    problems = []
    for name, outcome in sorted(mutants.items()):
        if outcome not in TRIAGED:
            continue
        found = by_name.get(name, [])
        if len(found) != 1:
            problems.append(f"{outcome} mutant has {len(found)} register rows: {name}")
            continue
        row = found[0]
        if row.outcome != outcome:
            problems.append(
                f"register outcome {row.outcome!r} is not {outcome!r}: {name}"
            )
        if row.status == "open":
            if not allow_open:
                problems.append(f"open: {name}")
        elif row.status not in FINAL:
            problems.append(f"status {row.status!r} is not one of {FINAL}: {name}")
        elif row.status == "hang" and outcome != "timeout":
            problems.append(f"hang is only for a timeout outcome: {name}")
        elif not row.proof or row.proof == "-":
            problems.append(f"{row.status} without a proof or reason: {name}")
    return problems


def report(args: argparse.Namespace) -> tuple[list[str], Counter[str]]:
    if args.expect_shards <= 0:
        return ["expected shard count must be positive"], Counter()
    problems: list[str] = []
    mutants: dict[str, str] = {}
    for shard in range(args.expect_shards):
        shard_problems, shard_mutants = shard_report(
            args.artifacts / f"mutants-out-shard-{shard}", shard
        )
        problems += shard_problems
        overlap = mutants.keys() & shard_mutants.keys()
        if overlap:
            problems.append(
                f"shard {shard}: overlapping mutant identities: {sorted(overlap)}"
            )
        mutants.update(shard_mutants)
    if args.register:
        if not args.campaign:
            problems.append("--register needs --campaign SHA (or GITHUB_SHA)")
        else:
            rows = register_rows(args.register.read_text(encoding="utf-8"))
            problems += register_problems(mutants, rows, args.campaign, args.allow_open)
    return problems, Counter(mutants.values())


def self_test() -> int:
    def shard(
        root: Path, k: int, names: list[tuple[str, str]], listed: int, done: bool = True
    ) -> None:
        directory = root / f"mutants-out-shard-{k}"
        directory.mkdir(parents=True)
        outcomes = [{"scenario": "Baseline", "summary": "Success"}] + [
            {"scenario": {"Mutant": {"name": name}}, "summary": summary}
            for name, summary in names
        ]
        (directory / "outcomes.json").write_text(
            json.dumps({"outcomes": outcomes, "end_time": "t" if done else None})
        )
        inventory = [name for name, _ in names]
        inventory.extend(
            f"src/missing.rs:{index}:1: x" for index in range(len(names), listed)
        )
        (directory / "mutants.json").write_text(
            json.dumps([{"name": name} for name in inventory])
        )

    missed = "src/client.rs:4950:17: replace | with ^ in renewal_kdc_option_bits"
    missed_col = "src/client.rs:4950:21: replace | with ^ in renewal_kdc_option_bits"
    slow = 'src/config.rs:1230:17: delete match arm "kdc" in Realm::parse'
    escaped = missed.replace("|", "\\|")
    head = "| " + " | ".join(HEADER) + " |\n| --- " * 1 + "|" + " --- |" * 7 + "\n"
    with TemporaryDirectory() as directory:
        root = Path(directory)
        for expected in (0, -1):
            with redirect_stdout(StringIO()):
                assert (
                    main(
                        [
                            "--artifacts",
                            str(root),
                            "--expect-shards",
                            str(expected),
                            "--enforce",
                        ]
                    )
                    == 1
                ), "empty campaign certified"
        for summary in ("Success", "UnknownSummary", "CaughtMutant"):
            campaign = root / summary
            shard(campaign, 0, [("same", summary)], 1)
            shard(campaign, 1, [("same", "CaughtMutant")], 1)
            with redirect_stdout(StringIO()):
                assert (
                    main(
                        [
                            "--artifacts",
                            str(campaign),
                            "--expect-shards",
                            "2",
                            "--enforce",
                        ]
                    )
                    == 1
                ), "overlapping campaign certified"
            if summary != "CaughtMutant":
                assert shard_report(campaign / "mutants-out-shard-0", 0)[0], (
                    "invalid mutant summary accepted"
                )
        duplicate = root / "duplicate-outcomes"
        shard(duplicate, 0, [("same", "CaughtMutant"), ("same", "CaughtMutant")], 2)
        assert shard_report(duplicate / "mutants-out-shard-0", 0)[0], (
            "duplicate outcomes accepted"
        )
        artifacts = root / "artifacts"
        shard(
            artifacts,
            0,
            [(missed, "MissedMutant"), ("src/a.rs:1:1: x", "CaughtMutant")],
            2,
        )
        shard(artifacts, 1, [(slow, "Timeout"), (missed_col, "MissedMutant")], 2)
        register = root / "mutants.md"

        def run(*extra: str) -> tuple[int, str]:
            printed = StringIO()
            with redirect_stdout(printed):
                code = main(
                    [
                        "--artifacts",
                        str(artifacts),
                        "--register",
                        str(register),
                        "--campaign",
                        "abc1234",
                        "--enforce",
                        *extra,
                    ]
                )
            return code, printed.getvalue()

        # Given one shard missing and one missed mutant unrecorded, both are reported.
        register.write_text(
            head
            + f"| abc1234 | `{escaped}` | src/client.rs | renewal_kdc_option_bits | \\| | missed | killed | `renewal_bits_xor` |\n"
        )
        code, out = run("--expect-shards", "3")
        assert (
            code == 1
            and "shard 2: missing" in out
            and f"1 register rows: {missed_col}" not in out
        ), out
        assert f"missed mutant has 0 register rows: {missed_col}" in out, out
        assert f"timeout mutant has 0 register rows: {slow}" in out, out
        # Given every mutant triaged, the campaign passes and counts are printed.
        register.write_text(
            register.read_text()
            + f"| abc1234 | `{missed_col.replace('|', chr(92) + '|')}` | src/client.rs | f | \\| | missed | equivalent | same bits |\n"
            + f"| abc1234 | `{slow}` | src/config.rs | Realm::parse | arm | timeout | hang | 600 s re-run timed out |\n"
        )
        code, out = run("--expect-shards", "2")
        assert (
            code == 0 and "missed=2" in out and "timeout=1" in out and "caught=1" in out
        ), out
        # A row of another campaign does not count; open needs --allow-open.
        text = register.read_text()
        register.write_text(
            text.replace("| abc1234 | `src/config", "| fff0000 | `src/config")
        )
        assert "0 register rows" in run("--expect-shards", "2")[1]
        register.write_text(text.replace("| hang |", "| open |"))
        assert run("--expect-shards", "2")[0] == 1
        assert run("--expect-shards", "2", "--allow-open")[0] == 0
        register.write_text(
            text.replace("| timeout | hang |", "| timeout | killed |").replace(
                "| equivalent |", "| hang |"
            )
        )
        assert "hang is only for a timeout outcome" in run("--expect-shards", "2")[1]
        # An unfinished shard: null end_time, or fewer tested than listed.
        shard(artifacts, 2, [(missed, "MissedMutant")], 4, done=False)
        out = run("--expect-shards", "3")[1]
        assert "shard 2: did not finish (end_time is null)" in out, out
        assert "shard 2: did not finish (tested 1 of 4 listed)" in out, out
        empty = root / "empty"
        empty.mkdir()
        (empty / "outcomes.json").write_text(
            json.dumps({"outcomes": [], "end_time": "done"})
        )
        (empty / "mutants.json").write_text("[]")
        problems, _ = shard_report(empty, 0)
        assert any("baseline" in problem for problem in problems), problems
        assert any("empty" in problem for problem in problems), problems
        for baseline in ([], [{"scenario": "Baseline", "summary": "Failure"}]):
            (empty / "outcomes.json").write_text(
                json.dumps(
                    {
                        "outcomes": baseline
                        + [
                            {
                                "scenario": {"Mutant": {"name": missed}},
                                "summary": "CaughtMutant",
                            }
                        ],
                        "end_time": "done",
                    }
                )
            )
            (empty / "mutants.json").write_text(json.dumps([{"name": missed}]))
            assert any("baseline" in problem for problem in shard_report(empty, 0)[0])
        (empty / "outcomes.json").write_text(
            json.dumps(
                {
                    "outcomes": [
                        {"scenario": "Baseline", "summary": "Success"},
                        {
                            "scenario": {"Mutant": {"name": missed}},
                            "summary": "CaughtMutant",
                        },
                    ],
                    "end_time": "done",
                }
            )
        )
        assert shard_report(empty, 0) == ([], {missed: "caught"})
        (empty / "mutants.json").write_text(json.dumps([{"name": missed_col}]))
        assert any("identities" in problem for problem in shard_report(empty, 0)[0])
    print(
        "mutants_report self-test: ok (missing and unfinished shards, unrecorded, open, misplaced hang, escaped names)"
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--artifacts", type=Path)
    parser.add_argument("--expect-shards", type=int)
    parser.add_argument("--register", type=Path)
    parser.add_argument("--campaign", default=os.environ.get("GITHUB_SHA", ""))
    parser.add_argument("--allow-open", action="store_true")
    parser.add_argument("--enforce", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    if args.artifacts is None or args.expect_shards is None:
        parser.error("--artifacts DIR and --expect-shards N are required")
    try:
        problems, counts = report(args)
    except (OSError, ValueError, KeyError, TypeError) as error:
        problems, counts = [f"cannot read the campaign: {error}"], Counter()
    print(
        "mutants: " + " ".join(f"{name}={counts[name]}" for name in OUTCOMES.values())
    )
    print("\n".join(problems + [f"mutants_report: {len(problems)} problem(s)"]))
    return int(args.enforce and bool(problems))


if __name__ == "__main__":
    sys.exit(main())
