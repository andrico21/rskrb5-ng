#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
# How to run: python3 scripts/lint-gates/workflow_shape.py --self-test
"""Allow-listed execution shapes shared by the two mandatory CI jobs.

This is deliberately a YAML subset, not a permissive YAML implementation.
Only known mapping keys, literal run scalars and pinned setup actions enter
the execution model. Unsupported syntax fails before command certification.
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from typing import Final

from workflow_yaml import Line, children, scalar, structure

PIN: Final = re.compile(r"([\w.-]+/[\w./-]+)@([0-9a-f]{40})\s+#\s+(\S+)")
ROOT_KEYS: Final = frozenset({"name", "on", "permissions", "env", "jobs"})
JOB_KEYS: Final = frozenset({"name", "runs-on", "env", "steps", "strategy"})


@dataclass(frozen=True, slots=True)
class Mapping:
    """Validated mapping keys with their structural source indexes."""

    entries: dict[str, int]


def mapping(lines: list[Line], indexes: list[int], allowed: frozenset[str]) -> Mapping:
    entries: dict[str, int] = {}
    if indexes and len({lines[i].indent for i in indexes}) != 1:
        raise RuntimeError("inconsistent mapping indentation")
    for index in indexes:
        line = lines[index]
        if not line.plain_key or line.key not in allowed or line.key in entries:
            raise RuntimeError(
                f"ci.yml:{line.number}: unknown, non-plain or duplicate key {line.key!r}"
            )
        if line.key is None:
            raise RuntimeError(f"ci.yml:{line.number}: expected mapping key")
        entries[line.key] = index
    return Mapping(entries)


def block(lines: list[Line], index: int) -> list[int]:
    line = lines[index]
    if line.value and not line.value.startswith("#"):
        raise RuntimeError(
            f"ci.yml:{line.number}: {line.key} must be a block mapping/list"
        )
    return children(lines, index)


def environment(lines: list[Line], index: int, workflow: bool) -> None:
    allowed = {"PYTHONDONTWRITEBYTECODE": "1"}
    if workflow:
        allowed["CARGO_TERM_COLOR"] = "always"
    settings = mapping(lines, block(lines, index), frozenset(allowed)).entries
    for key, child in settings.items():
        if (
            children(lines, child)
            or scalar(lines[child].value, "environment") != allowed[key]
        ):
            raise RuntimeError(f"ci.yml:{lines[child].number}: environment override")


def run_value(text: str, line: Line) -> str:
    """Read the literal block with exactly the indentation GitHub will execute."""
    if line.value != "|":
        if line.value.startswith(("'", '"', ">", "|", "[", "{", "!", "&", "*")):
            raise RuntimeError(
                f"ci.yml:{line.number}: run must be plain or a literal block"
            )
        return line.value
    body = []
    for raw in text.splitlines()[line.number :]:
        if raw.strip() and len(raw) - len(raw.lstrip(" ")) <= line.indent:
            break
        if raw.strip() and not raw.startswith(" " * (line.indent + 2)):
            raise RuntimeError(f"ci.yml:{line.number}: unsupported run indentation")
        body.append(raw[line.indent + 2 :])
    return "\n".join(body).strip()


def setup(lines: list[Line], fields: Mapping, job: str) -> None:
    index = fields.entries["uses"]
    match = PIN.fullmatch(lines[index].value)
    if match is None:
        raise RuntimeError(
            f"ci.yml:{lines[index].number}: setup needs SHA and version comment"
        )
    action, _, channel = match.groups()
    allowed: dict[str, str] = {}
    if action == "dtolnay/rust-toolchain" and channel in {"stable", "master"}:
        allowed = {"components": "clippy"}
        if channel == "master" and job == "lint-gates":
            allowed["toolchain"] = "nightly-2026-10-03"
    elif action == "Swatinem/rust-cache" and job == "closures":
        allowed = {"key": "closure-${{ strategy.job-index }}"}
    elif action != "actions/checkout":
        raise RuntimeError(
            f"ci.yml:{lines[index].number}: unapproved setup action/channel"
        )
    if "with" in fields.entries:
        inputs = mapping(
            lines, block(lines, fields.entries["with"]), frozenset(allowed)
        ).entries
        for key, child in inputs.items():
            if (
                children(lines, child)
                or scalar(lines[child].value, "action input") != allowed[key]
            ):
                raise RuntimeError(
                    f"ci.yml:{lines[child].number}: unapproved setup input"
                )
    elif action == "dtolnay/rust-toolchain" and channel == "master":
        raise RuntimeError("dated nightly setup requires explicit toolchain input")


def mandatory_runs(text: str, job: str) -> list[str]:
    """Validate the entire execution surface before returning any run commands."""
    lines = structure(text)
    top = [i for i, line in enumerate(lines) if line.indent == 0]
    root = mapping(lines, top, ROOT_KEYS).entries
    if "jobs" not in root:
        raise RuntimeError("workflow needs jobs")
    if "env" in root:
        environment(lines, root["env"], True)
    job_indexes = block(lines, root["jobs"])
    jobs = mapping(
        lines, job_indexes, frozenset(line.key for line in lines if line.key)
    ).entries
    if job not in jobs:
        raise RuntimeError(f"workflow needs {job}")
    fields = mapping(lines, block(lines, jobs[job]), JOB_KEYS).entries
    if "steps" not in fields or "runs-on" not in fields:
        raise RuntimeError(f"{job} needs steps and runs-on")
    for key in ("name", "runs-on"):
        if key in fields and children(lines, fields[key]):
            raise RuntimeError(f"{job}: unexpected nested {key}")
    if scalar(lines[fields["runs-on"]].value, "runs-on") != "ubuntu-latest":
        raise RuntimeError(f"{job} must run on ubuntu-latest")
    if "env" in fields:
        if job != "lint-gates":
            raise RuntimeError("closures may not override its environment")
        environment(lines, fields["env"], False)
    if "strategy" in fields:
        if job != "closures":
            raise RuntimeError("lint-gates may not use a matrix")
        strategy = mapping(
            lines, block(lines, fields["strategy"]), frozenset({"fail-fast", "matrix"})
        ).entries
        if "matrix" not in strategy or "fail-fast" not in strategy:
            raise RuntimeError("closures needs matrix and fail-fast")
        if lines[strategy["fail-fast"]].value != "false":
            raise RuntimeError("closures must not cancel other matrix legs")
        matrix = mapping(
            lines, block(lines, strategy["matrix"]), frozenset({"closures"})
        ).entries
        if set(matrix) != {"closures"}:
            raise RuntimeError("closures needs exactly its closure matrix")
        block(lines, matrix["closures"])
    step_indexes = block(lines, fields["steps"])
    groups: list[list[int]] = []
    for index in step_indexes:
        if lines[index].item:
            groups.append([])
        if not groups:
            raise RuntimeError("steps must be a list of mappings")
        groups[-1].append(index)
    runs = []
    for group in groups:
        step = mapping(lines, group, frozenset({"name", "run", "uses", "with"}))
        keys = step.entries.keys()
        if ("run" in keys) == ("uses" in keys) or ("run" in keys and "with" in keys):
            raise RuntimeError("each step needs exactly one run or uses")
        for key, index in step.entries.items():
            if key != "with" and children(lines, index):
                raise RuntimeError(
                    f"ci.yml:{lines[index].number}: unexpected nested {key}"
                )
        if "run" in keys:
            runs.append(run_value(text, lines[step.entries["run"]]))
        else:
            if runs:
                raise RuntimeError("setup actions must precede all run steps")
            setup(lines, step, job)
    return runs


def self_test() -> int:
    text = "jobs:\n  lint-gates:\n    runs-on: ubuntu-latest\n    steps:\n      - run: true\n"
    assert mandatory_runs(text, "lint-gates") == ["true"]
    for job in ("lint-gates", "closures"):
        for condition in (
            "needs: mutants",
            "needs: [mutants]",
            "needs:\n      - mutants",
            "needs: mutants\n    if: success()",
            "needs: mutants\n    if: always() && needs.mutants.result == 'success'",
            "if: always()",
            "if: cancelled()",
            "if: failure()",
        ):
            hostile = text.replace("lint-gates", job).replace(
                "    steps:", f"    {condition}\n    steps:"
            )
            try:
                mandatory_runs(hostile, job)
            except RuntimeError:
                pass
            else:
                raise AssertionError(
                    f"conditional mandatory job admitted: {job}: {condition}"
                )
    for extra in (
        "unknown: x",
        "shell: bash",
        "container: ubuntu",
        '"env": {}',
        "steps: []",
    ):
        try:
            mandatory_runs(
                text.replace("    steps:", f"    {extra}\n    steps:"), "lint-gates"
            )
        except RuntimeError:
            pass
        else:
            raise AssertionError(extra)
    print("workflow_shape self-test: ok")
    return 0


if __name__ == "__main__":
    sys.exit(self_test() if "--self-test" in sys.argv else 2)
