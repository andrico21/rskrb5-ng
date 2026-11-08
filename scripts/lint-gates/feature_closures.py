#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
# How to run: python3 scripts/lint-gates/feature_closures.py list
"""Compute Cargo feature closures and canonical build arguments."""

from __future__ import annotations

import argparse
import itertools
import re
import shlex
import subprocess
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path

import common
from workflow_yaml import Line, children, only, scalar, structure, subtree


@dataclass(frozen=True, slots=True)
class Closure:
    features: frozenset[str]
    arguments: tuple[str, ...]

    @property
    def label(self) -> str:
        return ",".join(sorted(self.features)) or "(none)"


def resolve(features: dict[str, list[str]], seeds: frozenset[str]) -> frozenset[str]:
    """Follow only local feature edges."""
    result = set(seeds)
    pending = list(seeds)
    while pending:
        for edge in features[pending.pop()]:
            if edge in features and edge not in result:
                result.add(edge)
                pending.append(edge)
    return frozenset(result)


def compute(features: dict[str, list[str]]) -> list[Closure]:
    """Expand reachable unions, retaining shortest lexicographic generators."""
    generators: dict[frozenset[str], tuple[str, ...]] = {frozenset(): ()}
    for name in sorted(features):
        for closure, seeds in list(generators.items()):
            expanded = closure | resolve(features, frozenset({name}))
            candidate = (*seeds, name)
            prior = generators.get(expanded)
            if prior is None or (len(candidate), candidate) < (len(prior), prior):
                generators[expanded] = candidate
    default = (
        resolve(features, frozenset({"default"}))
        if "default" in features
        else frozenset()
    )
    result = []
    for closure, seeds in generators.items():
        if closure == frozenset(features):
            arguments = ("--all-features",)
        elif "default" in closure:
            candidates = [
                seed
                for part, seed in generators.items()
                if "default" not in part and part | default == closure
            ]
            extra = min(candidates, key=lambda seed: (len(seed), seed))
            arguments = ("--features", ",".join(extra)) if extra else ()
        else:
            arguments = ("--no-default-features",)
            if seeds:
                arguments += ("--features", ",".join(seeds))
        result.append(Closure(closure, arguments))
    return sorted(result, key=lambda value: (len(value.features), value.label))


def load(root: Path) -> list[Closure]:
    with (root / "Cargo.toml").open("rb") as stream:
        return compute(tomllib.load(stream)["features"])


CLIPPY_RUN = "cargo clippy --all-targets ${{ matrix.closures }} -- -D warnings"
TEST_RUN = "cargo test ${{ matrix.closures }}"
# Keys that can cap lints, swap the compiler or swallow a failing command:
# none may appear anywhere in the closures job.
JOB_FORBIDDEN = frozenset(
    {
        "continue-on-error",
        "if",
        "env",
        "defaults",
        "shell",
        "container",
        "working-directory",
    }
)
ACTIONS = ("actions/checkout@", "dtolnay/rust-toolchain@", "Swatinem/rust-cache@")
# Workflow-level variables Cargo or rustc read; only these harmless ones may be set.
CARGO_ENV_ALLOWED = frozenset(
    {"CARGO_TERM_COLOR", "CARGO_INCREMENTAL", "CARGO_NET_RETRY", "RUST_BACKTRACE"}
)


def check_workflow_scope(lines: list[Line], top: list[int]) -> None:
    """No workflow-level default or variable reaches the closures job's cargo."""
    for index in top:
        if lines[index].key == "defaults":
            raise RuntimeError(
                f"ci.yml:{lines[index].number}: a workflow `defaults:` reaches the closures job"
            )
        if lines[index].key == "env":
            for child in children(lines, index):
                name = lines[child].key or ""
                if name.startswith(("CARGO", "RUST")) and name not in CARGO_ENV_ALLOWED:
                    raise RuntimeError(
                        f"ci.yml:{lines[child].number}: workflow env {name} reaches the closures job"
                    )


def check_cargo_config(path: Path) -> None:
    """`.cargo/config.toml` keeps `build.warnings = "deny"` and adds no flags or wrapper."""
    try:
        config = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise RuntimeError(f"{path}: {error}") from error
    build = config.get("build", {})
    if build.get("warnings") != "deny":
        raise RuntimeError(
            f'{path}: build.warnings must be "deny", is {build.get("warnings")!r}'
        )
    for key in ("rustflags", "rustc-wrapper", "rustc-workspace-wrapper", "rustc"):
        if key in build:
            raise RuntimeError(
                f"{path}: build.{key} would change how the closures compile"
            )
    for name, table in config.get("target", {}).items():
        if isinstance(table, dict) and "rustflags" in table:
            raise RuntimeError(
                f"{path}: target.{name}.rustflags would change how the closures compile"
            )
    if any(name.startswith(("CARGO", "RUST")) for name in config.get("env", {})):
        raise RuntimeError(f"{path}: [env] sets a Cargo or rustc variable")


def ci_matrix(text: str) -> list[str]:
    """The closure arguments of `jobs.closures.strategy.matrix.closures`.

    The job is selected by its id, exactly once; no other `closures:` key may
    exist anywhere (a decoy job or matrix), the matrix holds nothing else
    (no `include`/`exclude`), and the job runs both strict steps on every leg
    with nothing that caps lints or swallows a failure: no `env`, `defaults`,
    `shell`, `container`, `working-directory`, `if` or `continue-on-error` in
    the job, no lint-relevant workflow `env` or `defaults`, and only the
    checkout, toolchain and cache actions.
    """
    lines = structure(text)
    top = [i for i, line in enumerate(lines) if line.indent == 0]
    if any(lines[i].item or lines[i].key is None for i in top):
        raise RuntimeError("ci.yml: the top level must be a mapping")
    jobs = only(lines, top, "jobs", "ci.yml")
    job = only(lines, children(lines, jobs), "closures", "jobs")
    strategy = only(lines, children(lines, job), "strategy", "jobs.closures")
    matrix = only(lines, children(lines, strategy), "matrix", "jobs.closures.strategy")
    keys = [lines[i].key for i in children(lines, matrix)]
    if keys != ["closures"]:
        raise RuntimeError(
            f"jobs.closures matrix must hold only `closures`, has {keys}"
        )
    key = children(lines, matrix)[0]
    if lines[key].value and not lines[key].value.startswith("#"):
        raise RuntimeError("the closures matrix must be a block list of strings")
    entries = []
    end = key + 1
    while end < len(lines) and (
        lines[end].indent > lines[key].indent
        or (lines[end].indent == lines[key].indent and lines[end].item)
    ):
        end += 1
    items = lines[key + 1 : end]
    if (
        any(not line.item or line.key is not None for line in items)
        or len({line.indent for line in items}) > 1
    ):
        raise RuntimeError("the closures matrix must be a flat list of strings")
    for line in items:
        entries.append(scalar(line.value, f"ci.yml:{line.number}"))
    stray = [
        line.number
        for line in lines
        if line.key == "closures" and line is not lines[job] and line is not lines[key]
    ]
    if stray:
        raise RuntimeError(
            f"ci.yml: another `closures:` key (decoy) on line(s) {stray}"
        )
    check_workflow_scope(lines, top)
    body = subtree(lines, job)
    for line in body:
        if line.key in JOB_FORBIDDEN:
            raise RuntimeError(
                f"ci.yml:{line.number}: the closures job may not use `{line.key}:`"
            )
        if line.key == "uses" and not scalar(line.value, "uses").startswith(ACTIONS):
            raise RuntimeError(
                f"ci.yml:{line.number}: the closures job may use only {ACTIONS}"
            )
    runs = [
        scalar(line.value, f"ci.yml:{line.number}")
        for line in body
        if line.key == "run"
    ]
    if runs != [CLIPPY_RUN, TEST_RUN]:
        raise RuntimeError(
            f"the closures job must run exactly {[CLIPPY_RUN, TEST_RUN]}, runs {runs}"
        )
    return entries


def check_ci(closures: list[Closure], path: Path) -> None:
    """Hold the real `closures` job's matrix equal to the computed closures."""
    values = ci_matrix(path.read_text())
    expected = [shlex.join(closure.arguments) for closure in closures]
    if len(values) != len(set(values)) or set(values) != set(expected):
        raise RuntimeError(
            f"closure matrix mismatch: expected {expected}, got {values}"
        )


def self_test() -> int:
    # Given cycles and dep-only edges, expansion must match brute force.
    features = {
        "default": ["a"],
        "a": ["b"],
        "b": ["a"],
        "evaluation": ["dep:serde"],
        "serde": [],
    }
    closures = compute(features)
    brute = {
        resolve(features, frozenset(subset))
        for size in range(len(features) + 1)
        for subset in itertools.combinations(features, size)
    }
    assert {closure.features for closure in closures} == brute
    assert resolve(features, frozenset({"evaluation"})) == frozenset({"evaluation"})
    for closure in closures:
        args = closure.arguments
        seeds = (
            frozenset(args[args.index("--features") + 1].split(","))
            if "--features" in args
            else frozenset()
        )
        if "--all-features" in args:
            seeds = frozenset(features)
        elif "--no-default-features" not in args:
            seeds |= {"default"}
        assert resolve(features, seeds) == closure.features
    assert sum(not closure.arguments for closure in closures) == 1
    from tempfile import TemporaryDirectory

    def job(
        entries: list[str],
        *,
        name: str = "closures",
        key: str = "closures:",
        runs: tuple[str, ...] = (CLIPPY_RUN, TEST_RUN),
    ) -> str:
        return (
            f"  {name}:\n    name: {name}\n    runs-on: ubuntu-latest\n"
            "    strategy:\n      fail-fast: false\n      matrix:\n"
            f"        # every closure\n        {key}\n"
            + "".join(f"          - {entry}\n" for entry in entries)
            + "    steps:\n      - uses: actions/checkout@v7 # pinned\n"
            + "".join(f"      - name: step\n        run: {run}\n" for run in runs)
        )

    quoted = [f'"{shlex.join(closure.arguments)}"' for closure in closures]
    head = "name: CI\non:\n  push:\njobs:\n  fmt:\n    runs-on: ubuntu-latest\n"
    script = (
        "  lint:\n    runs-on: ubuntu-latest\n    steps:\n      - run: |\n"
        "          closures:\n          - '--all-features'\n"
    )
    accepted = {
        "plain": head + job(quoted),
        "single-quoted, commented, unquoted and blank-separated entries": head
        + job(
            [f"'{value[1:-1]}'" for value in quoted[:-3]]
            + [
                quoted[-3] + "  # trailing comment\n\n          # comment line",
                quoted[-2],
            ]
            + [quoted[-1][1:-1] or '""']
        ).replace("      matrix:\n", "      matrix: # comment\n"),
        "quoted keys": head.replace("jobs:", '"jobs":')
        + job(quoted, key="'closures':").replace("  closures:\n", '  "closures":\n', 1),
        "a block scalar mentioning closures": head + script + job(quoted),
    }
    rejected = {
        "missing entry": head + job(quoted[1:]),
        "duplicate entry": head + job(quoted + quoted[:1]),
        "decoy job before, real matrix short": head
        + job(quoted, name="decoy")
        + job(quoted[1:]),
        "decoy matrix after": head + job(quoted) + job(quoted, name="decoy"),
        "duplicate closures job": head + job(quoted) + job(quoted),
        "no jobs mapping": job(quoted).replace("  ", "", 1),
        "exclude in the matrix": head
        + job(quoted).replace(
            "    steps:", "        exclude:\n          - other: x\n    steps:", 1
        ),
        "flow-style list": head
        + job([]).replace(
            "        closures:\n", "        closures: [" + ", ".join(quoted) + "]\n"
        ),
        "continue-on-error": head
        + job(quoted).replace("    steps:", "    continue-on-error: true\n    steps:"),
        "skipped step": head
        + job(quoted).replace(
            "        run: cargo test", "        if: false\n        run: cargo test"
        ),
        "no -D warnings": head
        + job(
            quoted, runs=("cargo clippy --all-targets ${{ matrix.closures }}", TEST_RUN)
        ),
        "no test step": head + job(quoted, runs=(CLIPPY_RUN,)),
        "tab indentation": head + job(quoted).replace("          - ", "\t- ", 1),
    }
    steps = "    steps:\n"
    for key in (
        r'"\u0069f"',
        r'"\x69f"',
        r'"\u0065nv"',
        r'"\u0073hell"',
        r'"\U00000069f"',
    ):
        rejected[f"escaped key {key}"] = head + job(quoted).replace(
            "        run: cargo test", f"        {key}: false\n        run: cargo test"
        )
    capped = '      RUSTFLAGS: "--cap-lints=allow"\n'
    rejected |= {
        "job env capping lints": head
        + job(quoted).replace(steps, "    env:\n" + capped + steps),
        "the fuzz-build env pair": head
        + job(quoted).replace(
            steps,
            '    env:\n      RUSTFLAGS: "--cap-lints=warn"\n      CARGO_BUILD_WARNINGS: allow\n'
            + steps,
        ),
        "step env": head
        + job(quoted).replace(
            "        run: cargo test",
            "        env:\n    " + capped + "        run: cargo test",
        ),
        "workflow env": head.replace(
            "jobs:", "env:\n  CARGO_BUILD_WARNINGS: allow\njobs:"
        )
        + job(quoted),
        "workflow env wrapper": head.replace(
            "jobs:", "env:\n  RUSTC_WRAPPER: /tmp/w\njobs:"
        )
        + job(quoted),
        "workflow defaults shell": head.replace(
            "jobs:", "defaults:\n  run:\n    shell: \"bash -c '{0} || true'\"\njobs:"
        )
        + job(quoted),
        "job defaults shell": head
        + job(quoted).replace(
            steps, "    defaults:\n      run:\n        shell: sh\n" + steps
        ),
        "step shell": head
        + job(quoted).replace(
            "        run: cargo test",
            "        shell: 'bash {0} || true'\n        run: cargo test",
        ),
        "container": head
        + job(quoted).replace(steps, "    container: rust:slim\n" + steps),
        "working directory": head
        + job(quoted).replace(
            "        run: cargo test",
            "        working-directory: fuzz\n        run: cargo test",
        ),
        "unknown action": head
        + job(quoted).replace(
            steps + "      - uses: actions/checkout@v7 # pinned\n",
            steps + "      - uses: someone/set-rustflags@v1\n",
        ),
    }
    with TemporaryDirectory() as directory:
        path = Path(directory) / "ci.yml"
        for label, text in accepted.items():
            path.write_text(text)
            check_ci(closures, path)
            assert ci_matrix(text), label
        for label, text in rejected.items():
            path.write_text(text)
            try:
                check_ci(closures, path)
            except RuntimeError:
                pass
            else:
                raise AssertionError(f"check-ci accepted: {label}")
        config = Path(directory) / "config.toml"
        accepted_configs = (
            '[build]\nwarnings = "deny"\n',
            '[build]\nwarnings = "deny"\nedition = "2024"\n[alias]\nxtask = "run"\n',
        )
        rejected_configs = (
            "",
            '[build]\nwarnings = "allow"\n',
            '[build]\nwarnings = "deny"\nrustflags = ["--cap-lints=allow"]\n',
            '[build]\nwarnings = "deny"\n[target.x86_64-unknown-linux-gnu]\nrustflags = ["--cap-lints", "allow"]\n',
            '[build]\nwarnings = "deny"\nrustc-wrapper = "/tmp/w"\n',
            '[build]\nwarnings = "deny"\n[env]\nRUSTFLAGS = "--cap-lints=allow"\n',
        )
        for text in accepted_configs:
            config.write_text(text)
            check_cargo_config(config)
        for text in rejected_configs:
            config.write_text(text)
            try:
                check_cargo_config(config)
            except RuntimeError:
                pass
            else:
                raise AssertionError(f"check-ci accepted .cargo/config.toml: {text!r}")
    print(
        f"feature_closures self-test: ok (check-ci: {len(accepted)} workflows "
        f"accepted, {len(rejected)} rejected)"
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--root", type=Path, default=common.ROOT)
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("list")
    run = sub.add_parser("run")
    mode = run.add_mutually_exclusive_group()
    mode.add_argument("--clippy-only", action="store_true")
    mode.add_argument("--test-only", action="store_true")
    sub.add_parser("check-ci").add_argument("workflow", type=Path)
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    closures = load(args.root)
    if args.command == "list":
        for closure in closures:
            print(closure.label + "\t" + shlex.join(closure.arguments))
    elif args.command == "check-ci":
        check_ci(closures, args.workflow)
        check_cargo_config(args.root / ".cargo/config.toml")
    elif args.command == "run":
        failures = 0
        for closure in closures:
            commands = []
            if not args.test_only:
                commands.append(
                    [
                        "clippy",
                        "--all-targets",
                        *closure.arguments,
                        "--",
                        "-D",
                        "warnings",
                    ]
                )
            if not args.clippy_only:
                commands.append(["test", *closure.arguments])
            for command in commands:
                print(f"{closure.label}: cargo {shlex.join(command)}", flush=True)
                failures += (
                    subprocess.run(
                        ["flock", "/tmp/rskrb5-cargo.lock", "cargo", *command],
                        cwd=args.root,
                    ).returncode
                    != 0
                )
        return int(bool(failures))
    else:
        parser.error("choose list, run or check-ci")
    return 0


if __name__ == "__main__":
    sys.exit(main())
