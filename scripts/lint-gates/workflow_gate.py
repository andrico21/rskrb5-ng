#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
# How to run: python3 scripts/lint-gates/workflow_gate.py --enforce
"""Hold the CI wiring of the gates and the release toolchain pin.

* The `lint-gates` job of `ci.yml` and the `lint-gates` hook of `prek.toml`
  each run every command in `REQUIRED`: the gate self-tests and enforcements,
  the error-variant construction audit with its self-test, and the offline
  self-tests of the AD dispatch helper, the AD preflight, the
  fixture runner and the release script. The job may not be skipped or allowed
  to fail.
* Every action is pinned to a full commit SHA, each `dtolnay/rust-toolchain`
  channel (`# stable`, `# master`, `# nightly`) to one SHA across all
  workflows, and the release workflows set up their toolchain only with the
  `# stable` revision CI exercises.
"""

from __future__ import annotations

import argparse
import re
import shlex
import json
import sys
import tomllib
from pathlib import Path
from contextlib import redirect_stdout
from io import StringIO
from tempfile import TemporaryDirectory
from typing import Final

ROOT: Final = Path(__file__).resolve().parents[2]
REQUIRED: Final = (
    'for s in scripts/lint-gates/*.py scripts/check-error-constructions.py; do python3 "$s" --self-test',
    "python3 scripts/lint-gates/allow_gate.py --enforce",
    "python3 scripts/lint-gates/exception_gate.py --enforce",
    "python3 scripts/lint-gates/profile_eq.py --clippy-toml",
    "python3 scripts/lint-gates/completeness_check.py",
    "python3 scripts/lint-gates/facade_gate.py --enforce",
    "python3 scripts/lint-gates/prose_gate.py --enforce",
    "python3 scripts/lint-gates/feature_closures.py check-ci .github/workflows/ci.yml",
    "python3 scripts/lint-gates/fuzz_lint.py --enforce",
    "python3 scripts/lint-gates/fuzz_coverage.py --enforce",
    "python3 scripts/lint-gates/gate_hygiene.py --enforce",
    "python3 scripts/lint-gates/workflow_gate.py --enforce",
    "python3 scripts/check-error-constructions.py",
    "python3 scripts/check-config-relations.py --self-test",
    "python3 scripts/check-config-relations.py",
    "python3 scripts/lint-gates/package_links.py --enforce",
    "python3 scripts/check-github-ad-gate.py --self-test",
    "python3 scripts/check-ad-integration-env-smoke.py",
    "bash scripts/run-gated-integration.sh self-test",
    "bash scripts/release-publish.sh self-test",
    "lint-migration src tests examples fuzz",
)
RELEASE_WORKFLOWS: Final = ("release.yml", "publish.yml")
USES: Final = re.compile(
    r"^\s*(?:-\s+)?uses:\s*([\w.-]+/[\w./-]+)@(\S+)(?:\s+#\s*(\S+))?"
)

SELF_TEST_LOOP: Final = REQUIRED[0] + " || exit 1; done"
CI_NEGATIVE: Final = (
    "grep -rn lint-migration src tests examples fuzz && exit 1\ntest $? -eq 1"
)
HOOK_NEGATIVE: Final = (
    "{ rg -n lint-migration src tests examples fuzz; test $? -eq 1; }"
)


def run_blocks(job: str) -> list[str]:
    """Read only run scalars at step indentation; reject unsupported scalar forms."""
    lines = job.splitlines()
    blocks = []
    for index, line in enumerate(lines):
        match = re.fullmatch(r"(?:      - |        )run: (.*)", line)
        if not match:
            continue
        value = match[1]
        if value == "|":
            body = []
            for following in lines[index + 1 :]:
                if following.strip() and not following.startswith("          "):
                    break
                body.append(following[10:])
            value = "\n".join(body).strip()
        blocks.append(value)
    return blocks


def effective_commands(blocks: list[str], hook: bool = False) -> set[str]:
    """Accept only the documented fail-closed command grammar, never shell substrings."""
    accepted = set()
    for block in blocks:
        if hook:
            try:
                argv = shlex.split(block)
            except ValueError:
                continue
            if len(argv) != 3 or argv[:2] != ["bash", "-c"]:
                continue
            script = argv[2]
            prefix = "export PYTHONDONTWRITEBYTECODE=1; "
            if not script.startswith(prefix):
                continue
            script = script[len(prefix) :]
            script = script.replace(SELF_TEST_LOOP, "SELF_TEST_LOOP").replace(
                HOOK_NEGATIVE, "NEGATIVE_SEARCH"
            )
            commands = script.split(" && ")
        else:
            commands = [
                block.replace(SELF_TEST_LOOP, "SELF_TEST_LOOP").replace(
                    CI_NEGATIVE, "NEGATIVE_SEARCH"
                )
            ]
        mapped = []
        for command in commands:
            if command == "SELF_TEST_LOOP":
                mapped.append(REQUIRED[0])
            elif command == "NEGATIVE_SEARCH":
                mapped.append(REQUIRED[-1])
            elif command in REQUIRED[1:-1]:
                mapped.append(command)
            else:
                mapped = []
                break
        accepted.update(mapped)
    return accepted


def job_text(workflow: str, job: str) -> str:
    """The job's lines without comment lines; empty when the job is absent."""
    lines = workflow.splitlines()
    try:
        start = lines.index(f"  {job}:")
    except ValueError:
        return ""
    body = []
    for line in lines[start + 1 :]:
        if (
            line.strip()
            and not line.startswith("   ")
            and not line.lstrip().startswith("#")
        ):
            break
        if not line.lstrip().startswith("#"):
            body.append(line)
    return "\n".join(body)


def wiring_errors(workflow: str, prek: str) -> list[str]:
    errors = []
    job = job_text(workflow, "lint-gates")
    if not job:
        errors.append("ci.yml has no lint-gates job")
    for key in (
        "continue-on-error:",
        "if:",
        "shell:",
        "defaults:",
        "working-directory:",
    ):
        if re.search(rf"(?m)^\s+(?:-\s+)?{re.escape(key)}", job):
            errors.append(f"the lint-gates job may not use `{key}`")
    if re.search(r"(?m)^defaults:", workflow):
        errors.append("workflow defaults may not alter gate execution")
    if re.search(r"(?m)^        (?!run:)[\w-]+: [|>]", job):
        errors.append("non-run multiline step values are unsupported in lint-gates")
    hooks = [
        hook
        for repo in tomllib.loads(prek).get("repos", [])
        for hook in repo.get("hooks", [])
        if hook.get("id") == "lint-gates"
    ]
    entry = hooks[0].get("entry", "") if len(hooks) == 1 else ""
    if len(hooks) != 1:
        errors.append(f"prek.toml needs exactly one lint-gates hook, has {len(hooks)}")
    ci_commands = effective_commands(run_blocks(job))
    hook_commands = effective_commands([entry], hook=True)
    for command in REQUIRED:
        if command not in ci_commands:
            errors.append(f"ci.yml lint-gates does not run `{command}`")
        if command not in hook_commands:
            errors.append(f"prek.toml lint-gates does not run `{command}`")
    return errors


def pin_errors(workflows: dict[str, str]) -> list[str]:
    errors = []
    channels: dict[str, set[str]] = {}
    for name, text in sorted(workflows.items()):
        for number, line in enumerate(text.splitlines(), 1):
            match = USES.match(line)
            if match is None:
                continue
            action, ref, comment = match.groups()
            if not re.fullmatch(r"[0-9a-f]{40}", ref):
                errors.append(
                    f"{name}:{number}: {action} is not pinned to a commit SHA"
                )
            if action == "dtolnay/rust-toolchain":
                channels.setdefault(comment or "(no channel comment)", set()).add(ref)
                if name in RELEASE_WORKFLOWS and comment != "stable":
                    errors.append(
                        f"{name}:{number}: the release toolchain must use CI's "
                        f"`# stable` dtolnay/rust-toolchain revision, not `# {comment}`"
                    )
    for channel, refs in sorted(channels.items()):
        if len(refs) > 1:
            errors.append(
                f"dtolnay/rust-toolchain `# {channel}` is pinned to {sorted(refs)}"
            )
    return errors


def check(root: Path) -> list[str]:
    workflows = {
        path.name: path.read_text(encoding="utf-8")
        for path in sorted((root / ".github/workflows").glob("*.yml"))
    }
    link_errors = []
    docs = job_text(workflows.get("ci.yml", ""), "docs-validate")
    if not any(
        "args:" in line
        and "--offline" in line
        and "--include-fragments" in line
        and "'docs/**/*.md'" in line
        for line in docs.splitlines()
    ):
        link_errors.append(
            "docs-validate must check nested Markdown offline with fragments"
        )
    return (
        link_errors
        + wiring_errors(
            workflows.get("ci.yml", ""),
            (root / "prek.toml").read_text(encoding="utf-8"),
        )
        + pin_errors(workflows)
    )


def self_test() -> int:
    actual_ci = (ROOT / ".github/workflows/ci.yml").read_text()
    assert "'docs/**/*.md'" in job_text(actual_ci, "docs-validate"), (
        "nested docs omitted"
    )
    commands = [SELF_TEST_LOOP, *REQUIRED[1:-1]]
    run = "".join(f"      - run: {command}\n" for command in commands)
    run += (
        "      - run: |\n          " + CI_NEGATIVE.replace("\n", "\n          ") + "\n"
    )
    ci = (
        "jobs:\n  lint-gates:\n    runs-on: ubuntu-latest\n    steps:\n"
        + run
        + "  next:\n    steps: []\n"
    )
    prek = (
        '[[repos]]\nrepo = "local"\nhooks = [{ id = "lint-gates", entry = '
        + json.dumps(
            "bash -c 'export PYTHONDONTWRITEBYTECODE=1; "
            + " && ".join([*commands, HOOK_NEGATIVE])
            + "'"
        )
        + " }]\n"
    )
    assert wiring_errors(ci, prek) == [], wiring_errors(ci, prek)
    for wrapper in [
        "echo '{command}'",
        "printf '%s' '{command}'",
        "# {command}",
        "if false; then {command}; fi",
        "{command} || true",
        "cat <<'EOF'\n{command}\nEOF",
    ]:
        fake = ci.replace(
            "run: " + REQUIRED[1], "run: " + wrapper.format(command=REQUIRED[1])
        )
        assert wiring_errors(fake, prek), wrapper
        fake_hook = prek.replace(
            REQUIRED[1],
            wrapper.format(command=REQUIRED[1])
            .replace('"', '\\"')
            .replace("\n", "\\n"),
        )
        assert wiring_errors(ci, fake_hook), wrapper
    ad = "python3 scripts/check-ad-integration-env-smoke.py"
    dropped = ci.replace(f"      - run: {ad}\n", f"      # - run: {ad}\n")
    assert wiring_errors(dropped, prek) == [f"ci.yml lint-gates does not run `{ad}`"]
    assert f"prek.toml lint-gates does not run `{ad}`" in wiring_errors(
        ci, prek.replace(ad, "true")
    )
    advisory = ci.replace(
        "    steps:\n", "    continue-on-error: true\n    steps:\n", 1
    )
    assert wiring_errors(advisory, prek) == [
        "the lint-gates job may not use `continue-on-error:`"
    ]
    sha = "a" * 40
    other = "b" * 40
    stable = f"      - uses: dtolnay/rust-toolchain@{sha} # stable\n"
    assert pin_errors({"ci.yml": stable, "publish.yml": stable}) == []
    assert pin_errors(
        {"ci.yml": stable, "publish.yml": stable.replace(sha, other)}
    ) == [f"dtolnay/rust-toolchain `# stable` is pinned to {sorted([sha, other])}"]
    master = f"      - uses: dtolnay/rust-toolchain@{other} # master\n"
    assert len(pin_errors({"ci.yml": stable + master, "release.yml": master})) == 1
    assert pin_errors({"ci.yml": "      - uses: actions/checkout@v7\n"}) == [
        "ci.yml:1: actions/checkout is not pinned to a commit SHA"
    ]
    with TemporaryDirectory() as directory:
        root = Path(directory)
        (root / ".github/workflows").mkdir(parents=True)
        (root / ".github/workflows/ci.yml").write_text(ci + stable)
        (root / ".github/workflows/publish.yml").write_text(master)
        (root / "prek.toml").write_text(prek)
        with redirect_stdout(StringIO()):
            assert main(["--root", str(root)]) == 0
            assert main(["--enforce", "--root", str(root)]) == 1
    print(
        "workflow_gate self-test: ok (dropped and advisory wiring, split and release pins, unpinned action)"
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
    try:
        errors = check(args.root)
    except (OSError, tomllib.TOMLDecodeError) as error:
        errors = [str(error)]
    print("\n".join(errors + [f"workflow_gate: {len(errors)} problem(s)"]))
    return int(args.enforce and bool(errors))


if __name__ == "__main__":
    sys.exit(main())
