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
from workflow_shape import mandatory_runs
from workflow_yaml import structure, children, only, subtree
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
USES: Final = re.compile(r"([\w.-]+/[\w./-]+)@([^\s]+)(?:\s+#\s*(\S+))?")

SELF_TEST_LOOP: Final = REQUIRED[0] + " || exit 1; done"
CI_NEGATIVE: Final = (
    "grep -rn lint-migration src tests examples fuzz && exit 1\ntest $? -eq 1"
)
HOOK_NEGATIVE: Final = (
    "{ rg -n lint-migration src tests examples fuzz; test $? -eq 1; }"
)


def effective_commands(blocks: list[str], hook: bool = False) -> set[str]:
    """Accept only the documented fail-closed command grammar, never shell substrings."""
    accepted = set()
    for block in blocks:
        if "SELF_TEST_LOOP" in block or "NEGATIVE_SEARCH" in block:
            continue
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
    blocks: list[str] = []
    try:
        blocks = mandatory_runs(workflow, "lint-gates")
        for block in blocks:
            if not effective_commands([block]):
                errors.append("lint-gates contains an unapproved run block")
    except RuntimeError as error:
        errors.append(str(error))
    hook_config = tomllib.loads(prek)
    if any(key in hook_config for key in ("files", "exclude")):
        errors.append("global hook file filters may not suppress lint gates")
    hooks = [
        hook
        for repo in hook_config.get("repos", [])
        for hook in repo.get("hooks", [])
        if hook.get("id") == "lint-gates"
    ]
    entry = hooks[0].get("entry", "") if len(hooks) == 1 else ""
    if len(hooks) != 1:
        errors.append(f"prek.toml needs exactly one lint-gates hook, has {len(hooks)}")
    else:
        hook = hooks[0]
        expected = {
            "language": "system",
            "pass_filenames": False,
            "stages": ["pre-push", "manual"],
            "files": r"\.(rs|toml|py|yml|md)$",
        }
        if any(hook.get(key) != value for key, value in expected.items()):
            errors.append("lint-gates hook must retain its pre-push applicability")
        if set(hook) - {"id", "name", "entry", *expected}:
            errors.append("unsupported lint-gates hook applicability setting")
    ci_commands = effective_commands(blocks)
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
        try:
            lines = structure(text)
        except RuntimeError as error:
            errors.append(f"{name}: {error}")
            continue
        for line in lines:
            if line.key != "uses":
                continue
            number = line.number
            match = USES.fullmatch(line.value)
            if match is None:
                errors.append(f"{name}:{number}: unsupported action reference")
                continue
            action, ref, comment = match.groups()
            if not re.fullmatch(r"[0-9a-f]{40}", ref):
                errors.append(
                    f"{name}:{number}: {action} is not pinned to a commit SHA"
                )
            elif comment is None:
                errors.append(f"{name}:{number}: action pin needs a version comment")
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
    try:
        ci = workflows.get("ci.yml", "")
        runs = mandatory_runs(ci, "docs-validate")
        if runs != ["(cd docs/rust-guidelines && sha256sum -c SHA256SUMS)"]:
            raise RuntimeError(
                "docs-validate must execute the guideline checksum check"
            )
        lines = structure(ci)
        top = [i for i, line in enumerate(lines) if line.indent == 0]
        jobs = only(lines, top, "jobs", "ci.yml")
        docs = only(lines, children(lines, jobs), "docs-validate", "jobs")
        steps = [
            line.value.split("@", 1)[0] if line.key == "uses" else "checksum"
            for line in subtree(lines, docs)
            if line.key in {"uses", "run"}
        ]
        if steps != ["actions/checkout", "checksum", "lycheeverse/lychee-action"]:
            raise RuntimeError(
                "docs-validate needs checkout, checksum and mandatory lychee scan in order"
            )
    except RuntimeError as error:
        link_errors.append(str(error))
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
        + ', language = "system", pass_filenames = false, stages = ["pre-push", "manual"], files = "\\\\.(rs|toml|py|yml|md)$" }]\n'
    )
    assert wiring_errors(ci, prek) == [], wiring_errors(ci, prek)
    assert wiring_errors(
        ci.replace("    steps:\n", "    needs: mutants\n    steps:\n", 1), prek
    ), "skippable prerequisite admitted"
    for variable in ("BASH_ENV", "PYTHONOPTIMIZE", "PYTHONPATH", "PATH", "LD_PRELOAD"):
        for position in ("    steps:\n", "      - run: " + REQUIRED[2] + "\n"):
            extra = f'      - run: echo "{variable}=hostile" >> "$GITHUB_ENV"\n'
            hostile = ci.replace(position, position + extra, 1)
            assert wiring_errors(hostile, prek), (
                f"extra environment step accepted: {variable}"
            )
    assert wiring_errors(
        ci.replace(
            "    steps:\n",
            '    steps:\n      - run: echo /tmp/bin >> "$GITHUB_PATH"\n',
            1,
        ),
        prek,
    ), "extra PATH step accepted"
    actual_prek = (ROOT / "prek.toml").read_text()
    for before, after in (
        ('stages = ["pre-push", "manual"]', 'stages = ["manual"]'),
        ('id = "lint-gates"', 'id = "lint-gates"\nexclude = ".*"'),
        ('id = "lint-gates"', 'id = "lint-gates"\ntypes = ["python"]'),
        ('id = "lint-gates"', 'id = "lint-gates"\ntypes_or = ["python"]'),
        ('id = "lint-gates"', 'id = "lint-gates"\nexclude_types = ["rust"]'),
        ('id = "lint-gates"', 'id = "lint-gates"\nalways_run = false'),
        ('files = "\\\\.(rs|toml|py|yml|md)$"', 'files = "never-match"'),
        ('language = "system"', 'language = "fail"'),
        ("pass_filenames = false", "pass_filenames = true"),
    ):
        hostile = actual_prek.replace(before, after)
        assert wiring_errors(actual_ci, hostile), f"suppressed hook accepted: {after}"
    for setting in ('exclude = ".*"', 'files = "never-match"'):
        assert wiring_errors(actual_ci, setting + "\n" + actual_prek), setting
    for setting in (
        "container: ubuntu:24.04",
        "container:\n      image: ubuntu:24.04\n      options: --env PYTHONOPTIMIZE=1",
        "container:\n      image: ubuntu:24.04\n      options: --env BASH_ENV=/tmp/skip-gates",
        "services:\n      helper:\n        image: ubuntu:24.04\n        options: --privileged",
        "options: --env PYTHONOPTIMIZE=1",
        "'container': {image: ubuntu:24.04, options: '--env PYTHONOPTIMIZE=1'}",
    ):
        hostile = ci.replace("    steps:\n", f"    {setting}\n    steps:\n", 1)
        assert wiring_errors(hostile, prek), (
            f"container execution override accepted: {setting}"
        )
    for key in (
        r'"\u0069f"',
        r'"\x69f"',
        r'"\u0065nv"',
        r'"\u0073hell"',
        r'"\U00000069f"',
    ):
        hostile = ci.replace(
            "      - run: " + REQUIRED[1],
            "      - " + key + ": false\n        run: " + REQUIRED[1],
        )
        assert wiring_errors(hostile, prek), f"escaped execution key accepted: {key}"
    for key in ("shell", "defaults", '"shell"', '"defaults"'):
        for hostile in (
            f"{key}: hostile\n" + ci,
            ci.replace("    steps:\n", f"    {key}: hostile\n    steps:\n", 1),
            ci.replace(
                "      - run: " + REQUIRED[1],
                f"      - {key}: hostile\n        run: " + REQUIRED[1],
            ),
        ):
            assert wiring_errors(hostile, prek), f"execution override accepted: {key}"
    for variable in (
        "BASH_ENV",
        "PYTHONOPTIMIZE",
        "PATH",
        "PYTHONPATH",
        "ENV",
        "SHELL",
    ):
        for hostile in (
            f"env:\n  {variable}: hostile\n" + ci,
            ci.replace(
                "    steps:\n", f"    env:\n      {variable}: hostile\n    steps:\n", 1
            ),
            ci.replace(
                "      - run: " + REQUIRED[1],
                f"      - env:\n          {variable}: hostile\n        run: "
                + REQUIRED[1],
            ),
        ):
            assert wiring_errors(hostile, prek), (
                f"interpreter override accepted: {variable}"
            )
    for key in [
        '"if"',
        "'if'",
        '"continue-on-error"',
        '"shell"',
        '"defaults"',
        '"working-directory"',
    ]:
        hostile = ci.replace(
            "      - run: " + REQUIRED[1],
            "      - " + key + ": false\n        run: " + REQUIRED[1],
        )
        assert wiring_errors(hostile, prek), f"quoted execution key accepted: {key}"
    assert wiring_errors(
        ci.replace("  next:", "    steps:\n      - run: true\n  next:"), prek
    ), "duplicate steps accepted"
    assert wiring_errors(ci.replace(SELF_TEST_LOOP, "SELF_TEST_LOOP"), prek)
    assert wiring_errors(
        ci.replace(
            "      - run: " + REQUIRED[1],
            "      - run: " + REQUIRED[1] + "\n        run: echo skipped",
        ),
        prek,
    )
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
    assert any("continue-on-error" in error for error in wiring_errors(advisory, prek))
    sha = "a" * 40
    for key in ('"uses"', "'uses'"):
        assert pin_errors({"release.yml": f"      - {key}: actions/checkout@v7\n"}), (
            "quoted unpinned action admitted"
        )
        assert (
            pin_errors({"release.yml": f"      - {key}: actions/checkout@{sha} # v7\n"})
            == []
        )
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
