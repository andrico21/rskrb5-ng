#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
# How to run: python3 scripts/lint-gates/workflow_regressions.py --self-test
"""Cross-round workflow bypass fixtures against the real CI admission boundary."""

import sys
from pathlib import Path

import feature_closures
import workflow_gate


def self_test() -> int:
    root = Path(__file__).resolve().parents[2]
    ci = (root / ".github/workflows/ci.yml").read_text()
    prek = (root / "prek.toml").read_text()
    assert workflow_gate.wiring_errors(ci, prek) == []
    assert len(feature_closures.ci_matrix(ci)) == 36
    gate = "python3 scripts/lint-gates/allow_gate.py --enforce"
    fixtures = {
        "fb19af4/U6-09 echo": ci.replace("run: " + gate, "run: echo '" + gate + "'"),
        "fb19af4/U6-09 swallowed failure": ci.replace(
            "run: " + gate, "run: " + gate + " || true"
        ),
        "f22ea5b/U6-01 quoted condition": ci.replace(
            "run: " + gate, '"if": false\n        run: ' + gate
        ),
        "f22ea5b/U6-01 duplicate steps": ci.replace(
            "  fuzz-build:", "    steps:\n      - run: true\n  fuzz-build:"
        ),
        "f22ea5b/U6-05 startup env": ci.replace(
            'PYTHONDONTWRITEBYTECODE: "1"',
            'PYTHONDONTWRITEBYTECODE: "1"\n      BASH_ENV: /tmp/skip',
        ),
        "b8d23a5/U6-01 escaped condition": ci.replace(
            "run: " + gate, r'"\u0069f": false' + "\n        run: " + gate
        ),
        "b8d23a5/U6-02 container options": ci.replace(
            "    name: lint-gates",
            "    container:\n      image: ubuntu:24.04\n      options: --env PYTHONOPTIMIZE=1\n    name: lint-gates",
        ),
        "87d6d5f/U6-01 runtime env": ci.replace(
            "      - name: Allow gate",
            '      - run: echo "BASH_ENV=/tmp/skip" >> "$GITHUB_ENV"\n      - name: Allow gate',
        ),
        "87d6d5f/U6-02 prerequisite": ci.replace(
            "    name: lint-gates", "    needs: mutants\n    name: lint-gates"
        ),
    }
    for label, hostile in fixtures.items():
        assert hostile != ci, label
        assert workflow_gate.wiring_errors(hostile, prek), label
    for before, after in (
        ('stages = ["pre-push", "manual"]', 'stages = ["manual"]'),
        ('id = "lint-gates"', 'id = "lint-gates"\nexclude = ".*"'),
    ):
        hostile = prek.replace(before, after)
        assert hostile != prek
        assert workflow_gate.wiring_errors(ci, hostile), (
            "b8d23a5/U6-06 hook suppression"
        )
    for job in ("lint-gates", "closures"):
        for key in (
            "unknown",
            "env",
            "defaults",
            "shell",
            "container",
            "services",
            "options",
            '"if"',
            r'"\x69f"',
            "needs",
        ):
            hostile = ci.replace(
                f"    name: {job}", f"    {key}: hostile\n    name: {job}"
            )
            if job == "lint-gates":
                assert workflow_gate.wiring_errors(hostile, prek), key
            else:
                try:
                    feature_closures.ci_matrix(hostile)
                except RuntimeError:
                    pass
                else:
                    raise AssertionError(f"closures accepted {key}")
    for filename in ("release.yml", "publish.yml"):
        original = (root / ".github/workflows" / filename).read_text()
        assert workflow_gate.pin_errors({filename: original}) == []
        for key in ('"uses"', "'uses'", r'"\u0075ses"'):
            hostile = original.replace(
                "uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
                f"{key}: actions/checkout@v7",
            )
            assert hostile != original
            assert workflow_gate.pin_errors({filename: hostile}), (
                "87d6d5f/U6-03 quoted pin"
            )
    for hostile in (
        "jobs: {build: {steps: [{uses: actions/checkout@v7}]}}",
        "jobs:\n  build:\n    steps: [{uses: actions/checkout@v7}]",
        "jobs:\n  build:\n    steps:\n      - uses: !!str actions/checkout@v7",
        "jobs:\n  build:\n    steps:\n      - uses: &action actions/checkout@v7",
        "jobs:\n  build:\n    steps:\n      - uses: *action",
        "jobs:\n  build:\n    steps:\n      - <<: *action",
    ):
        assert workflow_gate.pin_errors({"hostile.yml": hostile}), hostile
    print("workflow_regressions self-test: ok (four critic rounds, real workflows)")
    return 0


if __name__ == "__main__":
    sys.exit(self_test() if "--self-test" in sys.argv else 2)
