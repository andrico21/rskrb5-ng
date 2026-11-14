#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
# How to run: python3 scripts/lint-gates/fuzz_lint.py --enforce
"""Apply the root lint profile to the separate fuzz crate."""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path
from tempfile import TemporaryDirectory

import common


def lint_flags(manifest: dict) -> list[str]:
    entries = [
        (namespace, name, value if isinstance(value, dict) else {"level": value})
        for namespace, table in manifest["lints"].items()
        for name, value in table.items()
    ]
    entries.sort(key=lambda entry: entry[2].get("priority", 0))
    return [
        flag
        for namespace, name, value in entries
        for flag in (
            {"deny": "-D", "forbid": "-F", "warn": "-W", "allow": "-A"}[value["level"]],
            name if namespace == "rust" else namespace + "::" + name,
        )
    ]


def self_test() -> int:
    flags = lint_flags(
        {
            "lints": {
                "clippy": {
                    "unwrap_used": "deny",
                    "all": {"level": "deny", "priority": -1},
                    "todo": "deny",
                }
            }
        }
    )
    assert flags == [
        "-D",
        "clippy::all",
        "-D",
        "clippy::unwrap_used",
        "-D",
        "clippy::todo",
    ]
    print("fuzz_lint self-test: ok (groups first, individual file order)")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=common.ROOT)
    parser.add_argument("--enforce", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    flags = lint_flags(tomllib.loads((args.root / "Cargo.toml").read_text()))
    command = [
        "flock",
        "/tmp/rskrb5-cargo.lock",
        "cargo",
        "+nightly-2026-10-03",
        "clippy",
        "--manifest-path",
        "fuzz/Cargo.toml",
        "--all-targets",
        "--",
        "-D",
        "warnings",
        *flags,
    ]
    print("$ " + " ".join(command), flush=True)
    with TemporaryDirectory(prefix="rskrb5-fuzz-lint-") as directory:
        scratch = Path(directory) / "source"
        shutil.copytree(
            args.root,
            scratch,
            ignore=shutil.ignore_patterns(".git", "target", ".omo", "__pycache__"),
        )
        env = dict(os.environ)
        env.setdefault("CARGO_TARGET_DIR", str(Path(directory) / "target"))
        status = subprocess.run(command, cwd=scratch, env=env).returncode
    print(f"fuzz_lint: clippy exited {status}")
    return int(args.enforce and status != 0)


if __name__ == "__main__":
    sys.exit(main())
