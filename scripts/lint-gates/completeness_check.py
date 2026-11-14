#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
# How to run: python3 scripts/lint-gates/completeness_check.py --self-test
"""Compare discovered rustc/restriction omissions with their own exclusion rows."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tomllib
from pathlib import Path

import common


def omissions(help_text: str, namespace: str) -> set[str]:
    if namespace == "rustc":
        return {
            m[1].replace("-", "_")
            for m in re.finditer(r"(?m)^\s*([\w-]+)\s+allow\s+", help_text)
        }
    match = re.search(r"(?m)^\s*clippy::restriction\s+([^\n]+)", help_text)
    if match is None:
        raise RuntimeError("clippy-driver help contains no restriction group")
    return {
        name.strip().removeprefix("clippy::").replace("-", "_")
        for name in match[1].split(",")
        if name.strip()
    }


def compare(core: str, profile: dict, discovered: dict[str, set[str]]) -> list[str]:
    errors = []
    for kind, table in (("rustc", "rust"), ("restriction", "clippy")):
        excluded = {
            m[1].removeprefix("clippy::")
            for m in re.finditer(r"(?m)^\|\s*`([^`]+)`\s*\|\s*" + kind + r"\s*\|", core)
        }
        missing = discovered[kind] - profile.get(table, {}).keys()
        for name in sorted(missing - excluded):
            errors.append(f"{kind}: undocumented omission {name}")
        for name in sorted(excluded - missing):
            errors.append(f"{kind}: stale exclusion {name}")
    allows = {
        (table, name)
        for table, entries in profile.items()
        for name, value in entries.items()
        if (value if isinstance(value, str) else value.get("level")) == "allow"
    }
    if allows != {("clippy", "redundant_pub_crate")}:
        errors.append(
            f"only allow must be clippy::redundant_pub_crate; got {sorted(allows)}"
        )
    return errors


def self_test() -> int:
    core = "| `nightly_only` | rustc | unstable |\n| `clippy::conflict` | restriction | conflicts |\n"
    profile = {
        "rust": {"new_lint": "deny"},
        "clippy": {"unwrap_used": "deny", "redundant_pub_crate": "allow"},
    }
    discovered = {
        "rustc": omissions(
            " nightly-only allow description\n new-lint allow description\n", "rustc"
        ),
        "restriction": omissions(
            " clippy::restriction clippy::conflict, clippy::unwrap-used\n",
            "restriction",
        ),
    }
    assert compare(core, profile, discovered) == []
    lowered = {"rust": profile["rust"], "clippy": {"redundant_pub_crate": "allow"}}
    assert any("unwrap_used" in e for e in compare(core, lowered, discovered))
    crossed = core.replace("| rustc |", "| restriction |")
    assert any("nightly_only" in e for e in compare(crossed, profile, discovered))
    assert compare(core, {"clippy": {"unwrap_used": "allow"}}, discovered)
    print("completeness_check self-test: ok (missing lint, namespaces, sole allow)")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=common.ROOT)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    try:
        discovered = {}
        for kind, command in (
            ("rustc", ["rustc", "-W", "help"]),
            ("restriction", ["rustup", "run", "stable", "clippy-driver", "-W", "help"]),
        ):
            result = subprocess.run(
                command, cwd=args.root, capture_output=True, text=True, check=True
            )
            discovered[kind] = omissions(result.stdout, kind)
            if not discovered[kind]:
                raise RuntimeError(f"empty {kind} discovery")
        profile = tomllib.loads((args.root / "Cargo.toml").read_text()).get("lints", {})
        errors = compare((args.root / common.CORE_REL).read_text(), profile, discovered)
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as error:
        errors = [str(error)]
    print(
        "\n".join(errors)
        if errors
        else "\n".join(
            f"{kind}: {name}"
            for kind, names in discovered.items()
            for name in sorted(
                names - profile.get("rust" if kind == "rustc" else "clippy", {}).keys()
            )
        )
    )
    return int(bool(errors))


if __name__ == "__main__":
    sys.exit(main())
