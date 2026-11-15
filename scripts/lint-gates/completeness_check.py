#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
# How to run: python3 scripts/lint-gates/completeness_check.py --self-test
"""Compare discovered rustc, Clippy and Cargo omissions with their exclusion rows."""

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


def cargo_omissions(page: str) -> set[str]:
    """The Cargo lints outside the groups that the profile denies (the `restriction` ones)."""
    covered = {"correctness", "style", "suspicious", "complexity", "perf", "pedantic"}
    found = set()
    for name, body in re.findall(
        r'<h2 id="([a-z0-9_]+)".*?</h2>(.*?)(?=<h2 |</main>)', page, re.DOTALL
    ):
        group = re.search(r"Group: <code[^>]*>([a-z]+)<", body)
        if group is not None and group[1] not in covered:
            found.add(name)
    return found


# The core's two single-lint overrides; `cargo::manual_readme` is temporary (rust-lang/cargo#17730).
ALLOWS = {("clippy", "redundant_pub_crate"), ("cargo", "manual_readme")}
TABLES = {"rustc": "rust", "restriction": "clippy", "Cargo restriction": "cargo"}


def compare(core: str, profile: dict, discovered: dict[str, set[str]]) -> list[str]:
    errors = []
    for kind, table in TABLES.items():
        excluded = {
            m[1].removeprefix("clippy::").removeprefix("cargo::")
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
    if allows != ALLOWS:
        errors.append(f"the only allows must be {sorted(ALLOWS)}; got {sorted(allows)}")
    return errors


def self_test() -> int:
    core = "| `nightly_only` | rustc | unstable |\n| `clippy::conflict` | restriction | conflicts |\n"
    profile = {
        "rust": {"new_lint": "deny"},
        "clippy": {"unwrap_used": "deny", "redundant_pub_crate": "allow"},
        "cargo": {"manual_readme": "allow"},
    }
    discovered = {
        "rustc": omissions(
            " nightly-only allow description\n new-lint allow description\n", "rustc"
        ),
        "restriction": omissions(
            " clippy::restriction clippy::conflict, clippy::unwrap-used\n",
            "restriction",
        ),
        "Cargo restriction": set(),
    }
    assert compare(core, profile, discovered) == []
    lowered = {**profile, "clippy": {"redundant_pub_crate": "allow"}}
    assert any("unwrap_used" in e for e in compare(core, lowered, discovered))
    crossed = core.replace("| rustc |", "| restriction |")
    assert any("nightly_only" in e for e in compare(crossed, profile, discovered))
    assert compare(core, {"clippy": {"unwrap_used": "allow"}}, discovered)
    no_cargo_allow = {**profile, "cargo": {"manual_readme": "deny"}}
    assert any("manual_readme" in e for e in compare(core, no_cargo_allow, discovered))
    third = {**profile, "cargo": {"manual_readme": "allow", "pedantic": "allow"}}
    assert any("pedantic" in e for e in compare(core, third, discovered))
    page = "".join(
        f'<h2 id="{name}"><a>{name}</a></h2><p>Group: <code class="x">{group}</code></p>'
        for name, group in (
            ("manual_readme", "pedantic"),
            ("non_kebab_case_bins", "pedantic"),
            ("non_snake_case_packages", "restriction"),
        )
    )
    assert cargo_omissions(page + "</main>") == {"non_snake_case_packages"}
    cargo_core = core + "| `cargo::non_snake_case_packages` | Cargo restriction | pair |\n"
    cargo_profile = profile
    cargo_found = {**discovered, "Cargo restriction": {"non_snake_case_packages"}}
    assert compare(cargo_core, cargo_profile, cargo_found) == []
    assert any(
        "undocumented omission non_snake_case_packages" in e
        for e in compare(core, cargo_profile, cargo_found)
    )
    assert any(
        "stale exclusion" in e
        for e in compare(cargo_core, cargo_profile, {**discovered, "Cargo restriction": set()})
    )
    print("completeness_check self-test: ok (missing lint, namespaces, the two allows, Cargo leg)")
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
        sysroot = subprocess.run(
            ["rustup", "run", "stable", "rustc", "--print", "sysroot"],
            cwd=args.root,
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        page = Path(sysroot, "share/doc/rust/html/cargo/reference/lints.html")
        discovered["Cargo restriction"] = cargo_omissions(page.read_text())
        if not discovered["Cargo restriction"]:
            raise RuntimeError("empty Cargo discovery (the rust-docs component is needed)")
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
            for name in sorted(names - profile.get(TABLES[kind], {}).keys())
        )
    )
    return int(bool(errors))


if __name__ == "__main__":
    sys.exit(main())
