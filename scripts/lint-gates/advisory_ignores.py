#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
# How to run: python3 scripts/lint-gates/advisory_ignores.py --enforce
"""The advisory ignore sets of `deny.toml` and `.cargo/audit.toml` must be equal.

`cargo deny` and `cargo audit` read separate files, so an ignore added to one
only silently weakens, or fails, the other tool. Both files say "keep equal";
this gate enforces it. `deny.toml` lists ignores as `[[advisories.ignore]]`
tables (`id = ...` or `crate = ...`) or plain strings; `audit.toml` lists plain
advisory ids.
"""

from __future__ import annotations

import argparse
import sys
import tomllib
from pathlib import Path

DENY = "deny.toml"
AUDIT = ".cargo/audit.toml"


def ignore_ids(text: str) -> set[str]:
    """Advisory ids (or `crate` specs) of `[advisories] ignore`, in table or string form."""
    entries = tomllib.loads(text).get("advisories", {}).get("ignore", [])
    return {
        str(entry.get("id") or entry.get("crate")) if isinstance(entry, dict) else str(entry)
        for entry in entries
    }


def problems(deny_text: str, audit_text: str) -> list[str]:
    deny, audit = ignore_ids(deny_text), ignore_ids(audit_text)
    return [f"{advisory} is ignored in {DENY} only" for advisory in sorted(deny - audit)] + [
        f"{advisory} is ignored in {AUDIT} only" for advisory in sorted(audit - deny)
    ]


def self_test() -> int:
    deny = '[advisories]\n[[advisories.ignore]]\nid = "RUSTSEC-2026-0543"\nreason = "r"\n'
    audit = '[advisories]\nignore = ["RUSTSEC-2026-0543"]\n'
    assert ignore_ids(deny) == {"RUSTSEC-2026-0543"} == ignore_ids(audit)
    assert problems(deny, audit) == []
    assert problems('[advisories]\nignore = ["RUSTSEC-2026-0543"]\n', audit) == []
    only_deny = deny + '[[advisories.ignore]]\nid = "RUSTSEC-2099-0001"\nreason = "r"\n'
    found = problems(only_deny, audit)
    assert found and "RUSTSEC-2099-0001" in found[0] and DENY in found[0], found
    only_audit = '[advisories]\nignore = ["RUSTSEC-2026-0543", "RUSTSEC-2099-0002"]\n'
    found = problems(deny, only_audit)
    assert found and "RUSTSEC-2099-0002" in found[0] and AUDIT in found[0], found
    assert problems("[advisories]\n", "[advisories]\n") == []
    assert problems("[advisories]\n", audit), "an empty deny.toml set against a non-empty audit set"
    print("advisory_ignores self-test: ok (equal, table and string forms, either file alone)")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--enforce", action="store_true")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    found = problems(
        (args.root / DENY).read_text(encoding="utf-8"),
        (args.root / AUDIT).read_text(encoding="utf-8"),
    )
    print("\n".join(found + [f"advisory_ignores: {len(found)} mismatch(es)"]))
    return int(args.enforce and bool(found))


if __name__ == "__main__":
    sys.exit(main())
