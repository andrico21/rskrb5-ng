#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
# How to run: python3 scripts/lint-gates/upstream_issue.py --enforce
"""Fail when rust-lang/cargo#17730 is closed (the weekly scheduled CI check).

The vendored guidelines core exempts `cargo::manual_readme` (`manual_readme =
"allow"` in `Cargo.toml`) while that Cargo bug is open: `cargo package`
verification lints the normalized manifest. Once the issue is closed the
exemption is removed from `Cargo.toml`, the core and the allow set together.
The issue is read through the GitHub API; `GITHUB_TOKEN`, when set, is sent
only to api.github.com.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.request
from collections.abc import Callable
from typing import Final

REPOSITORY: Final = "rust-lang/cargo"
NUMBER: Final = 17730
API: Final = "https://api.github.com"


def state_problem(state: str) -> str | None:
    if state == "open":
        return None
    if state == "closed":
        return (
            f"{REPOSITORY}#{NUMBER} is closed: remove `manual_readme = \"allow\"` from "
            "Cargo.toml, the vendored core and the allow set together"
        )
    return f"{REPOSITORY}#{NUMBER} has unexpected state {state!r}"


def check(fetch: Callable[[], str]) -> list[str]:
    try:
        problem = state_problem(fetch())
    except (OSError, ValueError, KeyError) as error:
        return [f"{REPOSITORY}#{NUMBER} could not be read: {error}"]
    return [problem] if problem else []


def read_state(api: str, token: str | None) -> str:
    request = urllib.request.Request(
        f"{api}/repos/{REPOSITORY}/issues/{NUMBER}",
        headers={"Accept": "application/vnd.github+json", "User-Agent": "rskrb5-ng-upstream-issue"},
    )
    if token and api == API:
        request.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310
        return str(json.load(response)["state"])


def self_test() -> int:
    assert check(lambda: "open") == []
    closed = check(lambda: "closed")
    assert closed and f"{REPOSITORY}#{NUMBER}" in closed[0] and "manual_readme" in closed[0], closed
    unknown = check(lambda: "merged")
    assert unknown and "unexpected" in unknown[0], unknown
    def broken() -> str:
        raise OSError("network down")
    assert check(broken), "an unreadable issue must fail, not pass"
    print("upstream_issue self-test: ok (open passes; closed, unknown and unreadable fail)")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--enforce", action="store_true")
    parser.add_argument("--api", default=API, help="GitHub API base URL (a fixture server in tests)")
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    found = check(lambda: read_state(args.api, os.environ.get("GITHUB_TOKEN")))
    print("\n".join(found + [f"upstream_issue: {REPOSITORY}#{NUMBER}: {len(found)} problem(s)"]))
    return int(args.enforce and bool(found))


if __name__ == "__main__":
    sys.exit(main())
