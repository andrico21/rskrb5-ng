#!/usr/bin/env python3
"""Smoke tests for the non-live AD integration environment preflight."""

from __future__ import annotations

import base64
import os
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PREFLIGHT = ROOT / "scripts" / "check-ad-integration-env.py"

AD_ENV_KEYS = {
    "TESTAD",
    "TESTAD_REQUIRED",
    "TEST_AD_REQUIRE_EXPLICIT_ENDPOINTS",
    "TEST_AD_REQUIRE_KEYTAB_OVERRIDES",
    "TEST_AD_SKIP_REACHABILITY",
    "TEST_AD_CHECK_ADMIN_REACHABILITY",
    "TEST_AD_CONNECT_TIMEOUT_SECS",
    "TEST_AD_USER_KDC_ADDR",
    "TEST_AD_RESOURCE_KDC_ADDR",
    "TEST_AD_USER_ADMIN_ADDR",
    "TEST_AD_RESOURCE_ADMIN_ADDR",
    "TEST_AD_KDC_ADDR",
    "TEST_AD_RES_KDC_ADDR",
    "TEST_AD_ADMIN_ADDR",
    "TEST_AD_RES_ADMIN_ADDR",
    "TEST_AD_TESTUSER1_KEYTAB_PATH",
    "TEST_AD_TESTUSER1_KEYTAB_HEX",
    "TEST_AD_TESTUSER1_KEYTAB_BASE64",
    "TEST_AD_TESTUSER2_KEYTAB_PATH",
    "TEST_AD_TESTUSER2_KEYTAB_HEX",
    "TEST_AD_TESTUSER2_KEYTAB_BASE64",
    "TEST_AD_TESTUSER3_KEYTAB_PATH",
    "TEST_AD_TESTUSER3_KEYTAB_HEX",
    "TEST_AD_TESTUSER3_KEYTAB_BASE64",
    "TEST_AD_SYSHTTP_KEYTAB_PATH",
    "TEST_AD_SYSHTTP_KEYTAB_HEX",
    "TEST_AD_SYSHTTP_KEYTAB_BASE64",
}

RESERVED_ENDPOINTS = {
    "TEST_AD_USER_KDC_ADDR": "192.0.2.10:88",
    "TEST_AD_RESOURCE_KDC_ADDR": "192.0.2.11:88",
    "TEST_AD_USER_ADMIN_ADDR": "192.0.2.10:464",
    "TEST_AD_RESOURCE_ADMIN_ADDR": "192.0.2.11:464",
}


def main() -> int:
    failures: list[str] = []
    realm = b"USER.GOKRB5"
    name = b"testuser1"
    entry = (
        b"\x00\x01"
        + len(realm).to_bytes(2, "big")
        + realm
        + len(name).to_bytes(2, "big")
        + name
        + (1).to_bytes(4, "big")
        + bytes(4)
        + b"\x01\x00\x12\x00\x20"
        + bytes(32)
    )
    valid = b"\x05\x02" + len(entry).to_bytes(4, "big") + entry
    failures.extend(
        check_case(
            "key after terminator is not usable",
            {
                **strict_dry_run_env(),
                "TEST_AD_TESTUSER1_KEYTAB_HEX": (
                    valid[:2] + bytes(4) + valid[2:]
                ).hex(),
            },
            expected_returncode=1,
            expected_text=["no usable key"],
        )
    )
    failures.extend(
        check_case(
            "deleted slot before key remains usable",
            {
                **strict_dry_run_env(),
                "TEST_AD_TESTUSER1_KEYTAB_HEX": (
                    valid[:2] + (-1).to_bytes(4, "big", signed=True) + b"x" + valid[2:]
                ).hex(),
            },
            expected_returncode=0,
            expected_text=["environment is ready"],
        )
    )
    failures.extend(
        check_case(
            "complete keytab override passes",
            {**strict_dry_run_env(), "TEST_AD_TESTUSER1_KEYTAB_HEX": valid.hex()},
            expected_returncode=0,
            expected_text=["environment is ready"],
        )
    )

    failures.extend(
        check_case(
            "missing TESTAD flags fails",
            {
                "TEST_AD_SKIP_REACHABILITY": "1",
            },
            expected_returncode=1,
            expected_text=[
                "TESTAD must be '1'",
                "TESTAD_REQUIRED must be '1'",
            ],
        )
    )

    failures.extend(
        check_case(
            "invalid endpoint syntax fails even in dry-run",
            {
                **strict_dry_run_env(),
                "TEST_AD_USER_KDC_ADDR": "not-a-host-port",
            },
            expected_returncode=1,
            expected_text=[
                "USER realm KDC endpoint 'not-a-host-port' is invalid",
            ],
        )
    )

    failures.extend(
        check_case(
            "dry-run with explicit reserved endpoints passes",
            strict_dry_run_env(),
            expected_returncode=0,
            expected_text=[
                "testuser1@USER.GOKRB5: embedded test fixture",
                "AD integration environment is ready.",
            ],
        )
    )

    failures.extend(
        check_case(
            "malformed keytab base64 fails",
            {
                **strict_dry_run_env(),
                "TEST_AD_TESTUSER1_KEYTAB_BASE64": "not valid base64%%",
            },
            expected_returncode=1,
            expected_text=[
                "TEST_AD_TESTUSER1_KEYTAB_BASE64 is not valid base64",
            ],
        )
    )

    failures.extend(
        check_case(
            "invalid keytab bytes fail",
            {
                **strict_dry_run_env(),
                "TEST_AD_TESTUSER1_KEYTAB_BASE64": base64.b64encode(
                    b"not-a-keytab"
                ).decode(),
            },
            expected_returncode=1,
            expected_text=[
                "TEST_AD_TESTUSER1_KEYTAB_BASE64 has invalid first byte",
            ],
        )
    )

    for malformed in ["050200", "0502000000100001", "0502000000020001"]:
        failures.extend(
            check_case(
                "truncated keytab fails",
                {**strict_dry_run_env(), "TEST_AD_TESTUSER1_KEYTAB_HEX": malformed},
                expected_returncode=1,
                expected_text=["truncated keytab"],
            )
        )

    if failures:
        print("AD preflight smoke tests failed:", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1

    print("AD preflight smoke tests passed.")
    return 0


def strict_dry_run_env() -> dict[str, str]:
    return {
        "TESTAD": "1",
        "TESTAD_REQUIRED": "1",
        "TEST_AD_REQUIRE_EXPLICIT_ENDPOINTS": "1",
        "TEST_AD_SKIP_REACHABILITY": "1",
        **RESERVED_ENDPOINTS,
    }


def check_case(
    name: str,
    env_updates: dict[str, str],
    *,
    expected_returncode: int,
    expected_text: list[str],
) -> list[str]:
    completed = subprocess.run(
        [sys.executable, str(PREFLIGHT)],
        cwd=ROOT,
        env=test_env(env_updates),
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    output = completed.stdout + completed.stderr
    failures: list[str] = []
    if completed.returncode != expected_returncode:
        failures.append(
            f"{name}: expected exit {expected_returncode}, got {completed.returncode}"
        )
    for text in expected_text:
        if text not in output:
            failures.append(f"{name}: missing output text {text!r}")
    if failures:
        print(f"\n{name} output:\n{output}", file=sys.stderr)
    return failures


def test_env(updates: dict[str, str]) -> dict[str, str]:
    env = os.environ.copy()
    for key in AD_ENV_KEYS:
        env.pop(key, None)
    env.update(updates)
    return env


if __name__ == "__main__":
    raise SystemExit(main())
