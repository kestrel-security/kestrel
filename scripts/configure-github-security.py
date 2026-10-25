# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Enable and verify the public repository's launch protections with gh.

Usage: python3 scripts/configure-github-security.py [--apply]
Visibility is never changed. GitHub gates these settings while this personal
repository is private; run after the public flip, before announcing it.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys

REPOSITORY = "kestrel-security/kestrel"
REQUIRED_CHECKS = [
    "Tier 0 — lint, types, migrations, manifests",
    "Tier 1 — unit",
    "Tier 2 — integration",
    "Order independence — seed 1234",
    "Order independence — seed 9876",
    "Coverage floor",
    "Web — lint, typecheck, test, build",
    "Documentation links and version consistency",
    "pip-audit",
    "pnpm audit",
    "gitleaks",
    "DCO sign-off",
    "Commit metadata hygiene",
]


def api(method: str, endpoint: str, payload: dict | None = None) -> dict:
    command = ["gh", "api", "--method", method, f"repos/{REPOSITORY}{endpoint}"]
    if payload is not None:
        command += ["--input", "-"]
    result = subprocess.run(
        command, input=json.dumps(payload) if payload is not None else None, text=True, capture_output=True
    )
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip())
    return json.loads(result.stdout) if result.stdout.strip() else {}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="Enable settings, then verify them.")
    args = parser.parse_args()
    repository = api("GET", "")
    if repository["visibility"] != "public":
        print("Repository is private. Run this after the public flip; visibility was not changed.", file=sys.stderr)
        return 1
    if args.apply:
        api("PUT", "/actions/permissions", {"enabled": True})
        api("PUT", "/private-vulnerability-reporting")
        api(
            "PATCH",
            "",
            {
                "security_and_analysis": {
                    "secret_scanning": {"status": "enabled"},
                    "secret_scanning_push_protection": {"status": "enabled"},
                }
            },
        )
        api("PUT", "/vulnerability-alerts")
        api(
            "PUT",
            "/branches/main/protection",
            {
                "required_status_checks": {"strict": True, "contexts": REQUIRED_CHECKS},
                "enforce_admins": True,
                "required_pull_request_reviews": None,
                "restrictions": None,
                "allow_force_pushes": False,
                "allow_deletions": False,
            },
        )
    repository = api("GET", "")
    reporting = api("GET", "/private-vulnerability-reporting")
    actions = api("GET", "/actions/permissions")
    protection = api("GET", "/branches/main/protection")
    api("GET", "/vulnerability-alerts")
    failures = []
    if not actions.get("enabled"):
        failures.append("GitHub Actions")
    if not reporting.get("enabled"):
        failures.append("private vulnerability reporting")
    analysis = repository.get("security_and_analysis") or {}
    for setting in ("secret_scanning", "secret_scanning_push_protection"):
        if analysis.get(setting, {}).get("status") != "enabled":
            failures.append(setting)
    checks = protection.get("required_status_checks") or {}
    if not checks.get("strict") or not set(REQUIRED_CHECKS).issubset(checks.get("contexts", [])):
        failures.append("required status checks")
    if not protection.get("enforce_admins", {}).get("enabled"):
        failures.append("administrator enforcement")
    for setting in ("allow_force_pushes", "allow_deletions"):
        if protection.get(setting, {}).get("enabled", True):
            failures.append(setting)
    if failures:
        print("Missing protections: " + ", ".join(failures), file=sys.stderr)
        return 1
    print("Actions, private reporting, secret protection, dependency alerts and main protection verified.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(1)
