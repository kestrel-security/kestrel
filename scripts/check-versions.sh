#!/usr/bin/env bash
# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
# scripts/check-versions.sh — assert the release version is consistent everywhere
#
# A release is identified by a single git tag (vX.Y.Z), so every place that
# records a version has to agree with it or the tag stops meaning anything --
# see docs/operations/release-process.md.
#
# Two independent checks:
#   1. The app version set (core, api, worker, web) must all match.
#   2. Each connector's pyproject version must match its manifest version.
#      Connectors are versioned independently of the app on purpose (a connector
#      can ship a fix without a product release), but its two files must agree
#      or `GET /connectors` advertises a version the package does not have.
#
# Usage:
#   scripts/check-versions.sh            # internal consistency only
#   scripts/check-versions.sh 0.2.0      # also assert the app set equals 0.2.0
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

EXPECTED="${1:-}"

EXPECTED="$EXPECTED" python3 - <<'PY'
from __future__ import annotations

import json
import os
import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(".").resolve()
errors: list[str] = []


def pyproject_version(path: str) -> str | None:
    file = ROOT / path
    if not file.is_file():
        errors.append(f"{path}: missing")
        return None
    try:
        data = tomllib.loads(file.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        errors.append(f"{path}: unparseable ({exc})")
        return None
    version = data.get("project", {}).get("version")
    if not version:
        errors.append(f"{path}: no [project] version")
        return None
    return str(version)


def json_version(path: str) -> str | None:
    file = ROOT / path
    if not file.is_file():
        errors.append(f"{path}: missing")
        return None
    version = json.loads(file.read_text(encoding="utf-8")).get("version")
    if not version:
        errors.append(f"{path}: no version field")
        return None
    return str(version)


def yaml_top_level_version(path: str, key: str) -> str | None:
    """Read a top-level `key: value` from YAML without a yaml dependency.

    Anchoring at column zero keeps a nested `version:` key from being picked up.
    """
    file = ROOT / path
    if not file.is_file():
        errors.append(f"{path}: missing")
        return None
    match = re.search(rf'^{re.escape(key)}:\s*"?([^"\s#]+)"?', file.read_text(encoding="utf-8"), re.MULTILINE)
    if match is None:
        errors.append(f"{path}: no top-level '{key}'")
        return None
    return match.group(1)


# --- Check 1: the app version set -------------------------------------------
app_versions = {
    "kestrel/pyproject.toml": pyproject_version("kestrel/pyproject.toml"),
    "apps/api/pyproject.toml": pyproject_version("apps/api/pyproject.toml"),
    "apps/worker/pyproject.toml": pyproject_version("apps/worker/pyproject.toml"),
    "apps/web/package.json": json_version("apps/web/package.json"),
}

known = {path: v for path, v in app_versions.items() if v is not None}
distinct = sorted(set(known.values()))
if len(distinct) > 1:
    errors.append("app version set disagrees:")
    for path, version in sorted(known.items()):
        errors.append(f"  {version:<12} {path}")

expected = os.environ.get("EXPECTED", "").strip().lstrip("v")
if expected:
    for path, version in sorted(known.items()):
        if version != expected:
            errors.append(f"{path}: is {version}, expected {expected}")

# --- Check 2: connector pyproject vs manifest -------------------------------
for connector in sorted((ROOT / "connectors").iterdir()):
    if not connector.is_dir():
        continue
    rel = connector.relative_to(ROOT)
    pyproject = connector / "pyproject.toml"
    manifest = connector / "manifest.yaml"
    if not pyproject.is_file() or not manifest.is_file():
        continue
    pkg = pyproject_version(str(rel / "pyproject.toml"))
    declared = yaml_top_level_version(str(rel / "manifest.yaml"), "version")
    if pkg is not None and declared is not None and pkg != declared:
        errors.append(f"{rel}: pyproject.toml is {pkg} but manifest.yaml is {declared}")

if errors:
    print("Version consistency check failed:", file=sys.stderr)
    for error in errors:
        print(f"  {error}" if not error.startswith(" ") else error, file=sys.stderr)
    sys.exit(1)

label = distinct[0] if distinct else "unknown"
print(f"check-versions OK (app version {label})")
PY
