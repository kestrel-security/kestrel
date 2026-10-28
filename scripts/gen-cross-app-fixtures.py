# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Regenerate packs/cross-app/policies/fixtures/*.fixtures.json from
kestrel.policies.cross_app_fixtures. Run after changing a scenario; a unit
test fails when the files and the module disagree."""

from __future__ import annotations

import json
from pathlib import Path

from kestrel.policies.cross_app_fixtures import CROSS_APP_FIXTURE_SETS

FIXTURES_DIR = Path(__file__).resolve().parents[1] / "packs" / "cross-app" / "policies" / "fixtures"


def main() -> None:
    for slug, fixtures in CROSS_APP_FIXTURE_SETS.items():
        path = FIXTURES_DIR / f"{slug}.fixtures.json"
        path.write_text(json.dumps(fixtures, indent=2) + "\n")
        print(f"wrote {path.relative_to(FIXTURES_DIR.parents[3])}")


if __name__ == "__main__":
    main()
