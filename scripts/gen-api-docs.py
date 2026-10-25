#!/usr/bin/env python3
# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Regenerate the route tables in docs/api.md from the running application's OpenAPI schema.

    uv run python scripts/gen-api-docs.py           # rewrite the generated block
    uv run python scripts/gen-api-docs.py --check   # exit 1 if the block on disk is stale

The hand-written sections outside the markers are left untouched.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOC = ROOT / "docs" / "api.md"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="fail instead of writing when the block is stale")
    args = ap.parse_args()

    from kestrel.dev.api_docs import generated_block, render, splice
    from kestrel_api.main import create_app

    schema = create_app().openapi()
    fresh = render(schema)
    current = DOC.read_text(encoding="utf-8")
    if generated_block(current) == fresh:
        print("docs/api.md route tables are up to date")
        return 0
    if args.check:
        print("docs/api.md route tables are stale; run: uv run python scripts/gen-api-docs.py", file=sys.stderr)
        return 1
    DOC.write_text(splice(current, fresh), encoding="utf-8")
    print("docs/api.md route tables regenerated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
