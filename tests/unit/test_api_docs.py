# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""docs/api.md must describe the API that is actually mounted.

Two guards:

1. Every ``METHOD /path`` code span anywhere in the document names a route the
   application serves. This is what stops the document from describing routers
   that were removed (it once documented ten of them).
2. The generated block between the markers matches what
   ``kestrel.dev.api_docs.render`` produces from the live schema, so a new or
   renamed route without ``scripts/gen-api-docs.py`` fails here.

Building the app does not open a database connection, so this stays Tier 1.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from kestrel.dev.api_docs import (
    BEGIN_MARKER,
    END_MARKER,
    canonical_path,
    documented_routes,
    generated_block,
    operations,
    render,
    splice,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
API_DOC = REPO_ROOT / "docs" / "api.md"


@pytest.fixture(scope="module")
def schema() -> dict:
    from kestrel_api.main import create_app

    return create_app().openapi()


@pytest.fixture(scope="module")
def document() -> str:
    return API_DOC.read_text(encoding="utf-8")


def test_every_documented_route_exists(schema: dict, document: str) -> None:
    served: set[tuple[str, str]] = set()
    for tag_rows in operations(schema).values():
        for method, path, _ in tag_rows:
            served.add((method, canonical_path(path)))

    phantom = sorted(
        f"{method} {path}" for method, path in documented_routes(document) if (method, canonical_path(path)) not in served
    )
    assert not phantom, "docs/api.md names routes the application does not serve:\n  " + "\n  ".join(phantom)


def test_generated_block_is_current(schema: dict, document: str) -> None:
    assert generated_block(document) == render(schema), (
        "docs/api.md route tables are stale; run: uv run python scripts/gen-api-docs.py"
    )


def test_render_groups_by_tag_and_orders_methods() -> None:
    schema = {
        "paths": {
            "/api/v1/things/{thing_id}": {
                "delete": {"tags": ["things"], "summary": "Delete Thing"},
                "get": {"tags": ["things"], "description": "Fetch one thing.\n\nLong text."},
            },
            "/api/v1/things": {"get": {"tags": ["things"], "summary": "List Things"}},
            "/healthz": {"get": {"summary": "Healthz"}},
        }
    }
    out = render(schema)
    assert out.startswith(BEGIN_MARKER)
    assert out.endswith(END_MARKER)
    lines = [line for line in out.splitlines() if line.startswith("| `")]
    assert lines == [
        "| `GET` | `/api/v1/things` | List Things |",
        "| `GET` | `/api/v1/things/{thing_id}` | Fetch one thing |",
        "| `DELETE` | `/api/v1/things/{thing_id}` | Delete Thing |",
        "| `GET` | `/healthz` | Healthz |",
    ]
    assert "### Operational endpoints" in out


def test_splice_replaces_only_the_block() -> None:
    doc = f"intro\n\n{BEGIN_MARKER}\nold\n{END_MARKER}\n\noutro\n"
    assert splice(doc, f"{BEGIN_MARKER}\nnew\n{END_MARKER}") == f"intro\n\n{BEGIN_MARKER}\nnew\n{END_MARKER}\n\noutro\n"
    with pytest.raises(ValueError, match="generated-routes markers"):
        splice("no markers", "x")


def test_canonical_path_normalizes_parameter_names() -> None:
    assert canonical_path("/api/v1/findings/{finding_id}/notes") == canonical_path("/api/v1/findings/{id}/notes")
