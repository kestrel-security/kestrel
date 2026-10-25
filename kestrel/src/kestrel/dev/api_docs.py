# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Render the route tables in ``docs/api.md`` from the live OpenAPI schema.

``docs/api.md`` is hand-written outside a pair of marker comments and generated
between them. The generated block is one table per router tag, listing every
operation the application actually mounts, so the document cannot describe a
route that does not exist. ``tests/unit/test_api_docs.py`` fails when the
block on disk drifts from what this module renders, and
``scripts/gen-api-docs.py`` rewrites it.

The schema is whatever ``kestrel_api.main.create_app().openapi()`` returns;
this module has no FastAPI dependency of its own so it can be unit-tested with
a dict.
"""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Any

BEGIN_MARKER = "<!-- BEGIN GENERATED ROUTES -->"
END_MARKER = "<!-- END GENERATED ROUTES -->"

API_PREFIX = "/api/v1"

# Display title and order for each router tag. Tags not listed here are
# appended alphabetically after these, so a new router still renders.
TAG_TITLES: list[tuple[str, str]] = [
    ("auth", "Auth"),
    ("operators", "Operators"),
    ("api-tokens", "API tokens"),
    ("dashboard", "Dashboard (home)"),
    ("dashboards", "Dashboards (boards)"),
    ("changes", "Changes"),
    ("graph", "Graph"),
    ("identities", "Identities"),
    ("search", "Search"),
    ("findings", "Findings"),
    ("connectors", "Connectors"),
    ("policies", "Policies"),
    ("packs", "Packs"),
    ("audit", "Audit log"),
    ("webhooks", "Webhooks"),
    ("ticket-integrations", "Ticket integrations"),
    ("settings-ai", "AI settings"),
    ("settings-email", "Email settings"),
    ("notification-preferences", "Notification preferences"),
]

METHOD_ORDER = {"GET": 0, "POST": 1, "PUT": 2, "PATCH": 3, "DELETE": 4}
_ROUTE_SPAN = re.compile(r"`(GET|POST|PUT|PATCH|DELETE) (/[^`\s]*)`")
_PATH_PARAM = re.compile(r"\{[^}]+\}")


def _first_line(text: str | None) -> str:
    if not text:
        return ""
    line = text.strip().split("\n", 1)[0].strip()
    return line.rstrip(".")


def _describe(op: dict[str, Any]) -> str:
    """Prefer the docstring's first line; fall back to FastAPI's generated summary."""
    desc = _first_line(op.get("description"))
    if desc:
        return desc.replace("|", "\\|")
    return _first_line(op.get("summary")).replace("|", "\\|")


def operations(schema: dict[str, Any]) -> dict[str, list[tuple[str, str, str]]]:
    """Group operations by their first tag → ``[(METHOD, path, description), ...]``."""
    grouped: dict[str, list[tuple[str, str, str]]] = defaultdict(list)
    for path, ops in schema.get("paths", {}).items():
        for method, op in ops.items():
            if method.upper() not in METHOD_ORDER:
                continue
            tags = op.get("tags") or []
            tag = tags[0] if tags else "ops"
            grouped[tag].append((method.upper(), path, _describe(op)))
    for rows in grouped.values():
        rows.sort(key=lambda r: (r[1], METHOD_ORDER[r[0]]))
    return dict(grouped)


OPS_PATHS = ("/healthz", "/metrics")


def canonical_path(path: str) -> str:
    """Normalize a path for comparison.

    Parameter names are erased (``/findings/{finding_id}`` and ``/findings/{id}``
    compare equal) and a documented path written without the ``/api/v1`` prefix
    is treated as living under it, so prose may say ``GET /findings``.
    """
    if not path.startswith("/api/") and path not in OPS_PATHS:
        path = API_PREFIX + path
    return _PATH_PARAM.sub("{}", path)


def documented_routes(markdown: str) -> list[tuple[str, str]]:
    """Every ``METHOD /path`` code span in a document, as written."""
    return [(m.group(1), m.group(2)) for m in _ROUTE_SPAN.finditer(markdown)]


def render(schema: dict[str, Any]) -> str:
    """The Markdown that belongs between the two markers."""
    grouped = operations(schema)
    ordered: list[tuple[str, str]] = [(tag, title) for tag, title in TAG_TITLES if tag in grouped]
    known = {tag for tag, _ in TAG_TITLES}
    ordered += sorted((tag, tag.replace("-", " ").capitalize()) for tag in grouped if tag not in known and tag != "ops")
    if "ops" in grouped:
        ordered.append(("ops", "Operational endpoints (no auth, outside /api/v1)"))

    total = sum(len(rows) for rows in grouped.values())
    out = [
        BEGIN_MARKER,
        "",
        f"_{total} operations, generated from the application's OpenAPI schema by "
        "`scripts/gen-api-docs.py`. Do not edit by hand._",
        "",
    ]
    for tag, title in ordered:
        rows = grouped[tag]
        out.append(f"### {title}")
        out.append("")
        out.append("| Method | Path | Purpose |")
        out.append("|--------|------|---------|")
        for method, path, desc in rows:
            out.append(f"| `{method}` | `{path}` | {desc} |")
        out.append("")
    out.append(END_MARKER)
    return "\n".join(out)


def splice(document: str, generated: str) -> str:
    """Replace the block between the markers in ``document`` with ``generated``."""
    start = document.find(BEGIN_MARKER)
    end = document.find(END_MARKER)
    if start == -1 or end == -1 or end < start:
        raise ValueError("docs/api.md is missing the generated-routes markers")
    end += len(END_MARKER)
    return document[:start] + generated + document[end:]


def generated_block(document: str) -> str:
    """The block currently on disk, markers included."""
    start = document.find(BEGIN_MARKER)
    end = document.find(END_MARKER)
    if start == -1 or end == -1 or end < start:
        raise ValueError("docs/api.md is missing the generated-routes markers")
    return document[start : end + len(END_MARKER)]
