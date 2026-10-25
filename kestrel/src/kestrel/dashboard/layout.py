# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Per-operator dashboard widget layout.

Persists under ``Operator.ui_preferences["dashboard_layout"]`` as a small JSON
document. A later change may move this to a dedicated table / add resize metadata.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from kestrel.db.models.operator import Operator

LAYOUT_VERSION = 1

# Built-in widgets. Default layout stays the overview; the catalog adds
# optional catalog widgets operators can add in edit mode.
WIDGET_CATALOG: dict[str, dict[str, str]] = {
    "first_run": {
        "title": "Get started",
        "description": "First-run checklist (shown when onboarding is incomplete).",
    },
    "summary_metrics": {
        "title": "Summary metrics",
        "description": "Open findings, integration health, sync issues, webhook delivery.",
    },
    "open_by_severity": {
        "title": "Open by severity",
        "description": "Open findings broken down by severity.",
    },
    "by_status": {
        "title": "By status",
        "description": "Findings counts by status.",
    },
    "top_failing_policies": {
        "title": "Top failing policies",
        "description": "Policies with the most open findings.",
    },
    "recent_open_findings": {
        "title": "Recent open findings",
        "description": "Latest open findings.",
    },
    # Catalog widgets (optional — not in default layout)
    "aging_open_findings": {
        "title": "Aging open findings",
        "description": "Open findings by age buckets (SLA-style).",
    },
    "connector_health": {
        "title": "Connector health",
        "description": "Healthy / failed / stale / never-synced integration counts.",
    },
    "my_open_findings": {
        "title": "My open findings",
        "description": "Open findings assigned to you.",
    },
    "unassigned_open": {
        "title": "Unassigned open",
        "description": "Open findings with no assignee.",
    },
}

DEFAULT_WIDGET_IDS: tuple[str, ...] = (
    "first_run",
    "summary_metrics",
    "open_by_severity",
    "by_status",
    "top_failing_policies",
    "recent_open_findings",
)


def default_layout() -> dict[str, Any]:
    return {
        "version": LAYOUT_VERSION,
        "widgets": [{"id": wid} for wid in DEFAULT_WIDGET_IDS],
    }


def catalog_entries() -> list[dict[str, Any]]:
    default_set = set(DEFAULT_WIDGET_IDS)
    return [
        {
            "id": wid,
            "title": meta["title"],
            "description": meta["description"],
            "in_default": wid in default_set,
        }
        for wid, meta in WIDGET_CATALOG.items()
    ]


def _normalize_widgets(raw: Any) -> list[dict[str, str]]:
    if not isinstance(raw, list):
        raise ValueError("widgets must be a list")
    seen: set[str] = set()
    out: list[dict[str, str]] = []
    for item in raw:
        if isinstance(item, str):
            wid = item
        elif isinstance(item, dict) and isinstance(item.get("id"), str):
            wid = item["id"]
        else:
            raise ValueError("each widget must be an object with string id")
        if wid not in WIDGET_CATALOG:
            raise ValueError(f"unknown widget id: {wid}")
        if wid in seen:
            raise ValueError(f"duplicate widget id: {wid}")
        seen.add(wid)
        out.append({"id": wid})
    return out


def normalize_layout(payload: dict[str, Any] | None) -> dict[str, Any]:
    """Validate and normalize a layout body. Empty widgets is allowed (edit mode)."""
    if payload is None:
        return default_layout()
    if not isinstance(payload, dict):
        raise ValueError("layout must be an object")
    version = payload.get("version", LAYOUT_VERSION)
    if version != LAYOUT_VERSION:
        raise ValueError(f"unsupported layout version: {version}")
    widgets = _normalize_widgets(payload.get("widgets", []))
    return {"version": LAYOUT_VERSION, "widgets": widgets}


def layout_from_preferences(prefs: dict[str, Any] | None) -> dict[str, Any]:
    if not prefs:
        return default_layout()
    stored = prefs.get("dashboard_layout")
    if not stored:
        return default_layout()
    try:
        return normalize_layout(stored)
    except ValueError:
        # Corrupt prefs should not break the home page.
        return default_layout()


def get_layout_response(operator: Operator) -> dict[str, Any]:
    layout = layout_from_preferences(operator.ui_preferences)
    return {
        "layout": layout,
        "default_layout": default_layout(),
        "catalog": catalog_entries(),
        "is_default": layout == default_layout(),
    }


def save_layout(db: Session, operator: Operator, payload: dict[str, Any]) -> dict[str, Any]:
    layout = normalize_layout(payload)
    prefs = dict(operator.ui_preferences or {})
    prefs["dashboard_layout"] = layout
    operator.ui_preferences = prefs
    db.add(operator)
    db.flush()
    return get_layout_response(operator)


def reset_layout(db: Session, operator: Operator) -> dict[str, Any]:
    prefs = dict(operator.ui_preferences or {})
    prefs.pop("dashboard_layout", None)
    operator.ui_preferences = prefs
    db.add(operator)
    db.flush()
    return get_layout_response(operator)


# Re-export for tests that want a deep copy of defaults.
