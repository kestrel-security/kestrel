# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Default widget presets and catalog metadata for dashboards."""

from __future__ import annotations

from typing import Any

# Built-in posture widgets as preset query_spec entries.
PRESET_WIDGETS: dict[str, dict[str, Any]] = {
    "first_run": {
        "title": "Get started",
        "description": "First-run checklist (shown when onboarding is incomplete).",
        "viz_type": "preset",
        "query_spec": {"preset": "first_run"},
        "layout": {"x": 0, "y": 0, "w": 12, "h": 4},
        "in_default": True,
    },
    "summary_metrics": {
        "title": "Summary metrics",
        "description": "Open findings, integration health, sync issues, webhook delivery.",
        "viz_type": "preset",
        "query_spec": {"preset": "summary_metrics"},
        "layout": {"x": 0, "y": 0, "w": 12, "h": 4},
        "in_default": True,
    },
    "open_by_severity": {
        "title": "Open by severity",
        "description": "Open findings broken down by severity.",
        "viz_type": "bar",
        "query_spec": {
            "entity": "finding",
            "filters": [{"field": "status", "op": "eq", "value": "open"}],
            "group_by": ["severity"],
            "metric": {"fn": "count", "field": "*"},
            "order_by": [{"field": "count", "dir": "desc"}],
            "limit": 20,
        },
        "layout": {"x": 0, "y": 4, "w": 6, "h": 5},
        "in_default": True,
    },
    "by_status": {
        "title": "By status",
        "description": "Findings counts by status.",
        "viz_type": "pie",
        "query_spec": {
            "entity": "finding",
            "filters": [],
            "group_by": ["status"],
            "metric": {"fn": "count", "field": "*"},
            "order_by": [{"field": "count", "dir": "desc"}],
            "limit": 20,
        },
        "layout": {"x": 6, "y": 4, "w": 6, "h": 5},
        "in_default": True,
    },
    "top_failing_policies": {
        "title": "Top failing policies",
        "description": "Policies with the most open findings.",
        "viz_type": "preset",
        "query_spec": {"preset": "top_failing_policies"},
        "layout": {"x": 0, "y": 9, "w": 6, "h": 5},
        "in_default": True,
    },
    "recent_open_findings": {
        "title": "Recent open findings",
        "description": "Latest open findings.",
        "viz_type": "preset",
        "query_spec": {"preset": "recent_open_findings"},
        "layout": {"x": 6, "y": 9, "w": 6, "h": 5},
        "in_default": True,
    },
    "aging_open_findings": {
        "title": "Aging open findings",
        "description": "Open findings by age buckets (SLA-style).",
        "viz_type": "preset",
        "query_spec": {"preset": "aging_open_findings"},
        "layout": {"x": 0, "y": 9, "w": 6, "h": 5},
        "in_default": False,
    },
    "connector_health": {
        "title": "Connector health",
        "description": "Healthy / failed / stale / never-synced integration counts.",
        "viz_type": "donut",
        "query_spec": {
            "entity": "connector",
            "filters": [],
            "group_by": ["health"],
            "metric": {"fn": "count", "field": "*"},
            "limit": 20,
        },
        "layout": {"x": 6, "y": 9, "w": 6, "h": 5},
        "in_default": False,
    },
    "my_open_findings": {
        "title": "My open findings",
        "description": "Open findings assigned to you.",
        "viz_type": "preset",
        "query_spec": {"preset": "my_open_findings"},
        "layout": {"x": 0, "y": 14, "w": 6, "h": 5},
        "in_default": False,
    },
    "unassigned_open": {
        "title": "Unassigned open",
        "description": "Open findings with no assignee.",
        "viz_type": "preset",
        "query_spec": {"preset": "unassigned_open"},
        "layout": {"x": 6, "y": 14, "w": 6, "h": 5},
        "in_default": False,
    },
}

# Named board templates (GWS / Okta / exec).
BOARD_TEMPLATES: list[dict[str, Any]] = [
    {
        "name": "Okta",
        "slug": "okta",
        "description": "Open findings and connector health for Okta.",
        "widget_keys": ["summary_metrics", "open_by_severity", "by_status", "connector_health"],
        "extra_filters": {"application_type": "okta"},
    },
    {
        "name": "Google Workspace",
        "slug": "google-workspace",
        "description": "Open findings and connector health for Google Workspace.",
        "widget_keys": ["summary_metrics", "open_by_severity", "by_status", "connector_health"],
        "extra_filters": {"application_type": "google_workspace"},
    },
    {
        "name": "Exec weekly",
        "slug": "exec-weekly",
        "description": "High-level posture for leadership review.",
        "widget_keys": [
            "summary_metrics",
            "open_by_severity",
            "aging_open_findings",
            "connector_health",
        ],
        "extra_filters": {},
    },
]


def catalog_presets() -> list[dict[str, Any]]:
    return [
        {
            "id": key,
            "title": meta["title"],
            "description": meta["description"],
            "viz_type": meta["viz_type"],
            "query_spec": meta["query_spec"],
            "layout": meta["layout"],
            "in_default": meta["in_default"],
        }
        for key, meta in PRESET_WIDGETS.items()
    ]


def default_widget_defs() -> list[dict[str, Any]]:
    return [{"widget_key": key, **meta} for key, meta in PRESET_WIDGETS.items() if meta["in_default"]]
