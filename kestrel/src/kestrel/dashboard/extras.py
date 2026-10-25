# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Dashboard query result cache and the webhook summary payload."""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from typing import Any

from sqlalchemy.orm import Session

from kestrel.dashboard.query_dsl import QuerySpec, execute_query, parse_query_spec

# Process-local TTL cache (org-scoped keys). Fine for single-worker API; not shared.
_CACHE: dict[str, tuple[float, dict[str, Any]]] = {}
_CACHE_TTL_SECONDS = 30.0
_CACHE_MAX = 256


def _cache_key(org_id: uuid.UUID, spec: dict[str, Any], viewer: uuid.UUID | None) -> str:
    payload = json.dumps(
        {"org": str(org_id), "viewer": str(viewer) if viewer else None, "spec": spec},
        sort_keys=True,
        default=str,
    )
    return hashlib.sha256(payload.encode()).hexdigest()


def execute_query_cached(
    db: Session,
    *,
    org_id: uuid.UUID,
    spec: QuerySpec | dict[str, Any],
    viewer_operator_id: uuid.UUID | None = None,
    ttl_seconds: float = _CACHE_TTL_SECONDS,
) -> dict[str, Any]:
    parsed = parse_query_spec(spec)
    raw = parsed.model_dump(mode="json")
    key = _cache_key(org_id, raw, viewer_operator_id)
    now = time.monotonic()
    hit = _CACHE.get(key)
    if hit and hit[0] > now:
        return {**hit[1], "cached": True}
    result = execute_query(db, org_id=org_id, spec=parsed, viewer_operator_id=viewer_operator_id)
    if len(_CACHE) >= _CACHE_MAX:
        # Drop oldest ~half by expiry
        expired = [k for k, (exp, _) in _CACHE.items() if exp <= now]
        for k in expired[: _CACHE_MAX // 2] or list(_CACHE.keys())[:64]:
            _CACHE.pop(k, None)
    _CACHE[key] = (now + ttl_seconds, result)
    return {**result, "cached": False}


def dashboard_webhook_summary(snapshot: dict[str, Any]) -> dict[str, Any]:
    """Compact JSON suitable for outbound webhook / Slack-style payloads."""
    dash = snapshot.get("dashboard") or {}
    widgets = []
    for w in snapshot.get("widgets") or []:
        data = w.get("data") or {}
        widgets.append(
            {
                "title": w.get("title"),
                "viz_type": w.get("viz_type"),
                "total": data.get("total"),
                "series": (data.get("series") or [])[:10],
                "preset": data.get("preset"),
            }
        )
    return {
        "event": "dashboard.summary",
        "exported_at": snapshot.get("exported_at"),
        "dashboard": {
            "id": dash.get("id"),
            "name": dash.get("name"),
            "slug": dash.get("slug"),
        },
        "widgets": widgets,
    }
