# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""JSON helpers for crossing the policy eval process boundary."""

from __future__ import annotations

import contextlib
import re
import uuid
from datetime import date, datetime
from typing import Any

_ISO_DATETIME_RE = re.compile(r"^\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:\d{2})?$")


def row_to_jsonable(row: dict[str, Any]) -> dict[str, Any]:
    """Convert a dataload row into a JSON-serializable dict."""
    return {key: _to_jsonable(value) for key, value in row.items()}


def rows_to_jsonable(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [row_to_jsonable(row) for row in rows]


def row_from_jsonable(row: dict[str, Any]) -> dict[str, Any]:
    """Restore UUID subject ids and ISO datetimes after JSON round-trip."""
    out = {key: _from_jsonable(value) for key, value in row.items()}
    subject_id = out.get("_subject_id")
    if isinstance(subject_id, str):
        with contextlib.suppress(ValueError):
            out["_subject_id"] = uuid.UUID(subject_id)
    return out


def _to_jsonable(value: Any) -> Any:
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, dict):
        return {str(k): _to_jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_to_jsonable(v) for v in value]
    return str(value)


def _from_jsonable(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): _from_jsonable(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_from_jsonable(v) for v in value]
    if isinstance(value, str) and _ISO_DATETIME_RE.match(value):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return value
    return value
