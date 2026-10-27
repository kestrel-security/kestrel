# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""A widget whose query fails is exported as an error, not a failed export.

A spec the DSL rejects keeps its message, which is written for the operator.
Any other failure is replaced with a generic one: its text can carry SQL or
driver detail, and an export is a file that leaves the system.
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace
from typing import Any

import pytest
from kestrel.dashboard import export


def _snapshot_with_failing_widget(monkeypatch: pytest.MonkeyPatch, exc: Exception) -> dict[str, Any]:
    widget = {"id": "w1", "title": "Open findings", "viz_type": "table", "query_spec": {"entity": "finding"}}
    monkeypatch.setattr(export, "get_dashboard", lambda *a, **k: {"name": "Board", "widgets": [widget]})
    monkeypatch.setattr(export, "posture_overview", lambda *a, **k: {})

    def fail(*a: Any, **k: Any) -> dict[str, Any]:
        raise exc

    monkeypatch.setattr(export, "execute_query", fail)
    operator = SimpleNamespace(id=uuid.uuid4())
    snapshot = export.build_snapshot(None, org_id=uuid.uuid4(), dashboard_id=uuid.uuid4(), operator=operator)  # type: ignore[arg-type]
    return snapshot["widgets"][0]["data"]


def test_a_rejected_spec_keeps_its_message(monkeypatch: pytest.MonkeyPatch) -> None:
    data = _snapshot_with_failing_widget(monkeypatch, ValueError("filter field not allowed: secret"))

    assert data["kind"] == "error"
    assert data["error"] == "filter field not allowed: secret"


def test_an_internal_failure_is_not_exported(monkeypatch: pytest.MonkeyPatch) -> None:
    data = _snapshot_with_failing_widget(monkeypatch, RuntimeError("SELECT * FROM findings WHERE org_id = 'x'"))

    assert data["kind"] == "error"
    assert data["error"] == "query failed"
    assert "SELECT" not in export.snapshot_to_html({"dashboard": {}, "widgets": [{"title": "t", "data": data}]})
