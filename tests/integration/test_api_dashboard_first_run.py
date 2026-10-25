# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Dismissing the getting-started checklist is a per-operator preference:
it flips `first_run.dismissed` on GET /dashboard for that operator only,
survives nothing else about the org changing, and is undone by restore."""

from __future__ import annotations

from kestrel.db.models.operator import OperatorRole
from kestrel.testing import api_client


def _first_run(client) -> dict:
    res = client.get("/api/v1/dashboard")
    assert res.status_code == 200
    return res.json()["first_run"]


def test_dismiss_then_restore_round_trips_for_the_caller(db_session):
    client = api_client(db_session, OperatorRole.READ_ONLY)

    assert _first_run(client)["dismissed"] is False

    dismissed = client.post("/api/v1/dashboard/first-run/dismiss")
    assert dismissed.status_code == 200
    assert dismissed.json()["dismissed"] is True
    assert dismissed.json()["dismissed_at"]
    assert _first_run(client)["dismissed"] is True
    # Stored next to the dashboard layout, no new table.
    db_session.refresh(client.kestrel_operator)
    assert client.kestrel_operator.ui_preferences["first_run_dismissed_at"]

    restored = client.post("/api/v1/dashboard/first-run/restore")
    assert restored.status_code == 200
    assert restored.json() == {"dismissed": False, "dismissed_at": None}
    assert _first_run(client)["dismissed"] is False
    db_session.refresh(client.kestrel_operator)
    assert "first_run_dismissed_at" not in client.kestrel_operator.ui_preferences


def test_dismissal_is_per_operator_not_per_org(db_session):
    alice = api_client(db_session, OperatorRole.ADMIN)
    bob = api_client(db_session, OperatorRole.ANALYST, org=alice.kestrel_org)

    assert alice.post("/api/v1/dashboard/first-run/dismiss").status_code == 200

    assert _first_run(alice)["dismissed"] is True
    assert _first_run(bob)["dismissed"] is False


def test_dismissal_leaves_the_checklist_steps_intact(db_session):
    """Dismiss hides the card; it must not pretend setup finished."""
    client = api_client(db_session, OperatorRole.ADMIN)
    before = _first_run(client)

    client.post("/api/v1/dashboard/first-run/dismiss")
    after = _first_run(client)

    assert after["complete"] == before["complete"]
    assert after["steps"] == before["steps"]
