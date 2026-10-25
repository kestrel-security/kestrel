# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Liveness and readiness.

`/healthz` says the process is up, which decides whether to restart it.
`/readyz` says its dependencies are reachable, which decides whether to send it
traffic. Conflating the two is how a deploy goes green while every request
fails on a database it cannot reach.
"""

from __future__ import annotations

from kestrel.db.models.operator import OperatorRole
from kestrel.testing import api_client


def test_healthz_is_unauthenticated_and_reports_the_running_version(db_session):
    client = api_client(db_session, OperatorRole.READ_ONLY)
    response = client.get("/healthz", headers={"Authorization": ""})

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["version"]


def test_readyz_reports_each_dependency_by_name(db_session):
    client = api_client(db_session, OperatorRole.READ_ONLY)

    response = client.get("/readyz")

    # 200 when both dependencies answer, 503 when one does not -- either is a
    # valid result here; what matters is that the body names them.
    assert response.status_code in {200, 503}
    body = response.json()
    assert set(body["checks"]) == {"database", "broker"}
    assert body["status"] == ("ready" if all(v == "ok" for v in body["checks"].values()) else "degraded")


def test_readyz_is_503_when_a_dependency_is_unreachable(db_session, monkeypatch):
    """A degraded dependency must fail the check rather than being reported ok."""
    import kestrel_api.tasks_client as tasks_client

    monkeypatch.setattr(tasks_client, "get_broker_url", lambda: "redis://127.0.0.1:59999/0")
    client = api_client(db_session, OperatorRole.READ_ONLY)

    response = client.get("/readyz")

    assert response.status_code == 503
    body = response.json()
    assert body["status"] == "degraded"
    assert body["checks"]["broker"].startswith("unavailable")
