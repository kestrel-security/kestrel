# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Multi-dashboard behavior beyond the auth/tenant matrices: create/widget/
duplicate/set-default lifecycle and the query-preview execution path.
"""

from __future__ import annotations

from kestrel.db.models.operator import OperatorRole
from kestrel.testing import api_client
from kestrel.testing.factories import make_connector_instance


def test_create_dashboard_then_add_a_widget(db_session):
    client = api_client(db_session, OperatorRole.ADMIN)

    created = client.post("/api/v1/dashboards", json={"name": "SecOps overview"})
    assert created.status_code == 200
    dashboard_id = created.json()["id"]

    widget = client.post(
        f"/api/v1/dashboards/{dashboard_id}/widgets",
        json={
            "widget_key": "open_findings_by_severity",
            "title": "Open findings by severity",
            "viz_type": "bar",
            "query_spec": {"entity": "finding", "group_by": ["severity"]},
        },
    )
    assert widget.status_code == 200
    widget_id = widget.json()["id"]

    detail = client.get(f"/api/v1/dashboards/{dashboard_id}")
    assert detail.status_code == 200
    assert any(w["id"] == widget_id for w in detail.json().get("widgets", []))


def test_create_dashboard_rejects_a_duplicate_slug(db_session):
    client = api_client(db_session, OperatorRole.ADMIN)

    first = client.post("/api/v1/dashboards", json={"name": "Duplicate slug test"})
    assert first.status_code == 200

    second = client.post("/api/v1/dashboards", json={"name": "Duplicate slug test"})
    assert second.status_code == 400


def test_analyst_requesting_org_visibility_is_downgraded_to_private(db_session):
    """boards_svc.create_dashboard: only admins can publish an org-visible
    board -- an analyst asking for visibility="org" silently gets "private"
    instead of a 403, so the picker never dead-ends a non-admin author."""
    analyst = api_client(db_session, OperatorRole.ANALYST)
    admin = api_client(db_session, OperatorRole.ADMIN, org=analyst.kestrel_org)

    analyst_board = analyst.post("/api/v1/dashboards", json={"name": "Analyst board", "visibility": "org"})
    admin_board = admin.post("/api/v1/dashboards", json={"name": "Admin board", "visibility": "org"})

    assert analyst_board.status_code == 200
    assert analyst_board.json()["visibility"] == "private"
    assert admin_board.status_code == 200
    assert admin_board.json()["visibility"] == "org"


def test_duplicate_dashboard_creates_a_second_row(db_session):
    client = api_client(db_session, OperatorRole.ADMIN)
    created = client.post("/api/v1/dashboards", json={"name": "Original"})
    dashboard_id = created.json()["id"]

    duplicated = client.post(f"/api/v1/dashboards/{dashboard_id}/duplicate")

    assert duplicated.status_code == 200
    assert duplicated.json()["id"] != dashboard_id

    listed = client.get("/api/v1/dashboards")
    ids = {d["id"] for d in listed.json()["dashboards"]}
    assert dashboard_id in ids
    assert duplicated.json()["id"] in ids


def test_set_default_requires_admin_even_though_create_only_needs_analyst(db_session):
    client = api_client(db_session, OperatorRole.ANALYST)
    created = client.post("/api/v1/dashboards", json={"name": "Analyst-created"})
    dashboard_id = created.json()["id"]

    response = client.post(f"/api/v1/dashboards/{dashboard_id}/set-default")

    assert response.status_code == 403


def test_add_widget_rejects_a_query_spec_that_cannot_run(db_session):
    client = api_client(db_session, OperatorRole.ADMIN)
    dashboard_id = client.post("/api/v1/dashboards", json={"name": "Bad widget"}).json()["id"]

    response = client.post(
        f"/api/v1/dashboards/{dashboard_id}/widgets",
        json={"widget_key": "bad", "title": "Bad", "viz_type": "bar", "query_spec": {"entity": "findings"}},
    )

    assert response.status_code == 400


def test_query_preview_returns_the_posture_trend_series(db_session):
    client = api_client(db_session, OperatorRole.ANALYST)

    response = client.post(
        "/api/v1/dashboards/query/preview",
        json={"query_spec": {"entity": "posture_trend", "time_range": {"last": "30d"}}},
    )

    assert response.status_code == 200
    assert response.json()["kind"] == "timeseries"


def test_query_preview_applies_connector_filters(db_session):
    client = api_client(db_session, OperatorRole.ANALYST)
    org = client.kestrel_org
    make_connector_instance(db_session, org)
    make_connector_instance(db_session, org)
    db_session.flush()

    def count(filters):
        spec = {"entity": "connector", "filters": filters}
        return client.post("/api/v1/dashboards/query/preview", json={"query_spec": spec}).json()["total"]

    assert count([]) == 2
    assert count([{"field": "health", "op": "eq", "value": "never"}]) == 2
    assert count([{"field": "health", "op": "neq", "value": "never"}]) == 0


def test_query_preview_rejects_an_unknown_entity(db_session):
    client = api_client(db_session, OperatorRole.ANALYST)

    response = client.post("/api/v1/dashboards/query/preview", json={"query_spec": {"entity": "policy"}})

    assert response.status_code == 400


def test_query_preview_rejects_an_invalid_spec(db_session):
    client = api_client(db_session, OperatorRole.ANALYST)

    response = client.post("/api/v1/dashboards/query/preview", json={"query_spec": {}})

    assert response.status_code == 400


def test_delete_removes_a_dashboard(db_session):
    client = api_client(db_session, OperatorRole.ADMIN)
    created = client.post("/api/v1/dashboards", json={"name": "To delete"})
    dashboard_id = created.json()["id"]

    response = client.delete(f"/api/v1/dashboards/{dashboard_id}")
    assert response.status_code == 204

    follow_up = client.get(f"/api/v1/dashboards/{dashboard_id}")
    assert follow_up.status_code == 404


def test_delete_clears_a_pinned_home_that_pointed_at_the_board(db_session):
    client = api_client(db_session, OperatorRole.ADMIN)
    created = client.post("/api/v1/dashboards", json={"name": "Scratch board"})
    dashboard_id = created.json()["id"]

    pinned = client.post("/api/v1/dashboards/pin-home", json={"dashboard_id": dashboard_id})
    assert pinned.status_code == 200
    assert pinned.json()["dashboard_home_id"] == dashboard_id

    deleted = client.delete(f"/api/v1/dashboards/{dashboard_id}")
    assert deleted.status_code == 204

    me = client.get("/api/v1/auth/me").json()
    assert "dashboard_home_id" not in (me.get("ui_preferences") or {})


def test_delete_rejects_the_default_home_board(db_session):
    client = api_client(db_session, OperatorRole.ADMIN)
    listed = client.get("/api/v1/dashboards").json()["dashboards"]
    home = next(d for d in listed if d["is_default"])

    response = client.delete(f"/api/v1/dashboards/{home['id']}")

    assert response.status_code == 400
    assert client.get(f"/api/v1/dashboards/{home['id']}").status_code == 200
