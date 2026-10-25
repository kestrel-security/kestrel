# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Audit log filtering and export, beyond the pagination contract
(test_api_pagination.py already covers cursor mechanics for GET /audit-log).
"""

from __future__ import annotations

from kestrel.audit.service import record_audit_event
from kestrel.db.models.operator import OperatorRole
from kestrel.testing import api_client


def test_filters_by_action(db_session):
    client = api_client(db_session, OperatorRole.ADMIN)
    org = client.kestrel_org
    record_audit_event(db_session, org_id=org.id, actor_operator_id=None, action="probe.alpha")
    record_audit_event(db_session, org_id=org.id, actor_operator_id=None, action="probe.beta")
    db_session.commit()

    response = client.get("/api/v1/audit-log", params={"action": "probe.alpha"})

    assert response.status_code == 200
    actions = {row["action"] for row in response.json()["items"]}
    assert actions == {"probe.alpha"}


def test_filters_by_actor_operator_id(db_session):
    client = api_client(db_session, OperatorRole.ADMIN)
    org = client.kestrel_org
    other_actor = client.kestrel_operator
    record_audit_event(db_session, org_id=org.id, actor_operator_id=other_actor.id, action="probe.by-actor")
    record_audit_event(db_session, org_id=org.id, actor_operator_id=None, action="probe.no-actor")
    db_session.commit()

    response = client.get("/api/v1/audit-log", params={"actor_operator_id": str(other_actor.id)})

    assert response.status_code == 200
    actions = {row["action"] for row in response.json()["items"]}
    assert "probe.by-actor" in actions
    assert "probe.no-actor" not in actions


def test_export_csv_and_json(db_session):
    client = api_client(db_session, OperatorRole.ADMIN)
    org = client.kestrel_org
    record_audit_event(db_session, org_id=org.id, actor_operator_id=None, action="probe.export")
    db_session.commit()

    csv_response = client.get("/api/v1/audit-log/export", params={"format": "csv"})
    assert csv_response.status_code == 200
    assert csv_response.headers["content-type"].startswith("text/csv")
    assert "probe.export" in csv_response.text

    json_response = client.get("/api/v1/audit-log/export", params={"format": "json"})
    assert json_response.status_code == 200
    body = json_response.json()
    assert any(row["action"] == "probe.export" for row in body["items"])


def test_export_rejects_an_unknown_format(db_session):
    client = api_client(db_session, OperatorRole.ADMIN)

    response = client.get("/api/v1/audit-log/export", params={"format": "xml"})

    assert response.status_code == 422


def test_an_action_by_one_router_produces_exactly_one_row(db_session):
    """Regression guard for the audit trail's core promise: a mutation and
    its audit record commit in the same transaction, so a single API call
    produces a single row -- not zero, not a duplicate."""
    client = api_client(db_session, OperatorRole.ADMIN)

    response = client.post(
        "/api/v1/webhooks",
        json={"name": "audit probe", "url": "https://93.184.216.34/hook", "events": ["finding.opened"]},
    )
    assert response.status_code == 201

    audit = client.get("/api/v1/audit-log", params={"action": "webhook.created"})
    assert audit.status_code == 200
    matching = [row for row in audit.json()["items"] if row["target_id"] == response.json()["id"]]
    assert len(matching) == 1
