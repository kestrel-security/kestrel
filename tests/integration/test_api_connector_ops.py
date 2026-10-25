# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Connector instance operations the lifecycle tests leave thin: secret
status and upsert, the sync schedule, run history and run detail, the legacy
create shape, the health center filter, and the sync conflict guard.

Instances are created through the real installed `github` connector in
fixture mode, so nothing touches the network.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from kestrel.db.models.audit import AuditLog
from kestrel.db.models.connector import ConnectorInstance, ConnectorRun, ConnectorRunStatus, ConnectorRunTrigger
from kestrel.db.models.operator import OperatorRole
from kestrel.testing import api_client, make_application_instance, make_connector
from sqlalchemy import select

from tests.integration.test_api_factories import FakeTaskQueue


def _create_github_instance(client, **overrides) -> str:
    login = f"test-org-{uuid.uuid4().hex[:8]}"
    body = {
        "connector_name": "github",
        "display_name": "Test GitHub org",
        "external_tenant_ref": login,
        "auth_method": "pat",
        "sync_mode": "fixtures",
        "config": {"org_login": login},
    }
    body.update(overrides)
    response = client.post("/api/v1/connector-instances", json=body)
    assert response.status_code == 201, response.text
    return response.json()["id"]


def _add_run(session, instance_id: str, *, status: ConnectorRunStatus, started_at: datetime) -> ConnectorRun:
    instance = session.get(ConnectorInstance, uuid.UUID(instance_id))
    run = ConnectorRun(
        id=uuid.uuid4(),
        org_id=instance.org_id,
        connector_instance_id=instance.id,
        status=status,
        started_at=started_at,
        finished_at=None if status == ConnectorRunStatus.RUNNING else started_at + timedelta(minutes=1),
        object_counts={"identity": 3},
        triggered_by=ConnectorRunTrigger.MANUAL,
    )
    session.add(run)
    session.flush()
    return run


def _audit_actions(session, org_id) -> list[str]:
    return list(session.scalars(select(AuditLog.action).where(AuditLog.org_id == org_id)).all())


# --- secrets -------------------------------------------------------------


def test_secret_status_lists_declared_fields_without_values(db_session):
    client = api_client(db_session, OperatorRole.ANALYST)
    instance_id = _create_github_instance(client)

    response = client.get(f"/api/v1/connector-instances/{instance_id}/secrets")

    assert response.status_code == 200
    body = response.json()
    assert body["declared_fields"] == ["token"]
    assert body["configured_fields"] == []
    assert body["missing_fields"] == ["token"]
    assert body["fields"] == [{"name": "token", "configured": False}]


def test_put_secrets_stores_field_and_never_echoes_the_value(db_session):
    client = api_client(db_session, OperatorRole.ANALYST)
    instance_id = _create_github_instance(client)

    response = client.put(
        f"/api/v1/connector-instances/{instance_id}/secrets",
        json={"secrets": {"token": "ghp_secret_value_never_returned"}},
    )

    assert response.status_code == 200
    assert "ghp_secret_value_never_returned" not in response.text
    assert response.json()["configured_fields"] == ["token"]
    assert response.json()["missing_fields"] == []
    status = client.get(f"/api/v1/connector-instances/{instance_id}/secrets").json()
    assert status["fields"] == [{"name": "token", "configured": True}]
    assert "connector_instance.secrets_updated" in _audit_actions(db_session, client.kestrel_org.id)


def test_put_secrets_with_a_blank_value_keeps_the_stored_one(db_session):
    client = api_client(db_session, OperatorRole.ANALYST)
    instance_id = _create_github_instance(client)
    client.put(f"/api/v1/connector-instances/{instance_id}/secrets", json={"secrets": {"token": "first-value"}})

    response = client.put(f"/api/v1/connector-instances/{instance_id}/secrets", json={"secrets": {"token": "   "}})

    assert response.status_code == 200
    assert response.json()["configured_fields"] == ["token"]


def test_put_secrets_rejects_an_undeclared_field(db_session):
    client = api_client(db_session, OperatorRole.ANALYST)
    instance_id = _create_github_instance(client)

    response = client.put(
        f"/api/v1/connector-instances/{instance_id}/secrets",
        json={"secrets": {"not_a_declared_field": "x"}},
    )

    assert response.status_code == 400


def test_secrets_routes_are_404_for_an_unknown_instance(db_session):
    client = api_client(db_session, OperatorRole.ANALYST)
    missing = uuid.uuid4()

    assert client.get(f"/api/v1/connector-instances/{missing}/secrets").status_code == 404
    put = client.put(f"/api/v1/connector-instances/{missing}/secrets", json={"secrets": {"token": "x"}})
    assert put.status_code == 404


# --- schedule ------------------------------------------------------------


def test_set_and_clear_the_sync_schedule(db_session):
    client = api_client(db_session, OperatorRole.ANALYST)
    instance_id = _create_github_instance(client)

    set_response = client.patch(f"/api/v1/connector-instances/{instance_id}/schedule", json={"schedule_cron": "0 */6 * * *"})
    assert set_response.status_code == 200
    assert db_session.get(ConnectorInstance, uuid.UUID(instance_id)).schedule_cron == "0 */6 * * *"

    clear_response = client.patch(f"/api/v1/connector-instances/{instance_id}/schedule", json={"schedule_cron": None})
    assert clear_response.status_code == 200
    assert db_session.get(ConnectorInstance, uuid.UUID(instance_id)).schedule_cron is None
    assert _audit_actions(db_session, client.kestrel_org.id).count("connector_instance.schedule_updated") == 2


def test_an_invalid_cron_is_rejected_and_nothing_changes(db_session):
    client = api_client(db_session, OperatorRole.ANALYST)
    instance_id = _create_github_instance(client, schedule_cron="0 3 * * *")

    response = client.patch(f"/api/v1/connector-instances/{instance_id}/schedule", json={"schedule_cron": "not a cron"})

    assert response.status_code == 400
    assert db_session.get(ConnectorInstance, uuid.UUID(instance_id)).schedule_cron == "0 3 * * *"


def test_schedule_is_404_for_an_unknown_instance(db_session):
    client = api_client(db_session, OperatorRole.ANALYST)

    response = client.patch(f"/api/v1/connector-instances/{uuid.uuid4()}/schedule", json={"schedule_cron": None})

    assert response.status_code == 404


def test_schedule_is_404_for_another_orgs_instance(db_session):
    owner = api_client(db_session, OperatorRole.ANALYST)
    instance_id = _create_github_instance(owner)
    intruder = api_client(db_session, OperatorRole.ANALYST)

    response = intruder.patch(f"/api/v1/connector-instances/{instance_id}/schedule", json={"schedule_cron": "* * * * *"})

    assert response.status_code == 404
    assert db_session.get(ConnectorInstance, uuid.UUID(instance_id)).schedule_cron is None


# --- runs ----------------------------------------------------------------


def test_runs_are_listed_newest_first_and_limited(db_session):
    client = api_client(db_session, OperatorRole.ANALYST)
    instance_id = _create_github_instance(client)
    base = datetime(2026, 1, 1, tzinfo=UTC)
    older = _add_run(db_session, instance_id, status=ConnectorRunStatus.FAILED, started_at=base)
    newer = _add_run(db_session, instance_id, status=ConnectorRunStatus.SUCCESS, started_at=base + timedelta(hours=1))
    db_session.commit()

    response = client.get(f"/api/v1/connector-instances/{instance_id}/runs")

    assert response.status_code == 200
    rows = response.json()
    assert [r["id"] for r in rows] == [str(newer.id), str(older.id)]
    assert rows[0]["status"] == "success"
    assert rows[0]["triggered_by"] == "manual"
    assert rows[0]["object_counts"] == {"identity": 3}
    assert rows[0]["detail_path"] == f"/connectors/runs/{newer.id}"

    limited = client.get(f"/api/v1/connector-instances/{instance_id}/runs", params={"limit": 1}).json()
    assert [r["id"] for r in limited] == [str(newer.id)]


def test_runs_list_is_404_for_an_unknown_instance(db_session):
    client = api_client(db_session, OperatorRole.READ_ONLY)

    assert client.get(f"/api/v1/connector-instances/{uuid.uuid4()}/runs").status_code == 404


def test_run_detail_serializes_the_run_and_its_instance(db_session):
    client = api_client(db_session, OperatorRole.ANALYST)
    instance_id = _create_github_instance(client)
    run = _add_run(db_session, instance_id, status=ConnectorRunStatus.SUCCESS, started_at=datetime(2026, 2, 1, tzinfo=UTC))
    db_session.commit()

    response = client.get(f"/api/v1/connector-runs/{run.id}")

    assert response.status_code == 200
    body = response.json()
    assert body["id"] == str(run.id)
    assert body["connector_instance"]["id"] == instance_id
    assert body["policy_evaluations"] == []


def test_run_detail_and_changes_are_404_for_an_unknown_run(db_session):
    client = api_client(db_session, OperatorRole.READ_ONLY)
    missing = uuid.uuid4()

    assert client.get(f"/api/v1/connector-runs/{missing}").status_code == 404
    assert client.get(f"/api/v1/connector-runs/{missing}/changes").status_code == 404


def test_run_changes_for_a_run_with_no_drift_is_empty(db_session):
    client = api_client(db_session, OperatorRole.ANALYST)
    instance_id = _create_github_instance(client)
    run = _add_run(db_session, instance_id, status=ConnectorRunStatus.SUCCESS, started_at=datetime(2026, 2, 1, tzinfo=UTC))
    db_session.commit()

    response = client.get(f"/api/v1/connector-runs/{run.id}/changes")

    assert response.status_code == 200
    body = response.json()
    assert body["run_id"] == str(run.id)
    assert body["changes"] == []


def test_run_changes_rejects_an_unknown_change_type(db_session):
    client = api_client(db_session, OperatorRole.ANALYST)
    instance_id = _create_github_instance(client)
    run = _add_run(db_session, instance_id, status=ConnectorRunStatus.SUCCESS, started_at=datetime(2026, 2, 1, tzinfo=UTC))
    db_session.commit()

    response = client.get(f"/api/v1/connector-runs/{run.id}/changes", params={"change_type": "not-a-change-type"})

    assert response.status_code == 422


# --- sync guard ----------------------------------------------------------


def test_sync_is_refused_while_a_run_is_in_progress(db_session):
    tasks = FakeTaskQueue()
    client = api_client(db_session, OperatorRole.ANALYST, task_queue=tasks)
    instance_id = _create_github_instance(client)
    running = _add_run(db_session, instance_id, status=ConnectorRunStatus.RUNNING, started_at=datetime.now(UTC))
    db_session.commit()

    response = client.post(f"/api/v1/connector-instances/{instance_id}/sync")

    assert response.status_code == 409
    assert response.json()["detail"]["run_id"] == str(running.id)
    assert tasks.connector_syncs == []


def test_sync_reports_503_when_the_queue_is_unavailable(db_session):
    class BrokenQueue(FakeTaskQueue):
        def enqueue_connector_sync(self, **_kwargs) -> str:
            raise ConnectionError("broker unreachable")

    client = api_client(db_session, OperatorRole.ANALYST, task_queue=BrokenQueue())
    instance_id = _create_github_instance(client)

    response = client.post(f"/api/v1/connector-instances/{instance_id}/sync")

    assert response.status_code == 503
    assert "broker unreachable" in response.json()["detail"]


def test_sync_is_404_for_an_unknown_instance(db_session):
    client = api_client(db_session, OperatorRole.ANALYST, task_queue=FakeTaskQueue())

    assert client.post(f"/api/v1/connector-instances/{uuid.uuid4()}/sync").status_code == 404


# --- create / update edge cases ------------------------------------------


def test_legacy_create_shape_attaches_to_existing_inventory(db_session):
    client = api_client(db_session, OperatorRole.ANALYST)
    connector = make_connector(db_session)
    app_instance = make_application_instance(db_session, client.kestrel_org)
    db_session.commit()

    response = client.post(
        "/api/v1/connector-instances",
        json={
            "connector_id": str(connector.id),
            "application_instance_id": str(app_instance.id),
            "auth_method": "pat",
            "sync_mode": "fixtures",
            "schedule_cron": "0 * * * *",
        },
    )

    assert response.status_code == 201, response.text
    created = db_session.get(ConnectorInstance, uuid.UUID(response.json()["id"]))
    assert created.application_instance_id == app_instance.id
    assert created.schedule_cron == "0 * * * *"


def test_legacy_create_rejects_bad_inputs(db_session):
    client = api_client(db_session, OperatorRole.ANALYST)
    connector = make_connector(db_session)
    app_instance = make_application_instance(db_session, client.kestrel_org)
    foreign_app_instance = make_application_instance(db_session, api_client(db_session, OperatorRole.ADMIN).kestrel_org)
    db_session.commit()
    base = {
        "connector_id": str(connector.id),
        "application_instance_id": str(app_instance.id),
        "auth_method": "pat",
        "sync_mode": "fixtures",
    }

    cases = [
        {"schedule_cron": "nope"},
        {"connector_id": str(uuid.uuid4())},
        {"application_instance_id": str(foreign_app_instance.id)},
        {"auth_method": "not-an-auth-method"},
        {"sync_mode": "not-a-sync-mode"},
        {"config": {"api_token": "secret-in-config"}},
    ]
    for overrides in cases:
        response = client.post("/api/v1/connector-instances", json={**base, **overrides})
        assert response.status_code == 400, (overrides, response.text)


def test_create_via_connector_name_requires_display_name_and_tenant(db_session):
    client = api_client(db_session, OperatorRole.ANALYST)

    no_display = client.post(
        "/api/v1/connector-instances",
        json={"connector_name": "github", "external_tenant_ref": "x", "auth_method": "pat"},
    )
    no_tenant = client.post(
        "/api/v1/connector-instances",
        json={"connector_name": "github", "display_name": "GitHub", "auth_method": "pat"},
    )

    assert no_display.status_code == 422
    assert no_tenant.status_code == 422


def test_create_with_an_unknown_connector_name_is_400(db_session):
    client = api_client(db_session, OperatorRole.ANALYST)

    response = client.post(
        "/api/v1/connector-instances",
        json={
            "connector_name": f"no-such-connector-{uuid.uuid4().hex[:6]}",
            "display_name": "Nope",
            "external_tenant_ref": "nope",
            "auth_method": "pat",
        },
    )

    assert response.status_code == 400


def test_update_rejects_invalid_values(db_session):
    client = api_client(db_session, OperatorRole.ANALYST)
    instance_id = _create_github_instance(client)
    path = f"/api/v1/connector-instances/{instance_id}"

    assert client.patch(path, json={"sync_mode": "sideways"}).status_code == 400
    assert client.patch(path, json={"auth_method": "carrier-pigeon"}).status_code == 400
    assert client.patch(path, json={"display_name": "   "}).status_code == 400
    assert client.patch(path, json={"config": {"password": "hunter2"}}).status_code == 400
    assert client.patch(f"/api/v1/connector-instances/{uuid.uuid4()}", json={}).status_code == 404


def test_update_renames_the_application_instance_and_stores_secrets(db_session):
    client = api_client(db_session, OperatorRole.ANALYST)
    instance_id = _create_github_instance(client)

    response = client.patch(
        f"/api/v1/connector-instances/{instance_id}",
        json={"display_name": "Renamed org", "auth_method": "pat", "secrets": {"token": "fresh-token-value"}},
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["secrets_cleared"] == []
    assert body["secrets_reentry_required"] is False
    assert "fresh-token-value" not in response.text
    secrets = client.get(f"/api/v1/connector-instances/{instance_id}/secrets").json()
    assert secrets["configured_fields"] == ["token"]


def test_update_rejects_an_undeclared_secret_field(db_session):
    client = api_client(db_session, OperatorRole.ANALYST)
    instance_id = _create_github_instance(client)

    response = client.patch(f"/api/v1/connector-instances/{instance_id}", json={"secrets": {"bogus": "x"}})

    assert response.status_code == 400


# --- health center & probe -----------------------------------------------


def test_health_center_rejects_an_unknown_health_filter(db_session):
    client = api_client(db_session, OperatorRole.READ_ONLY)

    response = client.get("/api/v1/connector-instances/health", params={"health": "bogus"})

    assert response.status_code == 422


def test_health_center_filters_never_synced_instances(db_session):
    client = api_client(db_session, OperatorRole.ANALYST)
    instance_id = _create_github_instance(client)

    response = client.get("/api/v1/connector-instances/health", params={"health": "never"})

    assert response.status_code == 200
    assert instance_id in response.text


def test_probe_rejects_an_unknown_connector(db_session):
    client = api_client(db_session, OperatorRole.ANALYST)

    response = client.post(
        "/api/v1/connectors/probe",
        json={"connector_name": f"no-such-connector-{uuid.uuid4().hex[:6]}", "sync_mode": "fixtures"},
    )

    assert response.status_code == 400
