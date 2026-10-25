# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Connector instance lifecycle behavior beyond the auth/tenant matrices:
creation via the `connector_name` shape, test-connection against fixture
transport, sync enqueue (captured through the injectable task queue -- never
a real broker), and delete.

Uses the real installed `github` connector package (`connectors/github`) in
fixture mode -- a real connector name, not a demo persona, and no live
network: `sync_mode="fixtures"` resolves through
`load_fixture_transport_builder`, never `httpx`.
"""

from __future__ import annotations

from kestrel.db.models.operator import OperatorRole
from kestrel.testing import api_client

from tests.integration.test_api_factories import FakeTaskQueue


def _create_github_instance(client, *, sync_mode: str = "fixtures", org_login: str | None = None):
    org_login = org_login or f"test-org-{client.kestrel_org.id.hex[:8]}"
    return client.post(
        "/api/v1/connector-instances",
        json={
            "connector_name": "github",
            "display_name": "Test GitHub org",
            "external_tenant_ref": org_login,
            "auth_method": "pat",
            "sync_mode": sync_mode,
            "config": {"org_login": org_login},
        },
    )


def test_create_connector_instance_via_connector_name(db_session):
    client = api_client(db_session, OperatorRole.ANALYST)

    response = _create_github_instance(client)

    assert response.status_code == 201
    body = response.json()
    assert body["connector_name"] == "github"
    assert body["auth_method"] == "pat"
    assert body["sync_mode"] == "fixtures"
    assert "secrets" in body  # never plaintext, but field status must be present


def test_slack_without_enterprise_id_is_accepted_and_the_catalog_marks_it_optional(db_session):
    client = api_client(db_session, OperatorRole.ANALYST)

    catalog = {entry["name"]: entry for entry in client.get("/api/v1/connectors").json()}
    oauth = next(m for m in catalog["slack"]["auth_methods"] if m["id"] == "oauth")
    assert oauth["optional_config_fields"] == ["enterprise_id"]

    team_id = f"T{client.kestrel_org.id.hex[:8].upper()}"
    response = client.post(
        "/api/v1/connector-instances",
        json={
            "connector_name": "slack",
            "display_name": "Workspace bot",
            "external_tenant_ref": team_id,
            "auth_method": "oauth",
            "sync_mode": "fixtures",
            "config": {"team_id": team_id},
        },
    )
    assert response.status_code == 201, response.text


def test_create_connector_instance_requires_an_identity_shape(db_session):
    client = api_client(db_session, OperatorRole.ANALYST)

    response = client.post(
        "/api/v1/connector-instances",
        json={"auth_method": "pat", "config": {}},
    )

    assert response.status_code == 422


def test_test_connection_against_fixture_transport_never_5xxs(db_session):
    """The GitHub connector's shipped fixture set is keyed to its demo
    org_login (a shipped-fixture detail this suite must not name outside
    that connector's own fixture-contract test -- see rule 2 in
    docs/testing.md), so a factory-built instance with a
    synthetic org_login gets an unmatched-fixture probe failure. The
    contract worth asserting here is that probe_connector_instance
    (kestrel/connectors/probe.py) turns that into a structured
    `ok: False` response, never an unhandled 500."""
    client = api_client(db_session, OperatorRole.ANALYST)
    created = _create_github_instance(client)
    assert created.status_code == 201
    instance_id = created.json()["id"]

    response = client.post(f"/api/v1/connector-instances/{instance_id}/test-connection")

    assert response.status_code == 200
    body = response.json()
    assert body["sync_mode"] == "fixtures"
    assert body["ok"] is False
    assert body["healthy"] is False
    assert "message" in body


def test_sync_enqueues_through_the_task_queue_not_a_broker(db_session):
    tasks = FakeTaskQueue()
    client = api_client(db_session, OperatorRole.ANALYST, task_queue=tasks)
    created = _create_github_instance(client)
    assert created.status_code == 201
    instance_id = created.json()["id"]

    response = client.post(f"/api/v1/connector-instances/{instance_id}/sync")

    assert response.status_code == 202
    body = response.json()
    assert body["enqueued"] is True
    assert len(tasks.connector_syncs) == 1
    assert tasks.connector_syncs[0]["connector_instance_id"] == instance_id
    assert tasks.connector_syncs[0]["connector_name"] == "github"
    assert tasks.connector_syncs[0]["task_id"] == body["task_id"]


def test_delete_connector_instance_removes_it(db_session):
    client = api_client(db_session, OperatorRole.ANALYST)
    created = _create_github_instance(client)
    instance_id = created.json()["id"]

    response = client.delete(f"/api/v1/connector-instances/{instance_id}")
    assert response.status_code == 200
    assert response.json()["ok"] is True

    follow_up = client.get(f"/api/v1/connector-instances/{instance_id}")
    assert follow_up.status_code == 404


def test_live_mode_requires_secrets_up_front(db_session):
    client = api_client(db_session, OperatorRole.ANALYST)

    response = _create_github_instance(client, sync_mode="live")

    assert response.status_code == 400
    assert "secret" in response.json()["detail"].lower()


def test_ssrf_unsafe_config_url_is_rejected(db_session):
    """The legacy connector_id + application_instance_id creation path
    validates config URLs against the SSRF allowlist
    (kestrel.security.ssrf). An IP literal, not a hostname, so this never
    touches DNS."""
    from kestrel.testing import make_application_instance, make_connector, make_organization

    org = make_organization(db_session)
    connector = make_connector(db_session)
    app_instance = make_application_instance(db_session, org)
    db_session.commit()
    client = api_client(db_session, OperatorRole.ANALYST, org=org)

    response = client.post(
        "/api/v1/connector-instances",
        json={
            "connector_id": str(connector.id),
            "application_instance_id": str(app_instance.id),
            "auth_method": "pat",
            "sync_mode": "fixtures",
            "config": {"base_url": "http://169.254.169.254/latest/meta-data/"},
        },
    )

    assert response.status_code == 400
    assert "base_url" in response.json()["detail"]


def _running_run(db_session, instance_id: str, *, age_seconds: int):
    import uuid
    from datetime import UTC, datetime, timedelta

    from kestrel.db.models.connector import ConnectorInstance, ConnectorRun, ConnectorRunStatus, ConnectorRunTrigger

    instance = db_session.get(ConnectorInstance, uuid.UUID(instance_id))
    run = ConnectorRun(
        id=uuid.uuid4(),
        org_id=instance.org_id,
        connector_instance_id=instance.id,
        status=ConnectorRunStatus.RUNNING,
        started_at=datetime.now(UTC) - timedelta(seconds=age_seconds),
        triggered_by=ConnectorRunTrigger.MANUAL,
    )
    db_session.add(run)
    db_session.commit()
    return run


def test_sync_is_refused_while_a_run_is_in_progress(db_session):
    tasks = FakeTaskQueue()
    client = api_client(db_session, OperatorRole.ANALYST, task_queue=tasks)
    instance_id = _create_github_instance(client).json()["id"]
    running = _running_run(db_session, instance_id, age_seconds=30)

    response = client.post(f"/api/v1/connector-instances/{instance_id}/sync")

    assert response.status_code == 409
    assert response.json()["detail"]["run_id"] == str(running.id)
    assert tasks.connector_syncs == []


def test_a_run_stuck_on_running_past_the_lock_ttl_is_failed_and_the_sync_proceeds(db_session):
    from kestrel.db.models.connector import ConnectorRun, ConnectorRunStatus

    tasks = FakeTaskQueue()
    client = api_client(db_session, OperatorRole.ANALYST, task_queue=tasks)
    instance_id = _create_github_instance(client).json()["id"]
    stale = _running_run(db_session, instance_id, age_seconds=4 * 3600)

    response = client.post(f"/api/v1/connector-instances/{instance_id}/sync")

    assert response.status_code == 202
    assert len(tasks.connector_syncs) == 1
    db_session.expire_all()
    expired = db_session.get(ConnectorRun, stale.id)
    assert expired.status is ConnectorRunStatus.FAILED
    assert "did not finish" in (expired.error_summary or "")
    assert expired.finished_at is not None


def test_listing_instances_also_expires_stuck_runs(db_session):
    from kestrel.db.models.connector import ConnectorRun, ConnectorRunStatus

    client = api_client(db_session, OperatorRole.READ_ONLY, task_queue=FakeTaskQueue())
    admin = api_client(db_session, OperatorRole.ADMIN, task_queue=FakeTaskQueue())
    instance_id = _create_github_instance(admin).json()["id"]
    stale = _running_run(db_session, instance_id, age_seconds=4 * 3600)

    # Same org: read-only viewer sees the corrected status.
    client.kestrel_org = admin.kestrel_org
    response = admin.get("/api/v1/connector-instances")

    assert response.status_code == 200
    db_session.expire_all()
    assert db_session.get(ConnectorRun, stale.id).status is ConnectorRunStatus.FAILED


def test_probe_before_save_returns_a_classified_result_and_persists_nothing(db_session):
    from kestrel.db.models.connector import ConnectorInstance, ConnectorSecret

    client = api_client(db_session, OperatorRole.ANALYST, task_queue=FakeTaskQueue())
    before_instances = db_session.query(ConnectorInstance).count()
    before_secrets = db_session.query(ConnectorSecret).count()

    response = client.post(
        "/api/v1/connectors/probe",
        json={
            "connector_name": "github",
            "auth_method": "pat",
            "sync_mode": "fixtures",
            "config": {"org_login": "not-the-fixture-org"},
            "secrets": {"token": "ghp_notarealtokenvaluexxxxxxxxxxxxxxxx"},
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is False
    assert "checked_permissions" in body
    assert "ghp_notarealtoken" not in body["message"]
    assert db_session.query(ConnectorInstance).count() == before_instances
    assert db_session.query(ConnectorSecret).count() == before_secrets


def test_probe_before_save_requires_secrets_in_live_mode(db_session):
    client = api_client(db_session, OperatorRole.ANALYST, task_queue=FakeTaskQueue())
    response = client.post(
        "/api/v1/connectors/probe",
        json={
            "connector_name": "github",
            "auth_method": "pat",
            "sync_mode": "live",
            "config": {"org_login": "x"},
            "secrets": {},
        },
    )
    assert response.status_code == 400
    assert "secret" in response.json()["detail"].lower()


def test_probe_before_save_is_refused_for_read_only_operators(db_session):
    client = api_client(db_session, OperatorRole.READ_ONLY, task_queue=FakeTaskQueue())
    response = client.post(
        "/api/v1/connectors/probe",
        json={"connector_name": "github", "auth_method": "pat", "sync_mode": "fixtures", "config": {}, "secrets": {}},
    )
    assert response.status_code == 403


def test_run_detail_reports_reduced_coverage_structurally(db_session):
    """A family the credential could not read belongs in its own field, not
    buried in the same string as a stack trace."""
    import uuid
    from datetime import UTC, datetime

    from kestrel.db.models.connector import ConnectorInstance, ConnectorRun, ConnectorRunStatus, ConnectorRunTrigger

    client = api_client(db_session, OperatorRole.READ_ONLY, task_queue=FakeTaskQueue())
    admin = api_client(db_session, OperatorRole.ADMIN, task_queue=FakeTaskQueue())
    instance_id = _create_github_instance(admin).json()["id"]
    instance = db_session.get(ConnectorInstance, uuid.UUID(instance_id))
    run = ConnectorRun(
        id=uuid.uuid4(),
        org_id=instance.org_id,
        connector_instance_id=instance.id,
        status=ConnectorRunStatus.PARTIAL_FAILURE,
        started_at=datetime.now(UTC),
        finished_at=datetime.now(UTC),
        triggered_by=ConnectorRunTrigger.MANUAL,
        object_counts={"member": 12, "team": 3},
        skipped_object_types={"audit_log": "permission"},
        error_summary="Collected with reduced coverage; could not read: audit_log (permission).",
    )
    db_session.add(run)
    db_session.commit()

    response = admin.get(f"/api/v1/connector-runs/{run.id}")

    assert response.status_code == 200
    coverage = response.json()["coverage"]
    assert coverage["is_complete"] is False
    assert [item["object_type"] for item in coverage["skipped"]] == ["audit_log"]
    assert coverage["skipped"][0]["reason"] == "permission"
    assert "scope or permission" in coverage["skipped"][0]["detail"]
    assert {item["object_type"] for item in coverage["collected"]} == {"member", "team"}
    assert client is not None


def test_a_complete_run_reports_complete_coverage(db_session):
    import uuid
    from datetime import UTC, datetime

    from kestrel.db.models.connector import ConnectorInstance, ConnectorRun, ConnectorRunStatus, ConnectorRunTrigger

    admin = api_client(db_session, OperatorRole.ADMIN, task_queue=FakeTaskQueue())
    instance_id = _create_github_instance(admin).json()["id"]
    instance = db_session.get(ConnectorInstance, uuid.UUID(instance_id))
    run = ConnectorRun(
        id=uuid.uuid4(),
        org_id=instance.org_id,
        connector_instance_id=instance.id,
        status=ConnectorRunStatus.SUCCESS,
        started_at=datetime.now(UTC),
        finished_at=datetime.now(UTC),
        triggered_by=ConnectorRunTrigger.MANUAL,
        object_counts={"member": 12},
    )
    db_session.add(run)
    db_session.commit()

    coverage = admin.get(f"/api/v1/connector-runs/{run.id}").json()["coverage"]

    assert coverage["is_complete"] is True
    assert coverage["skipped"] == []
    assert coverage["notice"] is None
