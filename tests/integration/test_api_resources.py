# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Resources API: listing, detail, and the operator sensitivity override.

Sensitivity decides whether "an external collaborator can reach this" is a
finding, so the override is a real write with an audit trail, and it has to
survive the next sync rather than being overwritten by the connector's guess.
"""

from __future__ import annotations

import uuid

from kestrel.db.models.operator import OperatorRole
from kestrel.db.models.resource import Resource, ResourceType, ResourceVisibility
from kestrel.testing import api_client, make_application_instance, make_connector_instance
from sqlalchemy import select


def _make_resource(db_session, org, *, name="secrets-vault", sensitive=None, config=None) -> Resource:
    from datetime import UTC, datetime

    from kestrel.db.models.connector import ConnectorRun, ConnectorRunStatus, ConnectorRunTrigger

    app_instance = make_application_instance(db_session, org)
    connector_instance = make_connector_instance(db_session, org, application_instance=app_instance)
    db_session.flush()
    run = ConnectorRun(
        id=uuid.uuid4(),
        org_id=org.id,
        connector_instance_id=connector_instance.id,
        status=ConnectorRunStatus.SUCCESS,
        started_at=datetime.now(UTC),
        triggered_by=ConnectorRunTrigger.MANUAL,
    )
    db_session.add(run)
    db_session.flush()
    resource = Resource(
        id=uuid.uuid4(),
        org_id=org.id,
        application_instance_id=app_instance.id,
        provider_object_id=f"repo-{uuid.uuid4().hex[:8]}",
        resource_type=ResourceType.REPOSITORY,
        name=name,
        visibility=ResourceVisibility.PRIVATE,
        is_sensitive=sensitive,
        config=config or {},
        source_connector_run_id=run.id,
        raw_source={},
    )
    db_session.add(resource)
    db_session.flush()
    return resource


def test_list_and_filter_resources_by_sensitivity(db_session):
    client = api_client(db_session, OperatorRole.READ_ONLY)
    org = client.kestrel_org
    sensitive = _make_resource(db_session, org, name="prod-secrets", sensitive=True)
    ordinary = _make_resource(db_session, org, name="docs-site", sensitive=False)
    db_session.commit()

    response = client.get("/api/v1/resources", params={"is_sensitive": "true"})

    assert response.status_code == 200
    ids = {row["id"] for row in response.json()["items"]}
    assert str(sensitive.id) in ids
    assert str(ordinary.id) not in ids


def test_an_operator_can_mark_a_resource_sensitive(db_session):
    client = api_client(db_session, OperatorRole.ANALYST)
    org = client.kestrel_org
    resource = _make_resource(db_session, org, sensitive=None)
    db_session.commit()

    response = client.patch(f"/api/v1/resources/{resource.id}/sensitivity", json={"is_sensitive": True})

    assert response.status_code == 200
    body = response.json()
    assert body["is_sensitive"] is True
    assert body["sensitivity_source"] == "operator"
    db_session.expire_all()
    stored = db_session.get(Resource, resource.id)
    assert stored.is_sensitive is True
    assert stored.config["sensitivity_override"] is True


def test_clearing_the_override_returns_the_resource_to_the_connector_assessment(db_session):
    client = api_client(db_session, OperatorRole.ANALYST)
    org = client.kestrel_org
    resource = _make_resource(db_session, org, sensitive=None)
    db_session.commit()
    client.patch(f"/api/v1/resources/{resource.id}/sensitivity", json={"is_sensitive": True})

    response = client.patch(f"/api/v1/resources/{resource.id}/sensitivity", json={"is_sensitive": None})

    assert response.status_code == 200
    db_session.expire_all()
    stored = db_session.get(Resource, resource.id)
    assert "sensitivity_override" not in (stored.config or {})
    assert stored.config["sensitivity_source"] == "heuristic"


def test_the_override_survives_the_next_sync(db_session):
    """A later sync recomputes the heuristic; the operator's decision wins."""
    from kestrel.sync.upsert import _preserve_sensitivity_override

    client = api_client(db_session, OperatorRole.ANALYST)
    org = client.kestrel_org
    resource = _make_resource(db_session, org, sensitive=None)
    db_session.commit()
    client.patch(f"/api/v1/resources/{resource.id}/sensitivity", json={"is_sensitive": True})
    db_session.expire_all()
    stored = db_session.get(Resource, resource.id)

    # What the connector would write on the next run.
    incoming = {"is_sensitive": None, "config": {"sensitivity_source": "heuristic", "sensitivity_reasons": []}}
    _preserve_sensitivity_override(stored, incoming)

    assert incoming["is_sensitive"] is True
    assert incoming["config"]["sensitivity_override"] is True
    assert incoming["config"]["sensitivity_source"] == "operator"


def test_a_tombstoned_resource_is_hidden(db_session):
    from datetime import UTC, datetime

    client = api_client(db_session, OperatorRole.READ_ONLY)
    org = client.kestrel_org
    resource = _make_resource(db_session, org)
    resource.deleted_at = datetime.now(UTC)
    db_session.commit()

    assert client.get(f"/api/v1/resources/{resource.id}").status_code == 404
    listed = client.get("/api/v1/resources").json()["items"]
    assert str(resource.id) not in {row["id"] for row in listed}


def test_setting_sensitivity_writes_an_audit_event(db_session):
    from kestrel.db.models.audit import AuditLog

    client = api_client(db_session, OperatorRole.ANALYST)
    org = client.kestrel_org
    resource = _make_resource(db_session, org)
    db_session.commit()

    client.patch(f"/api/v1/resources/{resource.id}/sensitivity", json={"is_sensitive": True})

    actions = set(db_session.scalars(select(AuditLog.action).where(AuditLog.org_id == org.id)).all())
    assert "resource.sensitivity_set" in actions
