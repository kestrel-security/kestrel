# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Tier 2 -- demo teardown removes a tenant and everything derived from it.

The bug this guards: teardown used to delete `connector_runs` and then
the `ConnectorInstance` while leaving inventory in place, which cannot work --
fifteen tables carry a NOT NULL reference back to those runs, so the delete died
on a foreign key the moment a tenant had ever been synced.

Data here is test-owned (a scripted connector, not a shipped fixture set), so
these assertions do not depend on any connector's cast of characters.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any

import pytest
from kestrel.connectors.sdk.base import (
    HealthCheckResult,
    NormalizedObject,
    NormalizedRelationship,
    RawObject,
)
from kestrel.db.models.access import Grant, Group, GroupMembership, Role
from kestrel.db.models.application import ApplicationInstance
from kestrel.db.models.connector import ConnectorInstance, ConnectorRun, ConnectorRunTrigger
from kestrel.db.models.event import Event
from kestrel.db.models.finding import Finding, FindingStatus, FindingSubjectType
from kestrel.db.models.graph_edge import GraphEdge, GraphNode
from kestrel.db.models.identity import Identity
from kestrel.db.models.operator import Operator
from kestrel.db.models.org import Organization
from kestrel.db.models.policy import (
    Policy,
    PolicyEvaluation,
    PolicyEvaluationStatus,
    PolicySource,
    PolicyVersion,
    Severity,
)
from kestrel.db.models.webhook import WebhookDelivery, WebhookDeliveryStatus, WebhookEndpoint
from kestrel.demo.teardown import teardown_application_instances
from kestrel.sync.pipeline import run_sync
from kestrel.testing import (
    make_application_instance,
    make_connector_instance,
    make_operator,
    make_organization,
)
from sqlalchemy import func, select
from sqlalchemy.orm import Session


class _Collector:
    def __init__(self, objects: dict[str, list[NormalizedObject]]) -> None:
        self._objects = objects

    def discover(self) -> list[str]:
        return list(self._objects)

    def collect(self, object_type: str, *, since: datetime | None = None) -> Iterator[RawObject]:
        for index in range(len(self._objects[object_type])):
            yield RawObject(
                object_type=object_type,
                provider_id=f"{object_type}:{index}",
                payload={"index": index},
                collected_at=datetime.now(UTC),
            )

    def health_check(self) -> HealthCheckResult:
        return HealthCheckResult(healthy=True, message="ok")


class _Normalizer:
    def __init__(self, objects: dict[str, list[NormalizedObject]]) -> None:
        self._objects = objects

    def normalize(self, object_type: str, raw: RawObject) -> list[NormalizedObject]:
        return [self._objects[object_type][int(raw.provider_id.rsplit(":", 1)[1])]]


class _Connector:
    manifest = None

    def __init__(self, objects: dict[str, list[NormalizedObject]]) -> None:
        self.objects = objects

    def configure(self, config: dict[str, Any]) -> None:
        pass

    def authenticate(self, config: dict[str, Any], secrets: dict[str, str]) -> Any:
        raise NotImplementedError

    def build_collector(self, transport: Any) -> _Collector:
        return _Collector(self.objects)

    def build_normalizer(self, *_: Any) -> _Normalizer:
        return _Normalizer(self.objects)


def _tenant_objects() -> dict[str, list[NormalizedObject]]:
    """An identity that is an admin and a group member, so the run writes
    entities, relationship rows, and graph edges in one pass."""
    return {
        "role": [
            NormalizedObject(
                kind="role",
                provider_id="admin-role",
                attributes={"name": "Admin", "is_privileged": True},
                raw_source={"k": "role"},
            )
        ],
        "group": [
            NormalizedObject(
                kind="group",
                provider_id="team-1",
                attributes={"name": "Team One"},
                raw_source={"k": "group"},
            )
        ],
        "identity": [
            NormalizedObject(
                kind="identity",
                provider_id="user-1",
                attributes={
                    "identity_type": "user",
                    "email": "user-1@example.test",
                    "display_name": "User One",
                    "mfa_enabled": False,
                },
                raw_source={"k": "identity"},
                relationships=[
                    NormalizedRelationship(
                        edge_type="assigned_role",
                        source_ref="user-1",
                        target_ref="admin-role",
                        access_path="direct",
                    )
                ],
            )
        ],
        "group_membership": [
            NormalizedObject(
                kind="group_membership",
                provider_id="gm-1",
                attributes={"group_ref": "team-1", "identity_ref": "user-1"},
                raw_source={"k": "gm"},
                relationships=[
                    NormalizedRelationship(
                        edge_type="member_of",
                        source_ref="user-1",
                        target_ref="team-1",
                        access_path="direct",
                    )
                ],
            )
        ],
        "grant": [
            NormalizedObject(
                kind="grant",
                provider_id="grant-1",
                attributes={
                    "identity_ref": "user-1",
                    "role_ref": "admin-role",
                    "granted_via": "role_assignment",
                },
                raw_source={"k": "grant"},
            )
        ],
    }


@pytest.fixture
def synced_tenant(db_session: Session):
    """(session, org_id, application_instance_id) with one synced tenant."""
    org = make_organization(db_session)
    app_instance = make_application_instance(db_session, org, display_name="Acme (demo)")
    instance = make_connector_instance(db_session, org, application_instance=app_instance)
    db_session.flush()

    run_sync(
        db_session,
        connector_instance_id=instance.id,
        connector=_Connector(_tenant_objects()),
        config={},
        transport_override=object(),
        triggered_by=ConnectorRunTrigger.MANUAL,
    )
    db_session.flush()
    return db_session, org.id, app_instance.id


def _count(session: Session, model, *criteria) -> int:
    return session.scalar(select(func.count()).select_from(model).where(*criteria)) or 0


def test_teardown_removes_a_synced_tenant_without_a_foreign_key_violation(synced_tenant):
    # The whole point: a tenant that has been synced used to be undeletable.
    session, org_id, app_id = synced_tenant
    assert _count(session, Identity, Identity.application_instance_id == app_id) == 1

    result = teardown_application_instances(session, org_id=org_id, application_instance_ids=[app_id])

    assert result.application_instances == 1
    assert result.connector_instances == 1
    assert result.total_rows > 0
    assert _count(session, ApplicationInstance, ApplicationInstance.id == app_id) == 0
    assert _count(session, ConnectorInstance, ConnectorInstance.org_id == org_id) == 0
    assert _count(session, ConnectorRun, ConnectorRun.org_id == org_id) == 0


def test_teardown_leaves_no_orphaned_inventory_graph_or_change_rows(synced_tenant):
    session, org_id, app_id = synced_tenant
    teardown_application_instances(session, org_id=org_id, application_instance_ids=[app_id])

    for model in (Identity, Group, Role):
        assert _count(session, model, model.application_instance_id == app_id) == 0
    assert _count(session, Grant, Grant.org_id == org_id) == 0
    assert _count(session, GroupMembership, GroupMembership.org_id == org_id) == 0
    assert _count(session, Event, Event.org_id == org_id) == 0
    assert _count(session, GraphNode, GraphNode.org_id == org_id) == 0
    assert _count(session, GraphEdge, GraphEdge.org_id == org_id) == 0


def test_teardown_keeps_the_org_operators_and_policies(synced_tenant):
    # `demo up` after `demo down` must not have to re-bootstrap the install.
    session, org_id, app_id = synced_tenant
    org = session.get(Organization, org_id)
    assert org is not None
    operator = make_operator(session, org)
    session.flush()
    policy_count_before = _count(session, Policy, Policy.org_id == org_id)

    teardown_application_instances(session, org_id=org_id, application_instance_ids=[app_id])

    assert session.get(Organization, org_id) is not None
    assert session.get(Operator, operator.id) is not None
    assert _count(session, Policy, Policy.org_id == org_id) == policy_count_before


def test_teardown_does_not_touch_another_tenant_in_the_same_org(db_session: Session):
    org = make_organization(db_session)
    keep_app = make_application_instance(db_session, org, display_name="Real Tenant")
    keep_instance = make_connector_instance(db_session, org, application_instance=keep_app)
    drop_app = make_application_instance(db_session, org, display_name="Acme (demo)")
    drop_instance = make_connector_instance(db_session, org, application_instance=drop_app)
    db_session.flush()

    for instance in (keep_instance, drop_instance):
        run_sync(
            db_session,
            connector_instance_id=instance.id,
            connector=_Connector(_tenant_objects()),
            config={},
            transport_override=object(),
            triggered_by=ConnectorRunTrigger.MANUAL,
        )
    db_session.flush()

    teardown_application_instances(db_session, org_id=org.id, application_instance_ids=[drop_app.id])

    assert _count(db_session, Identity, Identity.application_instance_id == keep_app.id) == 1
    assert _count(db_session, Identity, Identity.application_instance_id == drop_app.id) == 0
    assert _count(db_session, ConnectorInstance, ConnectorInstance.id == keep_instance.id) == 1
    assert _count(db_session, ConnectorRun, ConnectorRun.connector_instance_id == keep_instance.id) >= 1


def test_teardown_of_nothing_is_a_no_op(db_session: Session):
    org = make_organization(db_session)
    db_session.flush()
    result = teardown_application_instances(db_session, org_id=org.id, application_instance_ids=[])
    assert result.application_instances == 0
    assert result.total_rows == 0


def test_teardown_is_repeatable(synced_tenant):
    session, org_id, app_id = synced_tenant
    teardown_application_instances(session, org_id=org_id, application_instance_ids=[app_id])
    again = teardown_application_instances(session, org_id=org_id, application_instance_ids=[app_id])
    assert again.total_rows == 0


def test_teardown_drops_pending_deliveries_but_keeps_delivery_history(synced_tenant):
    # A pending delivery for a finding that is going away would sit in the
    # dashboard's webhook backlog forever; sent ones are history and stay.
    session, org_id, app_id = synced_tenant
    identity = session.scalars(select(Identity).where(Identity.application_instance_id == app_id)).first()
    assert identity is not None
    policy = Policy(id=uuid.uuid4(), org_id=org_id, slug="teardown-webhooks", title="t", source=PolicySource.CUSTOM)
    session.add(policy)
    session.flush()
    version = PolicyVersion(
        id=uuid.uuid4(),
        policy_id=policy.id,
        version=1,
        source_text="def policy(resource):\n    return False\n",
        severity=Severity.HIGH,
    )
    session.add(version)
    session.flush()
    evaluation = PolicyEvaluation(
        id=uuid.uuid4(), org_id=org_id, policy_version_id=version.id, status=PolicyEvaluationStatus.SUCCESS
    )
    session.add(evaluation)
    session.flush()
    now = datetime.now(UTC)
    finding = Finding(
        id=uuid.uuid4(),
        org_id=org_id,
        policy_version_id=version.id,
        policy_evaluation_id=evaluation.id,
        title="t",
        severity=Severity.HIGH,
        status=FindingStatus.OPEN,
        subject_type=FindingSubjectType.IDENTITY,
        subject_id=identity.id,
        first_seen_at=now,
        last_seen_at=now,
    )
    endpoint = WebhookEndpoint(
        id=uuid.uuid4(),
        org_id=org_id,
        name="hook",
        url="https://example.com/hook",
        events=["finding.opened"],
        secret_ciphertext=b"x",
        secret_nonce=b"x",
        secret_key_version=1,
    )
    session.add_all([finding, endpoint])
    session.flush()
    for status in (WebhookDeliveryStatus.PENDING, WebhookDeliveryStatus.SUCCESS):
        session.add(
            WebhookDelivery(
                id=uuid.uuid4(),
                org_id=org_id,
                webhook_endpoint_id=endpoint.id,
                finding_id=finding.id,
                event_type="finding.opened",
                payload={},
                status=status,
                attempt_count=0,
            )
        )
    session.flush()

    teardown_application_instances(session, org_id=org_id, application_instance_ids=[app_id])

    remaining = list(session.scalars(select(WebhookDelivery).where(WebhookDelivery.org_id == org_id)).all())
    assert [d.status for d in remaining] == [WebhookDeliveryStatus.SUCCESS]
    assert remaining[0].finding_id is None
