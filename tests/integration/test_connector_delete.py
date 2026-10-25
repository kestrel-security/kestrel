# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Tier 2 -- deleting a connector instance that has actually synced.

The bug this guards: ``delete_connector_instance`` removed runs and the
instance but left ``connector_cursors`` (written on every successful run) and
``graph_snapshots`` (written on every full run) pointing at them, so deleting
any connector that had ever synced died on a foreign key and returned 500.
The only previous API test deleted an instance that had never synced.

The sync is fixture-mode in the sense that matters -- no network, no
credentials -- but driven by a test-owned connector double rather than a
shipped fixture set (rule 2 of ``docs/testing.md``).

The orphan check is generic: it walks ``Base.metadata`` for every foreign key
into the tables a connector delete removes rows from, so a table added later
that references them fails here instead of in production.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any

import pytest
from kestrel.connectors.sdk.base import HealthCheckResult, NormalizedObject, NormalizedRelationship, RawObject
from kestrel.db.base import Base
from kestrel.db.models.application import ApplicationInstance
from kestrel.db.models.connector import (
    ConnectorCursor,
    ConnectorInstance,
    ConnectorRun,
    ConnectorRunStatus,
    ConnectorRunTrigger,
)
from kestrel.db.models.operator import OperatorRole
from kestrel.graph.snapshots import GraphSnapshot
from kestrel.sync.pipeline import run_sync
from kestrel.testing import api_client, make_application_instance, make_connector_instance, make_organization
from sqlalchemy import func, select
from sqlalchemy.orm import Session

# Tables whose rows a connector delete removes. Any FK into them must be
# cleared (deleted or nulled) by the delete, or the delete fails.
_DELETED_TABLES = ("connector_instances", "connector_runs", "application_instances")


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


def _obj(kind: str, provider_id: str, attributes: dict[str, Any], **kwargs: Any) -> NormalizedObject:
    return NormalizedObject(kind=kind, provider_id=provider_id, attributes=attributes, raw_source={}, **kwargs)


def _tenant_objects() -> dict[str, list[NormalizedObject]]:
    """One of nearly every kind, so the run writes provenance rows,
    relationship rows, graph rows, a snapshot, cursors, and change events."""
    return {
        "role": [_obj("role", "admin-role", {"name": "Admin", "is_privileged": True})],
        "group": [_obj("group", "team-1", {"name": "Team One"})],
        "permission": [_obj("permission", "perm-1", {"name": "Push", "action": "push"})],
        "resource": [_obj("resource", "repo-1", {"resource_type": "repository", "name": "repo-1", "visibility": "private"})],
        "identity": [
            _obj(
                "identity",
                "user-1",
                {"identity_type": "user", "email": "user-1@example.test", "display_name": "User One"},
                relationships=[
                    NormalizedRelationship(
                        edge_type="assigned_role", source_ref="user-1", target_ref="admin-role", access_path="direct"
                    )
                ],
            )
        ],
        "oauth_application": [_obj("oauth_application", "app-1", {"name": "Some App", "owner_identity_ref": "user-1"})],
        "oauth_scope": [_obj("oauth_scope", "scope-1", {"oauth_application_ref": "app-1", "scope_name": "repo"})],
        "oauth_grant": [_obj("oauth_grant", "og-1", {"oauth_application_ref": "app-1", "identity_ref": "user-1"})],
        "setting": [
            _obj(
                "setting",
                "setting-1",
                {
                    "key": "two_factor_required",
                    "category": "security",
                    "label": "2FA required",
                    "value": True,
                    "value_type": "boolean",
                },
            )
        ],
        "event": [
            _obj(
                "event",
                "log-1",
                {
                    "action": "org.update",
                    "action_category": "config",
                    "occurred_at": datetime.now(UTC).isoformat(),
                    "summary": "org updated",
                },
            )
        ],
        "group_membership": [
            _obj(
                "group_membership",
                "gm-1",
                {"group_ref": "team-1", "identity_ref": "user-1"},
                relationships=[
                    NormalizedRelationship(
                        edge_type="member_of", source_ref="user-1", target_ref="team-1", access_path="direct"
                    )
                ],
            )
        ],
        "grant": [
            _obj(
                "grant",
                "grant-1",
                {"identity_ref": "user-1", "role_ref": "admin-role", "granted_via": "role_assignment"},
            )
        ],
    }


def _sync(session: Session, instance: ConnectorInstance) -> ConnectorRun:
    run = run_sync(
        session,
        connector_instance_id=instance.id,
        connector=_Connector(_tenant_objects()),
        config={},
        transport_override=object(),
        triggered_by=ConnectorRunTrigger.MANUAL,
    )
    session.flush()
    return run


def _count(session: Session, model, *criteria) -> int:
    return session.scalar(select(func.count()).select_from(model).where(*criteria)) or 0


def _referencing_columns() -> list[tuple[str, str, str]]:
    """(table, column, referenced table) for every FK into the deleted tables."""
    found = []
    for table in Base.metadata.tables.values():
        for fk in table.foreign_keys:
            if fk.column.table.name in _DELETED_TABLES:
                found.append((table.name, fk.parent.name, fk.column.table.name))
    return sorted(found)


def _orphans(session: Session, ids_by_table: dict[str, set[uuid.UUID]]) -> dict[str, int]:
    """Rows anywhere in the schema still pointing at a deleted id."""
    leftovers: dict[str, int] = {}
    for table_name, column_name, referenced in _referencing_columns():
        ids = ids_by_table[referenced]
        if not ids:
            continue
        table = Base.metadata.tables[table_name]
        column = table.c[column_name]
        count = session.scalar(select(func.count()).select_from(table).where(column.in_(ids))) or 0
        if count:
            leftovers[f"{table_name}.{column_name}"] = count
    return leftovers


@pytest.fixture
def synced(db_session: Session):
    org = make_organization(db_session)
    app_instance = make_application_instance(db_session, org)
    instance = make_connector_instance(db_session, org, application_instance=app_instance)
    db_session.flush()
    first = _sync(db_session, instance)
    second = _sync(db_session, instance)
    assert first.status == ConnectorRunStatus.SUCCESS
    assert second.status == ConnectorRunStatus.SUCCESS
    return org, app_instance, instance


def test_the_sync_wrote_the_rows_that_used_to_block_delete(db_session: Session, synced):
    # Guards the test itself: if the sync stops writing cursors or snapshots,
    # the delete tests below stop proving anything.
    _org, app_instance, instance = synced
    assert _count(db_session, ConnectorCursor, ConnectorCursor.connector_instance_id == instance.id) > 0
    assert _count(db_session, GraphSnapshot, GraphSnapshot.application_instance_id == app_instance.id) > 0


def test_deleting_a_synced_connector_succeeds_and_leaves_no_orphans(db_session: Session, synced):
    org, app_instance, instance = synced
    run_ids = set(db_session.scalars(select(ConnectorRun.id).where(ConnectorRun.connector_instance_id == instance.id)))
    assert run_ids
    client = api_client(db_session, OperatorRole.ANALYST, org=org)

    response = client.delete(f"/api/v1/connector-instances/{instance.id}")

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["ok"] is True
    assert body["runs_deleted"] == len(run_ids)
    assert body["application_instance_deleted"] is True
    db_session.expire_all()
    assert db_session.get(ConnectorInstance, instance.id) is None
    assert db_session.get(ApplicationInstance, app_instance.id) is None
    assert (
        _orphans(
            db_session,
            {
                "connector_instances": {instance.id},
                "connector_runs": run_ids,
                "application_instances": {app_instance.id},
            },
        )
        == {}
    )


def test_deleting_one_of_two_instances_on_a_shared_app_instance_keeps_the_other(db_session: Session):
    org = make_organization(db_session)
    app_instance = make_application_instance(db_session, org)
    doomed = make_connector_instance(db_session, org, application_instance=app_instance)
    survivor = make_connector_instance(db_session, org, application_instance=app_instance)
    db_session.flush()
    _sync(db_session, doomed)
    _sync(db_session, survivor)
    client = api_client(db_session, OperatorRole.ANALYST, org=org)

    response = client.delete(f"/api/v1/connector-instances/{doomed.id}")

    assert response.status_code == 200, response.text
    assert response.json()["application_instance_deleted"] is False
    db_session.expire_all()
    assert db_session.get(ConnectorInstance, survivor.id) is not None
    assert db_session.get(ApplicationInstance, app_instance.id) is not None
    assert _count(db_session, ConnectorRun, ConnectorRun.connector_instance_id == survivor.id) >= 1
    assert _count(db_session, ConnectorCursor, ConnectorCursor.connector_instance_id == doomed.id) == 0
