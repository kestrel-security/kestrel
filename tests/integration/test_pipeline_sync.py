# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Tier 2 -- ``sync.pipeline.run_sync`` mechanics.

Drives ``run_sync`` with a test-owned ``Connector`` double (``ScriptedConnector``
below) rather than a real connector's shipped fixtures: rule 1 of
``docs/testing.md`` is "tests own their data", and the sync
pipeline's contract -- entities/edges land in the DB, a rerun is idempotent,
disappearance is detected, raw_source survives -- has nothing to do with any
one connector's shape. ``ScriptedConnector`` satisfies the
``connectors.sdk.base.Connector`` Protocol structurally and replays whatever
``NormalizedObject`` list the test hands it, so ``run_sync``'s
``transport_override=`` seam never has to touch a real Transport.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any

import pytest
from kestrel.connectors.sdk.base import HealthCheckResult, NormalizedObject, NormalizedRelationship, RawObject
from kestrel.db.models.access import Grant, GroupMembership
from kestrel.db.models.application import ApplicationInstance
from kestrel.db.models.connector import ConnectorInstance, ConnectorRunStatus, ConnectorRunTrigger
from kestrel.db.models.event import ChangeType, Event
from kestrel.db.models.graph_edge import GraphEdge, GraphEdgeType, GraphNode
from kestrel.db.models.identity import Identity
from kestrel.db.models.org import Organization
from kestrel.sync.pipeline import run_sync
from kestrel.testing import make_application_instance, make_connector_instance, make_organization
from sqlalchemy import select
from sqlalchemy.orm import Session


class _ScriptedCollector:
    def __init__(
        self,
        objects_by_type: dict[str, list[NormalizedObject]],
        skipped_object_types: dict[str, str] | None = None,
    ) -> None:
        self._objects_by_type = objects_by_type
        # Optional contract from sdk/base.Collector: object types this run
        # could not read. Present here so the partial-coverage path is
        # exercised without depending on any real connector's failure modes.
        self.skipped_object_types = dict(skipped_object_types or {})

    def discover(self) -> list[str]:
        return list(self._objects_by_type)

    def collect(self, object_type: str, *, since: datetime | None = None) -> Iterator[RawObject]:
        for index in range(len(self._objects_by_type[object_type])):
            yield RawObject(
                object_type=object_type,
                provider_id=f"{object_type}:{index}",
                payload={"index": index},
                collected_at=datetime.now(UTC),
            )

    def health_check(self) -> HealthCheckResult:
        return HealthCheckResult(healthy=True, message="ok")


class _ScriptedNormalizer:
    def __init__(self, objects_by_type: dict[str, list[NormalizedObject]]) -> None:
        self._objects_by_type = objects_by_type

    def normalize(self, object_type: str, raw: RawObject) -> list[NormalizedObject]:
        index = int(raw.provider_id.rsplit(":", 1)[1])
        return [self._objects_by_type[object_type][index]]


class ScriptedConnector:
    """Test-owned ``Connector`` double: yields exactly the NormalizedObjects
    the test supplies. ``manifest`` is never read by ``run_sync``/
    ``run_collection``, and ``authenticate`` is never called because every
    test here passes ``transport_override=``."""

    manifest = None

    def __init__(
        self,
        objects_by_type: dict[str, list[NormalizedObject]],
        skipped_object_types: dict[str, str] | None = None,
    ) -> None:
        self.objects_by_type = objects_by_type
        self.skipped_object_types = skipped_object_types

    def configure(self, config: dict[str, Any]) -> None:
        pass

    def authenticate(self, config: dict[str, Any], secrets: dict[str, str]) -> Any:
        raise NotImplementedError("fixture-mode only; authenticate should never be called")

    def build_collector(self, transport: Any) -> _ScriptedCollector:
        return _ScriptedCollector(self.objects_by_type, self.skipped_object_types)

    def build_normalizer(self) -> _ScriptedNormalizer:
        return _ScriptedNormalizer(self.objects_by_type)


def _identity_obj(
    provider_id: str,
    *,
    mfa_enabled: bool = True,
    is_disabled: bool = False,
    relationships: list[NormalizedRelationship] | None = None,
) -> NormalizedObject:
    return NormalizedObject(
        kind="identity",
        provider_id=provider_id,
        attributes={
            "identity_type": "user",
            "email": f"{provider_id}@example.test",
            "display_name": f"Identity {provider_id}",
            "mfa_enabled": mfa_enabled,
            "is_disabled": is_disabled,
        },
        raw_source={"source": "scripted", "provider_id": provider_id},
        relationships=relationships or [],
    )


def _role_obj(provider_id: str, *, is_privileged: bool = False) -> NormalizedObject:
    return NormalizedObject(
        kind="role",
        provider_id=provider_id,
        attributes={"name": f"Role {provider_id}", "is_privileged": is_privileged},
        raw_source={"source": "scripted", "provider_id": provider_id},
    )


def _grant_obj(
    provider_id: str, *, identity_ref: str, role_ref: str, granted_via: str = "direct", permission_level: str | None = None
) -> NormalizedObject:
    return NormalizedObject(
        kind="grant",
        provider_id=provider_id,
        attributes={
            "identity_ref": identity_ref,
            "role_ref": role_ref,
            "granted_via": granted_via,
            "permission_level": permission_level,
        },
        raw_source={"source": "scripted"},
    )


@pytest.fixture
def connector_context(db_session: Session) -> tuple[Session, uuid.UUID, uuid.UUID]:
    """(session, org_id, connector_instance_id) for a fresh org."""
    org = make_organization(db_session)
    app_instance = make_application_instance(db_session, org)
    instance = make_connector_instance(db_session, org, application_instance=app_instance)
    db_session.flush()
    return db_session, org.id, instance.id


def _run(
    session: Session,
    connector_instance_id: uuid.UUID,
    objects_by_type: dict[str, list[NormalizedObject]],
    *,
    skipped_object_types: dict[str, str] | None = None,
):
    return run_sync(
        session,
        connector_instance_id=connector_instance_id,
        connector=ScriptedConnector(objects_by_type, skipped_object_types),
        config={},
        transport_override=object(),  # never touched: build_collector() ignores it
        triggered_by=ConnectorRunTrigger.MANUAL,
    )


def test_run_sync_creates_entities_and_graph_edges(connector_context):
    session, org_id, instance_id = connector_context
    objects = {
        "identity": [
            _identity_obj(
                "user-1",
                relationships=[
                    NormalizedRelationship(
                        edge_type="assigned_role", source_ref="user-1", target_ref="role-1", access_path="direct"
                    ),
                ],
            )
        ],
        "role": [_role_obj("role-1", is_privileged=True)],
        "grant": [
            _grant_obj("grant-1", identity_ref="user-1", role_ref="role-1", granted_via="direct", permission_level="admin")
        ],
    }

    run = _run(session, instance_id, objects)
    session.flush()

    assert run.status is ConnectorRunStatus.SUCCESS
    assert run.object_counts == {"identity": 1, "role": 1, "grant": 1}

    identity = session.scalars(select(Identity).where(Identity.org_id == org_id)).one()
    assert identity.provider_object_id == "user-1"
    assert identity.mfa_enabled is True

    # A GraphNode exists for the identity and a GraphEdge for the role assignment.
    nodes = session.scalars(select(GraphNode).where(GraphNode.org_id == org_id)).all()
    node_types = {n.node_type.value for n in nodes}
    assert {"identity", "role"} <= node_types

    edges = session.scalars(select(GraphEdge).where(GraphEdge.org_id == org_id)).all()
    assert len(edges) == 1
    assert edges[0].edge_type.value == "assigned_role"
    assert edges[0].access_path is not None
    assert edges[0].access_path.value == "direct"

    # Creation is diffed: one CREATED event per provenance/relationship row.
    events = session.scalars(select(Event).where(Event.org_id == org_id)).all()
    created_entity_types = {e.entity_type for e in events if e.change_type is ChangeType.CREATED}
    assert {"identity", "role", "grant"} <= created_entity_types


def test_rerunning_sync_is_idempotent(connector_context):
    session, org_id, instance_id = connector_context
    objects = {
        "identity": [_identity_obj("user-1")],
        "role": [_role_obj("role-1")],
    }

    _run(session, instance_id, objects)
    session.flush()
    identity_count_after_first = session.scalar(select(Identity).where(Identity.org_id == org_id))
    first_run_row_count = len(session.scalars(select(Identity).where(Identity.org_id == org_id)).all())

    second_run = _run(session, instance_id, objects)
    session.flush()

    assert second_run.status is ConnectorRunStatus.SUCCESS
    second_run_row_count = len(session.scalars(select(Identity).where(Identity.org_id == org_id)).all())
    assert second_run_row_count == first_run_row_count == 1

    # Nothing changed between the two runs, so the second run emits no
    # CREATED/UPDATED/DELETED events for the identity.
    identity_events = session.scalars(
        select(Event).where(
            Event.org_id == org_id,
            Event.entity_type == "identity",
            Event.connector_run_id == second_run.id,
        )
    ).all()
    assert identity_events == []
    del identity_count_after_first  # only used to force the first select above


def test_run_sync_detects_deletions(connector_context):
    session, org_id, instance_id = connector_context
    t0 = {
        "identity": [_identity_obj("user-1"), _identity_obj("user-2")],
    }
    first_run = _run(session, instance_id, t0)
    session.flush()
    assert first_run.status is ConnectorRunStatus.SUCCESS

    # user-2 disappears from the provider's response in the next run.
    t1 = {"identity": [_identity_obj("user-1")]}
    second_run = _run(session, instance_id, t1)
    session.flush()
    assert second_run.status is ConnectorRunStatus.SUCCESS

    deleted_events = session.scalars(
        select(Event).where(
            Event.org_id == org_id,
            Event.entity_type == "identity",
            Event.change_type == ChangeType.DELETED,
            Event.connector_run_id == second_run.id,
        )
    ).all()
    assert len(deleted_events) == 1

    remaining_identities = {
        i.provider_object_id for i in session.scalars(select(Identity).where(Identity.org_id == org_id)).all()
    }
    # detect_deletions does not remove the row -- it tombstones it and flags it
    # via the Event feed, so evidence and provenance keep something to point at.
    assert remaining_identities == {"user-1", "user-2"}

    deleted_identity = session.get(Identity, deleted_events[0].entity_id)
    assert deleted_identity is not None
    assert deleted_identity.provider_object_id == "user-2"
    assert deleted_identity.last_seen_at < second_run.started_at
    assert deleted_identity.deleted_at is not None
    survivor = session.scalars(
        select(Identity).where(Identity.org_id == org_id, Identity.provider_object_id == "user-1")
    ).one()
    assert survivor.deleted_at is None

    # Running the same (missing user-2) collection again must not re-report
    # the same deletion a second time.
    third_run = _run(session, instance_id, t1)
    session.flush()
    redundant_deleted_events = session.scalars(
        select(Event).where(
            Event.org_id == org_id,
            Event.entity_type == "identity",
            Event.change_type == ChangeType.DELETED,
            Event.connector_run_id == third_run.id,
        )
    ).all()
    assert redundant_deleted_events == []


def test_a_tombstoned_row_is_revived_when_the_provider_reports_it_again(connector_context):
    session, org_id, instance_id = connector_context
    both = {
        "identity": [_identity_obj("user-1"), _identity_obj("user-2")],
        "role": [_role_obj("admin", is_privileged=True)],
        "grant": [_grant_obj("g-2", identity_ref="user-2", role_ref="admin")],
    }
    only_one = {"identity": [_identity_obj("user-1")], "role": [_role_obj("admin", is_privileged=True)]}

    _run(session, instance_id, both)
    session.flush()
    _run(session, instance_id, only_one)
    session.flush()

    user_2 = session.scalars(
        select(Identity).where(Identity.org_id == org_id, Identity.provider_object_id == "user-2")
    ).one()
    assert user_2.deleted_at is not None
    grant = session.scalars(select(Grant).where(Grant.identity_id == user_2.id)).one()
    assert grant.deleted_at is not None

    revive_run = _run(session, instance_id, both)
    session.flush()
    session.refresh(user_2)
    session.refresh(grant)
    assert user_2.deleted_at is None
    assert grant.deleted_at is None

    # A reappearance is a CREATED change again, not an UPDATED on an old row.
    revived = session.scalars(
        select(Event).where(
            Event.connector_run_id == revive_run.id,
            Event.change_type == ChangeType.CREATED,
        )
    ).all()
    assert {(e.entity_type, e.entity_id) for e in revived} >= {("identity", user_2.id), ("grant", grant.id)}


def test_a_tombstoned_identity_leaves_the_graph(connector_context):
    session, org_id, instance_id = connector_context
    both = {
        "identity": [
            _identity_obj("user-1"),
            _identity_obj(
                "user-2",
                relationships=[
                    NormalizedRelationship(
                        edge_type="assigned_role", source_ref="user-2", target_ref="admin", access_path="direct"
                    )
                ],
            ),
        ],
        "role": [_role_obj("admin", is_privileged=True)],
        "grant": [_grant_obj("g-2", identity_ref="user-2", role_ref="admin")],
    }
    _run(session, instance_id, both)
    session.flush()
    user_2 = session.scalars(
        select(Identity).where(Identity.org_id == org_id, Identity.provider_object_id == "user-2")
    ).one()
    node_before = session.scalars(
        select(GraphNode).where(GraphNode.org_id == org_id, GraphNode.object_id == user_2.id)
    ).one()
    assert session.scalars(select(GraphEdge).where(GraphEdge.source_node_id == node_before.id)).all()

    _run(session, instance_id, {"identity": [_identity_obj("user-1")], "role": [_role_obj("admin", is_privileged=True)]})
    session.flush()

    assert session.scalars(select(GraphNode).where(GraphNode.org_id == org_id, GraphNode.object_id == user_2.id)).all() == []
    assert session.scalars(select(GraphEdge).where(GraphEdge.source_node_id == node_before.id)).all() == []

    # Reappearance rebuilds the node and its edges.
    _run(session, instance_id, both)
    session.flush()
    node_after = session.scalars(select(GraphNode).where(GraphNode.org_id == org_id, GraphNode.object_id == user_2.id)).one()
    assert session.scalars(select(GraphEdge).where(GraphEdge.source_node_id == node_after.id)).all()


def test_run_sync_preserves_raw_source_provenance(connector_context):
    session, org_id, instance_id = connector_context
    raw_payload = {"source": "scripted", "provider_id": "user-1", "extra_field": "kept-verbatim"}
    obj = NormalizedObject(
        kind="identity",
        provider_id="user-1",
        attributes={"identity_type": "user", "email": "user-1@example.test", "display_name": "User One"},
        raw_source=raw_payload,
    )
    run = _run(session, instance_id, {"identity": [obj]})
    session.flush()
    assert run.status is ConnectorRunStatus.SUCCESS

    identity = session.scalars(select(Identity).where(Identity.org_id == org_id)).one()
    assert identity.raw_source == raw_payload
    assert identity.source_connector_run_id == run.id


def test_run_sync_skips_a_relationship_whose_reference_does_not_resolve(connector_context):
    """A membership naming a group or member this run never saw (created
    between two collections, say) is skipped rather than failing the whole
    run; the next run that sees both ends writes it."""
    session, org_id, instance_id = connector_context

    bad_membership = NormalizedObject(
        kind="group_membership",
        provider_id="membership-1",
        attributes={"group_ref": "does-not-exist", "identity_ref": "also-missing"},
        raw_source={},
    )

    run = _run(session, instance_id, {"group_membership": [bad_membership]})
    session.flush()

    assert run.status is ConnectorRunStatus.SUCCESS
    assert session.scalars(select(GroupMembership).where(GroupMembership.org_id == org_id)).all() == []


def test_a_run_with_reduced_coverage_is_reported_as_partial_not_success(connector_context):
    session, _org_id, instance_id = connector_context
    run = _run(
        session,
        instance_id,
        {"identity": [_identity_obj("user-1")]},
        skipped_object_types={"audit_log": "permission"},
    )
    session.flush()

    assert run.status is ConnectorRunStatus.PARTIAL_FAILURE
    assert "audit_log (permission)" in (run.error_summary or "")
    # The rest of the tenant still landed -- degradation is not a failed sync.
    assert session.scalars(select(Identity).where(Identity.org_id == _org_id)).all()


def test_reduced_coverage_never_reports_the_missing_data_as_deleted(connector_context):
    """The regression this guards is severe: deletion detection works by
    absence, so a run that could not read part of the tenant would flag every
    row that family would have refreshed as DELETED -- a single 403 turning
    into "all of your repositories were removed" in the Changes feed."""
    session, org_id, instance_id = connector_context

    first = _run(session, instance_id, {"identity": [_identity_obj("user-1"), _identity_obj("user-2")]})
    session.flush()
    assert first.status is ConnectorRunStatus.SUCCESS

    # Next run cannot read identities at all, and collects nothing.
    degraded = _run(session, instance_id, {"identity": []}, skipped_object_types={"identity": "permission"})
    session.flush()

    assert degraded.status is ConnectorRunStatus.PARTIAL_FAILURE
    deleted = session.scalars(
        select(Event).where(
            Event.org_id == org_id,
            Event.change_type == ChangeType.DELETED,
            Event.connector_run_id == degraded.id,
        )
    ).all()
    assert deleted == []


def test_a_real_deletion_is_still_caught_on_the_next_complete_run(connector_context):
    session, org_id, instance_id = connector_context
    _run(session, instance_id, {"identity": [_identity_obj("user-1"), _identity_obj("user-2")]})
    session.flush()
    _run(session, instance_id, {"identity": []}, skipped_object_types={"identity": "permission"})
    session.flush()

    # Coverage recovers; user-2 really is gone.
    recovered = _run(session, instance_id, {"identity": [_identity_obj("user-1")]})
    session.flush()

    assert recovered.status is ConnectorRunStatus.SUCCESS
    deleted = session.scalars(
        select(Event).where(
            Event.org_id == org_id,
            Event.entity_type == "identity",
            Event.change_type == ChangeType.DELETED,
            Event.connector_run_id == recovered.id,
        )
    ).all()
    assert len(deleted) == 1


def test_reduced_coverage_does_not_write_a_graph_snapshot(connector_context):
    # Snapshots record a full inventory; storing a partial one would diff as
    # mass removal against the previous snapshot.
    from kestrel.graph.snapshots import GraphSnapshot

    session, org_id, instance_id = connector_context
    complete = _run(session, instance_id, {"identity": [_identity_obj("user-1")]})
    session.flush()
    degraded = _run(
        session,
        instance_id,
        {"identity": [_identity_obj("user-1")]},
        skipped_object_types={"audit_log": "permission"},
    )
    session.flush()

    snapshot_runs = {
        s.connector_run_id for s in session.scalars(select(GraphSnapshot).where(GraphSnapshot.org_id == org_id)).all()
    }
    assert complete.id in snapshot_runs
    assert degraded.id not in snapshot_runs


def test_a_not_configured_note_is_coverage_information_not_a_coverage_gap(connector_context):
    """GitHub records ``member.saml_identity = not_configured`` for every org
    without SAML SSO -- there is nothing to read, not something unreadable.
    Treating that as degradation made every such org permanently PARTIAL, with
    deletion detection and snapshots switched off for good: removed members
    were never tombstoned and never produced DELETED events."""
    from kestrel.graph.snapshots import GraphSnapshot

    session, org_id, instance_id = connector_context
    note = {"member.saml_identity": "not_configured"}

    first = _run(
        session, instance_id, {"identity": [_identity_obj("user-1"), _identity_obj("user-2")]}, skipped_object_types=note
    )
    session.flush()
    assert first.status is ConnectorRunStatus.SUCCESS
    assert first.error_summary is None
    # Still shown to the operator, so "no email because no SSO" stays explained.
    assert first.skipped_object_types == note

    # user-2 really is gone; the note is still there.
    second = _run(session, instance_id, {"identity": [_identity_obj("user-1")]}, skipped_object_types=note)
    session.flush()
    assert second.status is ConnectorRunStatus.SUCCESS
    deleted = session.scalars(
        select(Event).where(
            Event.org_id == org_id,
            Event.entity_type == "identity",
            Event.change_type == ChangeType.DELETED,
            Event.connector_run_id == second.id,
        )
    ).all()
    assert len(deleted) == 1
    snapshot_runs = {
        s.connector_run_id for s in session.scalars(select(GraphSnapshot).where(GraphSnapshot.org_id == org_id)).all()
    }
    assert {first.id, second.id} <= snapshot_runs


def test_a_truncated_family_still_degrades_the_run(connector_context):
    """A cap on a per-parent walk (GitHub's deep-scan limit, Slack's channel
    membership limit) leaves rows past the cap unrefreshed; absence must not
    be read as deletion there, so truncation keeps suppressing it."""
    session, _org_id, instance_id = connector_context
    run = _run(
        session,
        instance_id,
        {"identity": [_identity_obj("user-1")]},
        skipped_object_types={"repo_posture.truncated": "deep_scan_limit=200"},
    )
    session.flush()
    assert run.status is ConnectorRunStatus.PARTIAL_FAILURE


def test_a_real_gap_beside_a_note_still_degrades_the_run(connector_context):
    session, _org_id, instance_id = connector_context
    run = _run(
        session,
        instance_id,
        {"identity": [_identity_obj("user-1")]},
        skipped_object_types={"member.saml_identity": "not_configured", "audit_log": "permission"},
    )
    session.flush()
    assert run.status is ConnectorRunStatus.PARTIAL_FAILURE
    assert "audit_log (permission)" in (run.error_summary or "")
    assert "member.saml_identity" not in (run.error_summary or "")


def _resource_grant_obj(identity_ref: str, resource_ref: str) -> NormalizedObject:
    """A direct admin grant on a resource -- distinct from `_grant_obj` above,
    which grants a role rather than access to a specific resource."""
    return NormalizedObject(
        kind="grant",
        provider_id=f"{identity_ref}:{resource_ref}",
        attributes={
            "identity_ref": identity_ref,
            "resource_ref": resource_ref,
            "granted_via": "direct",
            "permission_level": "admin",
        },
        raw_source={"source": "scripted"},
    )


def _resource_obj(provider_id: str, name: str) -> NormalizedObject:
    return NormalizedObject(
        kind="resource",
        provider_id=provider_id,
        attributes={"resource_type": "repository", "name": name, "visibility": "private"},
        raw_source={},
    )


def _access_edge(identity_ref: str, resource_ref: str) -> NormalizedRelationship:
    return NormalizedRelationship(
        edge_type="can_access",
        source_ref=identity_ref,
        target_ref=resource_ref,
        access_path="direct",
    )


def _tenant_with_access(session: Session, instance_id: uuid.UUID):
    """One identity with a direct admin grant on one repo, plus the edge."""
    identity = _identity_obj("user-1", relationships=[_access_edge("user-1", "repo-1")])
    return _run(
        session,
        instance_id,
        {
            "identity": [identity],
            "resource": [_resource_obj("repo-1", "web-app")],
            "grant": [_resource_grant_obj("user-1", "repo-1")],
        },
    )


def test_revoked_access_disappears_from_the_graph(connector_context):
    """edges carried last_seen_at and nothing ever pruned them, so a
    grant revoked six months ago still drew a line in Explore."""
    session, org_id, instance_id = connector_context
    _tenant_with_access(session, instance_id)
    session.flush()
    before = session.scalars(
        select(GraphEdge).where(GraphEdge.org_id == org_id, GraphEdge.edge_type == GraphEdgeType.CAN_ACCESS)
    ).all()
    assert len(before) == 1

    # Next run: the identity and repo remain, the grant is gone.
    _run(
        session,
        instance_id,
        {
            "identity": [_identity_obj("user-1")],
            "resource": [_resource_obj("repo-1", "web-app")],
            "grant": [],
        },
    )
    session.flush()

    after = session.scalars(
        select(GraphEdge).where(GraphEdge.org_id == org_id, GraphEdge.edge_type == GraphEdgeType.CAN_ACCESS)
    ).all()
    assert after == []


def test_pruning_an_edge_emits_no_second_change_row(connector_context):
    # The grant row's DELETED change already records the revocation; a graph
    # event on top would double-count one revocation in the feed.
    session, org_id, instance_id = connector_context
    _tenant_with_access(session, instance_id)
    session.flush()

    run = _run(
        session,
        instance_id,
        {
            "identity": [_identity_obj("user-1")],
            "resource": [_resource_obj("repo-1", "web-app")],
            "grant": [],
        },
    )
    session.flush()

    deleted = session.scalars(
        select(Event).where(
            Event.org_id == org_id,
            Event.change_type == ChangeType.DELETED,
            Event.connector_run_id == run.id,
        )
    ).all()
    assert [event.entity_type for event in deleted] == ["grant"]


def test_access_that_still_exists_is_not_pruned(connector_context):
    session, org_id, instance_id = connector_context
    _tenant_with_access(session, instance_id)
    session.flush()
    _tenant_with_access(session, instance_id)
    session.flush()

    edges = session.scalars(
        select(GraphEdge).where(GraphEdge.org_id == org_id, GraphEdge.edge_type == GraphEdgeType.CAN_ACCESS)
    ).all()
    assert len(edges) == 1


def test_a_degraded_run_never_prunes_the_graph(connector_context):
    # Same reasoning as entity deletion detection: a run that could not read
    # part of the tenant has no evidence any of it is gone.
    session, org_id, instance_id = connector_context
    _tenant_with_access(session, instance_id)
    session.flush()

    _run(
        session,
        instance_id,
        {"identity": [], "resource": [], "grant": []},
        skipped_object_types={"grant": "permission"},
    )
    session.flush()

    edges = session.scalars(
        select(GraphEdge).where(GraphEdge.org_id == org_id, GraphEdge.edge_type == GraphEdgeType.CAN_ACCESS)
    ).all()
    assert len(edges) == 1


def test_another_connector_instances_edges_are_left_alone(connector_context):
    session, org_id, instance_id = connector_context
    other_app = make_application_instance(session, session.get(Organization, org_id))
    other_instance = make_connector_instance(session, session.get(Organization, org_id), application_instance=other_app)
    session.flush()
    _tenant_with_access(session, instance_id)
    _tenant_with_access(session, other_instance.id)
    session.flush()

    # The first instance loses its grant; the second one syncs nothing.
    _run(
        session,
        instance_id,
        {
            "identity": [_identity_obj("user-1")],
            "resource": [_resource_obj("repo-1", "web-app")],
            "grant": [],
        },
    )
    session.flush()

    remaining = session.scalars(
        select(GraphEdge).where(GraphEdge.org_id == org_id, GraphEdge.edge_type == GraphEdgeType.CAN_ACCESS)
    ).all()
    assert len(remaining) == 1


def test_two_connector_instances_on_one_application_instance_do_not_tombstone_each_other(connector_context):
    """A PAT instance and a GitHub App instance can be bound to the same org.
    Each collects what its credential can see, so their inventories differ;
    provenance tombstoning used to scope by application instance alone and
    each run reported the other's rows as deleted, which the other revived."""
    session, org_id, instance_id = connector_context
    org = session.get(Organization, org_id)
    shared_app = session.get(ApplicationInstance, session.get(ConnectorInstance, instance_id).application_instance_id)
    sibling = make_connector_instance(session, org, application_instance=shared_app)
    session.flush()

    _run(session, instance_id, {"identity": [_identity_obj("pat-only")]})
    session.flush()
    sibling_run = _run(session, sibling.id, {"identity": [_identity_obj("app-only")]})
    session.flush()
    rerun = _run(session, instance_id, {"identity": [_identity_obj("pat-only")]})
    session.flush()

    live = {
        row.provider_object_id
        for row in session.scalars(select(Identity).where(Identity.org_id == org_id, Identity.deleted_at.is_(None))).all()
    }
    assert live == {"pat-only", "app-only"}
    deleted = session.scalars(
        select(Event).where(
            Event.org_id == org_id,
            Event.change_type == ChangeType.DELETED,
            Event.connector_run_id.in_([sibling_run.id, rerun.id]),
        )
    ).all()
    assert deleted == []

    # A row this instance really stopped seeing is still tombstoned.
    final = _run(session, instance_id, {"identity": []})
    session.flush()
    gone = session.scalars(
        select(Event).where(Event.connector_run_id == final.id, Event.change_type == ChangeType.DELETED)
    ).all()
    assert [session.get(Identity, e.entity_id).provider_object_id for e in gone] == ["pat-only"]


def test_a_degraded_run_records_which_families_it_could_not_read(connector_context):
    """The skip list is structured on the run, so the UI does not have to parse
    prose out of `error_summary` to say what is missing."""
    session, _org_id, instance_id = connector_context

    run = _run(
        session,
        instance_id,
        {"identity": [_identity_obj("user-1")]},
        skipped_object_types={"audit_log": "permission"},
    )
    session.flush()

    assert run.status is ConnectorRunStatus.PARTIAL_FAILURE
    assert run.skipped_object_types == {"audit_log": "permission"}


def test_a_complete_run_records_an_empty_skip_list(connector_context):
    session, _org_id, instance_id = connector_context

    run = _run(session, instance_id, {"identity": [_identity_obj("user-1")]})
    session.flush()

    assert run.status is ConnectorRunStatus.SUCCESS
    assert run.skipped_object_types == {}
