# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Tier 2 -- ``sync.upsert`` edge cases found in the 0.4.0 correctness review.

Each test drives the upsert passes directly, one ``UpsertContext`` per
simulated run, so the sequence of runs is explicit.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from kestrel.connectors.sdk.base import NormalizedObject
from kestrel.db.models.access import Grant, GroupMembership
from kestrel.db.models.connector import ConnectorRun, ConnectorRunStatus, ConnectorRunTrigger
from kestrel.db.models.event import ChangeType, Event
from kestrel.db.models.oauth import OAuthScope
from kestrel.sync.upsert import (
    EntityChange,
    UpsertContext,
    detect_deletions,
    upsert_provenance_objects,
    upsert_relationship_objects,
)
from kestrel.testing import make_application_instance, make_connector_instance, make_organization
from sqlalchemy import select
from sqlalchemy.orm import Session


class _Runs:
    def __init__(self, session: Session) -> None:
        self.session = session
        org = make_organization(session)
        app_instance = make_application_instance(session, org)
        self.instance = make_connector_instance(session, org, application_instance=app_instance)
        self.org_id = org.id

    def next(self) -> tuple[UpsertContext, datetime]:
        started = datetime.now(UTC)
        run = ConnectorRun(
            id=uuid.uuid4(),
            org_id=self.org_id,
            connector_instance_id=self.instance.id,
            status=ConnectorRunStatus.SUCCESS,
            started_at=started,
            triggered_by=ConnectorRunTrigger.MANUAL,
        )
        self.session.add(run)
        self.session.flush()
        ctx = UpsertContext(
            org_id=self.org_id,
            application_instance_id=self.instance.application_instance_id,
            connector_run_id=run.id,
            connector_instance_id=self.instance.id,
        )
        return ctx, started

    def sync(self, objects: list[NormalizedObject], *, detect: bool = False, **ctx_overrides) -> list[EntityChange]:
        ctx, started = self.next()
        for key, value in ctx_overrides.items():
            setattr(ctx, key, value)
        changes = upsert_provenance_objects(self.session, objects, ctx)
        self.session.flush()
        changes.extend(upsert_relationship_objects(self.session, objects, ctx))
        self.session.flush()
        if detect:
            changes.extend(detect_deletions(self.session, ctx, started))
        for change in changes:
            self.session.add(
                Event(
                    id=uuid.uuid4(),
                    org_id=self.org_id,
                    connector_run_id=ctx.connector_run_id,
                    entity_type=change.entity_type,
                    entity_id=change.entity_id,
                    change_type=change.change_type,
                    field_changes=change.field_changes,
                    detected_at=datetime.now(UTC),
                )
            )
        self.session.flush()
        return changes


@pytest.fixture
def runs(db_session: Session) -> _Runs:
    return _Runs(db_session)


def _obj(kind: str, provider_id: str, **attributes) -> NormalizedObject:
    return NormalizedObject(kind=kind, provider_id=provider_id, attributes=attributes, raw_source={})


def _identity(provider_id: str) -> NormalizedObject:
    return _obj("identity", provider_id, identity_type="user", email=f"{provider_id}@example.test")


def _app(provider_id: str = "client-x") -> NormalizedObject:
    return _obj("oauth_application", provider_id, name="Client X")


def _scope(name: str, app_ref: str = "client-x") -> NormalizedObject:
    return _obj("oauth_scope", f"{app_ref}:{name}", oauth_application_ref=app_ref, scope_name=name)


def _oauth_grant(identity_ref: str, app_ref: str = "client-x") -> NormalizedObject:
    return _obj("oauth_grant", f"{app_ref}:{identity_ref}", oauth_application_ref=app_ref, identity_ref=identity_ref)


def test_a_new_scope_reported_by_two_existing_grants_is_written_once(runs: _Runs):
    """Google Workspace emits one oauth_scope per user token. Once both
    grants exist, nothing flushes between the two users' scopes."""
    base = [_identity("a"), _identity("b"), _app()]
    runs.sync([*base, _scope("openid"), _oauth_grant("a"), _scope("openid"), _oauth_grant("b")])

    runs.sync(
        [*base, _scope("openid"), _scope("drive"), _oauth_grant("a"), _scope("openid"), _scope("drive"), _oauth_grant("b")]
    )

    names = runs.session.scalars(select(OAuthScope.scope_name).where(OAuthScope.org_id == runs.org_id)).all()
    assert sorted(names) == ["drive", "openid"]


def test_a_grant_whose_resource_does_not_resolve_is_skipped(runs: _Runs):
    runs.sync(
        [
            _identity("a"),
            _obj("grant", "g1", identity_ref="a", resource_ref="drive-created-mid-sync", granted_via="direct"),
        ]
    )

    assert runs.session.scalars(select(Grant).where(Grant.org_id == runs.org_id)).all() == []


def test_a_membership_whose_identity_does_not_resolve_is_skipped(runs: _Runs):
    runs.sync(
        [
            _obj("group", "grp", name="Engineering"),
            _obj("group_membership", "grp:ghost", group_ref="grp", identity_ref="user-created-mid-sync"),
        ]
    )

    assert runs.session.scalars(select(GroupMembership).where(GroupMembership.org_id == runs.org_id)).all() == []


def test_an_app_whose_scopes_all_disappear_loses_them(runs: _Runs):
    runs.sync([_app(), _scope("admin:org")], reconcile_absent_scopes=True)

    changes = runs.sync([_app()], reconcile_absent_scopes=True)

    assert runs.session.scalars(select(OAuthScope).where(OAuthScope.org_id == runs.org_id)).all() == []
    scope_changes = [c for c in changes if c.entity_type == "oauth_application" and c.change_type is ChangeType.UPDATED]
    assert scope_changes
    assert scope_changes[0].field_changes == [{"field": "scopes", "old": ["admin:org"], "new": []}]


def test_absent_scopes_are_kept_when_the_run_could_not_vouch_for_them(runs: _Runs):
    runs.sync([_app(), _scope("admin:org")])

    runs.sync([_app()], reconcile_absent_scopes=False)

    names = runs.session.scalars(select(OAuthScope.scope_name).where(OAuthScope.org_id == runs.org_id)).all()
    assert names == ["admin:org"]


def test_a_second_revocation_after_a_restore_is_reported(runs: _Runs):
    identity = _identity("a")
    role = _obj("role", "admin", name="Admin", is_privileged=True)
    grant = _obj("grant", "g1", identity_ref="a", role_ref="admin", granted_via="direct")

    runs.sync([identity, role, grant], detect=True)
    runs.sync([identity, role], detect=True)  # revoked
    runs.sync([identity, role, grant], detect=True)  # restored
    runs.sync([identity, role], detect=True)  # revoked again

    grant_id = runs.session.scalar(select(Grant.id).where(Grant.org_id == runs.org_id))
    deleted = runs.session.scalars(
        select(Event).where(
            Event.org_id == runs.org_id,
            Event.entity_id == grant_id,
            Event.change_type == ChangeType.DELETED,
        )
    ).all()
    assert len(deleted) == 2


def test_query_count_does_not_grow_with_the_number_of_objects(runs: _Runs):
    """The upsert and graph passes load existing rows per kind, not per object."""
    from kestrel.graph.writer import upsert_edges, upsert_nodes
    from kestrel.sync.upsert import upsert_provenance_objects, upsert_relationship_objects
    from sqlalchemy import event

    def _objects(count: int) -> list[NormalizedObject]:
        objects: list[NormalizedObject] = [_obj("role", "admin", name="Admin", is_privileged=True)]
        for index in range(count):
            objects.append(_identity(f"user-{index}"))
            objects.append(_obj("grant", f"g-{index}", identity_ref=f"user-{index}", role_ref="admin", granted_via="direct"))
        return objects

    def _statements(objects: list[NormalizedObject]) -> int:
        ctx, _started = runs.next()
        connection = runs.session.connection()
        seen: list[str] = []

        def _record(conn, cursor, statement, parameters, context, executemany) -> None:
            seen.append(statement)

        event.listen(connection, "before_cursor_execute", _record)
        try:
            upsert_provenance_objects(runs.session, objects, ctx)
            node_ids = upsert_nodes(runs.session, objects, ctx)
            upsert_relationship_objects(runs.session, objects, ctx)
            upsert_edges(runs.session, objects, ctx, node_ids)
            runs.session.flush()
        finally:
            event.remove(connection, "before_cursor_execute", _record)
        return sum(1 for statement in seen if statement.lstrip().upper().startswith("SELECT"))

    small, large = _objects(5), _objects(60)
    _statements(small)
    _statements(large)  # first sight of most rows: inserts
    assert _statements(large) == _statements(small)
