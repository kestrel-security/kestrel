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
from kestrel.db.models.identity import Identity, ServiceAccount
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


# -- identity extras, worker type, and activity merging ----------------------


def _identity_with(provider_id: str, **attributes) -> NormalizedObject:
    return _obj("identity", provider_id, identity_type="user", email=f"{provider_id}@example.test", **attributes)


def _stored_identity(runs: _Runs, provider_id: str) -> Identity:
    row = runs.session.scalar(
        select(Identity).where(Identity.org_id == runs.org_id, Identity.provider_object_id == provider_id)
    )
    assert row is not None
    return row


def test_identity_extras_land_in_columns_and_attributes(runs: _Runs):
    runs.sync(
        [
            _identity_with(
                "pat",
                worker_type="contractor",
                department="Platform",
                title="SRE",
                manager_email="lead@example.test",
                disabled_at="2026-01-02T03:04:05Z",
                expires_at="2026-12-31T00:00:00Z",
                org_unit_path="/Contractors",
                guest_type=None,
                is_admin=False,
            )
        ]
    )

    row = _stored_identity(runs, "pat")
    assert row.worker_type == "contractor"
    assert row.worker_type_source == "connector"
    assert (row.department, row.title, row.manager_email) == ("Platform", "SRE", "lead@example.test")
    assert row.disabled_at == datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
    assert row.expires_at == datetime(2026, 12, 31, tzinfo=UTC)
    # Columns stay out of the extras; nulls are dropped; keys are sorted.
    assert row.attributes == {"is_admin": False, "org_unit_path": "/Contractors"}


def test_an_unrecognized_worker_type_is_stored_as_unknown_without_a_source(runs: _Runs):
    runs.sync([_identity_with("a", worker_type="Wizard")])
    row = _stored_identity(runs, "a")
    assert (row.worker_type, row.worker_type_source) == ("unknown", None)


def test_attribute_changes_are_reported_per_key(runs: _Runs):
    runs.sync([_identity_with("a", org_unit_path="/Staff", is_admin=False)])

    changes = runs.sync([_identity_with("a", org_unit_path="/Contractors", is_admin=False)])

    updates = [c for c in changes if c.entity_type == "identity" and c.change_type is ChangeType.UPDATED]
    assert [c.field_changes for c in updates] == [
        [{"field": "attributes.org_unit_path", "old": "/Staff", "new": "/Contractors"}]
    ]


def test_a_rule_assigned_worker_type_survives_a_resync(runs: _Runs):
    runs.sync([_identity_with("a", worker_type="employee")])
    row = _stored_identity(runs, "a")
    row.worker_type = "contractor"
    row.worker_type_source = "rule:ou-contractors"
    runs.session.flush()

    changes = runs.sync([_identity_with("a", worker_type="employee")])

    row = _stored_identity(runs, "a")
    assert (row.worker_type, row.worker_type_source) == ("contractor", "rule:ou-contractors")
    assert not [c for c in changes if c.entity_type == "identity" and c.change_type is ChangeType.UPDATED]


def test_a_resync_without_activity_keeps_the_stored_last_active(runs: _Runs):
    """A GitHub member re-sync carries no sign-in field; it must not erase what
    an audit-log poll learned."""
    runs.sync([_identity_with("a", last_active_at="2026-05-01T00:00:00Z", last_active_source="audit")])

    runs.sync([_identity_with("a")])

    row = _stored_identity(runs, "a")
    assert (row.last_active_at, row.last_active_source) == (datetime(2026, 5, 1, tzinfo=UTC), "audit")


def test_an_untrusted_source_never_replaces_a_trusted_one(runs: _Runs):
    runs.sync([_identity_with("a", last_active_at="2026-05-01T00:00:00Z", last_active_source="login")])

    runs.sync([_identity_with("a", last_active_at="2026-06-01T00:00:00Z", last_active_source="profile")])

    row = _stored_identity(runs, "a")
    assert (row.last_active_at, row.last_active_source) == (datetime(2026, 5, 1, tzinfo=UTC), "login")


def test_a_trusted_source_replaces_an_untrusted_one_even_when_older(runs: _Runs):
    runs.sync([_identity_with("a", last_active_at="2026-06-01T00:00:00Z", last_active_source="profile")])

    runs.sync([_identity_with("a", last_active_at="2026-05-01T00:00:00Z", last_active_source="audit")])

    row = _stored_identity(runs, "a")
    assert (row.last_active_at, row.last_active_source) == (datetime(2026, 5, 1, tzinfo=UTC), "audit")


def test_identity_activity_advances_last_active_on_an_events_only_run(runs: _Runs):
    runs.sync([_identity_with("a", last_active_at="2026-05-01T00:00:00Z", last_active_source="login")])

    # The audit-log poll: no identities in the run, two observations for one
    # account, the later one wins, and an unknown actor is ignored.
    runs.sync(
        [
            _obj("identity_activity", "e1", identity_ref="a", observed_at="2026-05-03T00:00:00Z", source="audit"),
            _obj("identity_activity", "e2", identity_ref="a", observed_at="2026-05-09T12:00:00Z", source="audit"),
            _obj("identity_activity", "e3", identity_ref="ghost", observed_at="2026-05-09T12:00:00Z", source="audit"),
        ]
    )

    row = _stored_identity(runs, "a")
    assert (row.last_active_at, row.last_active_source) == (datetime(2026, 5, 9, 12, tzinfo=UTC), "audit")

    # Re-reading the overlap window, or an older window, changes nothing.
    runs.sync([_obj("identity_activity", "e1", identity_ref="a", observed_at="2026-05-03T00:00:00Z", source="audit")])
    row = _stored_identity(runs, "a")
    assert row.last_active_at == datetime(2026, 5, 9, 12, tzinfo=UTC)


def test_identity_activity_is_not_a_change_feed_row(runs: _Runs):
    runs.sync([_identity_with("a")])
    changes = runs.sync([_obj("identity_activity", "e1", identity_ref="a", observed_at="2026-05-03T00:00:00Z")])
    assert changes == []


def test_service_account_owner_is_written_from_the_owner_ref(runs: _Runs):
    runs.sync(
        [
            _identity_with("owner"),
            _obj(
                "identity", "token-1", identity_type="service_account", display_name="CI token", owner_identity_ref="owner"
            ),
            _obj("identity", "token-2", identity_type="service_account", display_name="Orphan token"),
        ]
    )

    owner = _stored_identity(runs, "owner")
    accounts = {
        row.identity_id: row.owner_identity_id
        for row in runs.session.scalars(select(ServiceAccount)).all()
        if row.identity_id in {_stored_identity(runs, "token-1").id, _stored_identity(runs, "token-2").id}
    }
    assert accounts == {_stored_identity(runs, "token-1").id: owner.id}
