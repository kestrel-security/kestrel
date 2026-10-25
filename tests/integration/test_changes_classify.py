# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Tier 2 -- change detection and classification (``sync.upsert`` diffing +
``changes.classify``).

Drives ``upsert_provenance_objects`` directly across two synthetic
collection passes (t0, t1) built entirely by the test -- not a connector's
shipped ``fixtures/`` / ``fixtures/changed/`` pair, which would couple this
file to one connector's persona data for a behavior (volatile-field
suppression, MFA-disable classification) that has nothing to do with any
particular connector. This is what a last-login timestamp bump and an MFA
disable actually look like at the point they enter the Events feed.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from kestrel.changes.classify import ChangeClass, classify_event
from kestrel.connectors.sdk.base import NormalizedObject
from kestrel.db.models.activity_event import ActivityEvent
from kestrel.db.models.connector import ConnectorRun, ConnectorRunStatus, ConnectorRunTrigger
from kestrel.db.models.event import ChangeType, Event
from kestrel.sync.upsert import UpsertContext, upsert_provenance_objects
from kestrel.testing import make_application_instance, make_connector_instance, make_organization
from sqlalchemy.orm import Session


def _identity_object(provider_id: str, *, mfa_enabled: bool | None, last_active_at: datetime) -> NormalizedObject:
    return NormalizedObject(
        kind="identity",
        provider_id=provider_id,
        attributes={
            "identity_type": "user",
            "email": f"{provider_id}@example.test",
            "display_name": "Test Identity",
            "mfa_enabled": mfa_enabled,
            "last_active_at": last_active_at.isoformat(),
        },
        raw_source={},
    )


class _World:
    def __init__(self, session: Session):
        self.session = session
        self.org = make_organization(session)
        self.app_instance = make_application_instance(session, self.org)
        self.connector_instance = make_connector_instance(session, self.org, application_instance=self.app_instance)
        session.flush()

    def new_run(self) -> ConnectorRun:
        run = ConnectorRun(
            id=uuid.uuid4(),
            org_id=self.org.id,
            connector_instance_id=self.connector_instance.id,
            status=ConnectorRunStatus.RUNNING,
            started_at=datetime.now(UTC),
            triggered_by=ConnectorRunTrigger.MANUAL,
        )
        self.session.add(run)
        self.session.flush()
        return run

    def ctx(self, run: ConnectorRun) -> UpsertContext:
        return UpsertContext(
            org_id=self.org.id,
            application_instance_id=self.app_instance.id,
            connector_run_id=run.id,
            connector_instance_id=self.connector_instance.id,
        )


def test_last_login_only_update_produces_no_event(db_session: Session):
    world = _World(db_session)
    t0 = datetime.now(UTC) - timedelta(days=1)
    t1 = datetime.now(UTC)

    run0 = world.new_run()
    upsert_provenance_objects(db_session, [_identity_object("u1", mfa_enabled=True, last_active_at=t0)], world.ctx(run0))
    db_session.flush()

    run1 = world.new_run()
    changes = upsert_provenance_objects(
        db_session, [_identity_object("u1", mfa_enabled=True, last_active_at=t1)], world.ctx(run1)
    )
    db_session.flush()

    # last_active_at is a VOLATILE_FIELD: it is written onto the row but must
    # not produce a change worth surfacing in the feed.
    assert changes == []


def test_mfa_disable_produces_an_event_classified_as_mfa_disabled(db_session: Session):
    world = _World(db_session)
    now = datetime.now(UTC)

    run0 = world.new_run()
    upsert_provenance_objects(db_session, [_identity_object("u1", mfa_enabled=True, last_active_at=now)], world.ctx(run0))
    db_session.flush()

    run1 = world.new_run()
    changes = upsert_provenance_objects(
        db_session, [_identity_object("u1", mfa_enabled=False, last_active_at=now)], world.ctx(run1)
    )
    db_session.flush()

    assert len(changes) == 1
    change = changes[0]
    assert change.change_type is ChangeType.UPDATED
    field_names = {fc["field"] for fc in change.field_changes}
    assert "mfa_enabled" in field_names
    assert "last_active_at" not in field_names  # volatile field never leaks into field_changes

    event = Event(
        id=uuid.uuid4(),
        org_id=world.org.id,
        connector_run_id=run1.id,
        entity_type=change.entity_type,
        entity_id=change.entity_id,
        change_type=change.change_type,
        field_changes=change.field_changes,
        detected_at=datetime.now(UTC),
    )
    db_session.add(event)
    db_session.flush()

    classified = classify_event(db_session, world.org.id, event)
    assert classified is not None
    assert classified.change_class is ChangeClass.MFA_DISABLED


def test_mfa_staying_enabled_across_other_attribute_changes_is_not_classified_as_mfa_disabled(db_session: Session):
    world = _World(db_session)
    now = datetime.now(UTC)

    run0 = world.new_run()
    upsert_provenance_objects(db_session, [_identity_object("u1", mfa_enabled=True, last_active_at=now)], world.ctx(run0))
    db_session.flush()

    run1 = world.new_run()
    changed = NormalizedObject(
        kind="identity",
        provider_id="u1",
        attributes={
            "identity_type": "user",
            "email": "u1@example.test",
            "display_name": "Renamed Identity",
            "mfa_enabled": True,
            "last_active_at": now.isoformat(),
        },
        raw_source={},
    )
    changes = upsert_provenance_objects(db_session, [changed], world.ctx(run1))
    db_session.flush()

    assert len(changes) == 1
    event = Event(
        id=uuid.uuid4(),
        org_id=world.org.id,
        connector_run_id=run1.id,
        entity_type=changes[0].entity_type,
        entity_id=changes[0].entity_id,
        change_type=changes[0].change_type,
        field_changes=changes[0].field_changes,
        detected_at=datetime.now(UTC),
    )
    db_session.add(event)
    db_session.flush()

    classified = classify_event(db_session, world.org.id, event)
    assert classified is not None
    assert classified.change_class is not ChangeClass.MFA_DISABLED


def test_losing_visibility_into_mfa_is_not_classified_as_mfa_disabled(db_session: Session):
    # A token rotated to a non-owner admin can no longer read 2FA status, so
    # every member's mfa_enabled goes True -> None. That is lost coverage, not
    # every account in the org turning MFA off.
    world = _World(db_session)
    now = datetime.now(UTC)

    run0 = world.new_run()
    upsert_provenance_objects(db_session, [_identity_object("u1", mfa_enabled=True, last_active_at=now)], world.ctx(run0))
    db_session.flush()

    run1 = world.new_run()
    changes = upsert_provenance_objects(
        db_session, [_identity_object("u1", mfa_enabled=None, last_active_at=now)], world.ctx(run1)
    )
    db_session.flush()

    assert len(changes) == 1
    event = Event(
        id=uuid.uuid4(),
        org_id=world.org.id,
        connector_run_id=run1.id,
        entity_type=changes[0].entity_type,
        entity_id=changes[0].entity_id,
        change_type=changes[0].change_type,
        field_changes=changes[0].field_changes,
        detected_at=datetime.now(UTC),
    )
    db_session.add(event)
    db_session.flush()

    classified = classify_event(db_session, world.org.id, event)
    assert classified is not None
    assert classified.change_class is not ChangeClass.MFA_DISABLED
    assert classified.significance.value == "low"


def _audit_event_object(provider_id: str, *, occurred_at: datetime) -> NormalizedObject:
    return NormalizedObject(
        kind="event",
        provider_id=provider_id,
        attributes={
            "action": "privilege.grant",
            "action_category": "privilege",
            "actor_email": "admin@example.test",
            "actor_provider_id": "admin",
            "target_email": "u1@example.test",
            "target_type": "identity",
            "target_provider_id": "u1",
            "occurred_at": occurred_at.isoformat(),
            "summary": "admin granted u1 organization admin",
        },
        raw_source={},
    )


def test_collecting_audit_rows_writes_activity_events_but_no_feed_rows(db_session: Session):
    """audit-log rows must not become Changes rows.

    They are still upserted -- event policies in Findings read them -- but each
    one emitting an EntityChange meant a chatty tenant filled ``events`` with
    ``other`` / ``low`` rows that consume FEED_SCAN_CAP before classification.
    """
    world = _World(db_session)
    now = datetime.now(UTC)

    run0 = world.new_run()
    audit_rows = [_audit_event_object(f"log-{i}", occurred_at=now - timedelta(minutes=i)) for i in range(25)]
    changes = upsert_provenance_objects(db_session, audit_rows, world.ctx(run0))
    db_session.flush()

    assert changes == []
    assert db_session.query(ActivityEvent).filter(ActivityEvent.org_id == world.org.id).count() == 25


def test_audit_rows_do_not_crowd_a_real_grant_out_of_the_feed(db_session: Session):
    """The failure this fixes: real drift ranked behind hundreds of log lines."""
    world = _World(db_session)
    now = datetime.now(UTC)

    run0 = world.new_run()
    upsert_provenance_objects(db_session, [_identity_object("u1", mfa_enabled=True, last_active_at=now)], world.ctx(run0))
    db_session.flush()

    run1 = world.new_run()
    noisy = [_audit_event_object(f"log-{i}", occurred_at=now - timedelta(minutes=i)) for i in range(600)]
    changes = upsert_provenance_objects(
        db_session,
        [*noisy, _identity_object("u1", mfa_enabled=False, last_active_at=now)],
        world.ctx(run1),
    )
    db_session.flush()

    # 600 audit rows collected alongside one MFA disable: exactly one feed row.
    assert len(changes) == 1
    assert changes[0].entity_type == "identity"


def test_audit_rows_are_still_upserted_and_updated_in_place(db_session: Session):
    """Suppressing the feed row must not suppress the ActivityEvent itself."""
    world = _World(db_session)
    now = datetime.now(UTC)

    run0 = world.new_run()
    upsert_provenance_objects(db_session, [_audit_event_object("log-1", occurred_at=now)], world.ctx(run0))
    db_session.flush()

    run1 = world.new_run()
    revised = _audit_event_object("log-1", occurred_at=now)
    revised.attributes["summary"] = "corrected summary"
    changes = upsert_provenance_objects(db_session, [revised], world.ctx(run1))
    db_session.flush()

    assert changes == []
    row = db_session.query(ActivityEvent).filter(ActivityEvent.org_id == world.org.id).one()
    assert row.summary == "corrected summary"
