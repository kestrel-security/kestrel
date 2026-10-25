# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Tier 2 -- cursored incremental sync.

`Collector.collect(since=)` was in the SDK from the start and Okta and Slack
both forwarded it to their audit clients, but `run_sync` never supplied
it: there was nowhere to persist a high-water mark, so every sync re-read the
provider's full default window.

Two properties matter beyond "the cursor moves". An events-only run collects a
fraction of the tenant, so it must never run deletion detection -- and it must
never be mistaken for a full inventory, because both the Changes baseline and
connector freshness are computed from successful runs.

Uses ScriptedConnector from test_pipeline_sync (rule 1: tests own their data).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any, ClassVar

import pytest
from kestrel.changes.feed import change_feed
from kestrel.connectors.sdk.base import NormalizedObject
from kestrel.db.models.connector import ConnectorCursor, ConnectorRunStatus, ConnectorRunTrigger
from kestrel.db.models.event import ChangeType, Event
from kestrel.db.models.identity import Identity
from kestrel.sync.cursors import OVERLAP_WINDOW, load_since_by_object_type
from kestrel.sync.pipeline import run_sync
from kestrel.testing import make_application_instance, make_connector_instance, make_organization
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from tests.integration.test_pipeline_sync import ScriptedConnector, _identity_obj


def _audit_obj(provider_id: str, *, occurred_at: datetime | None = None) -> NormalizedObject:
    return NormalizedObject(
        kind="event",
        provider_id=provider_id,
        attributes={
            "action": "privilege.grant",
            "action_category": "privilege",
            "occurred_at": (occurred_at or datetime.now(UTC)).isoformat(),
            "summary": f"grant {provider_id}",
        },
        raw_source={},
    )


class _World:
    def __init__(self, session: Session):
        self.session = session
        self.org = make_organization(session)
        self.app_instance = make_application_instance(session, self.org)
        self.instance = make_connector_instance(session, self.org, application_instance=self.app_instance)
        session.flush()

    def run(self, objects_by_type, *, object_types=None):
        run = run_sync(
            self.session,
            connector_instance_id=self.instance.id,
            connector=ScriptedConnector(objects_by_type),
            config={},
            transport_override=object(),
            triggered_by=ConnectorRunTrigger.SCHEDULE,
            object_types=object_types,
        )
        self.session.flush()
        return run

    def cursors(self) -> dict[str, str]:
        rows = self.session.scalars(
            select(ConnectorCursor).where(ConnectorCursor.connector_instance_id == self.instance.id)
        ).all()
        return {row.object_type: row.cursor for row in rows}


def test_a_full_run_advances_a_cursor_for_every_object_type_it_collected(db_session: Session):
    world = _World(db_session)
    world.run({"identity": [_identity_obj("u1")], "event": [_audit_obj("e1")]})

    assert set(world.cursors()) == {"identity", "event"}


def test_the_watermark_handed_back_is_overlapped_not_the_exact_last_position(db_session: Session):
    # Provider audit logs are eventually consistent: an event that occurred at
    # T can surface after a poll that asked for everything since T. Asking for
    # the exact boundary drops events.
    world = _World(db_session)
    run = world.run({"event": [_audit_obj("e1")]})

    since = load_since_by_object_type(db_session, connector_instance_id=world.instance.id)
    assert since["event"] == run.started_at - OVERLAP_WINDOW


def test_an_overlapping_re_read_creates_no_duplicate_rows_or_feed_entries(db_session: Session):
    world = _World(db_session)
    world.run({"event": [_audit_obj("e1"), _audit_obj("e2")]})

    # The overlap means the next poll sees e2 again alongside a new e3.
    world.run({"event": [_audit_obj("e2"), _audit_obj("e3")]}, object_types=["event"])

    from kestrel.db.models.activity_event import ActivityEvent

    rows = db_session.scalars(select(ActivityEvent).where(ActivityEvent.org_id == world.org.id)).all()
    assert {row.provider_object_id for row in rows} == {"e1", "e2", "e3"}
    # And none of it reached the Changes feed.
    feed = change_feed(db_session, world.org.id, min_significance="low")
    assert feed["changes"] == []


def test_an_events_only_run_never_reports_the_inventory_it_did_not_read_as_deleted(
    db_session: Session,
):
    """The regression that would make incremental sync unshippable.

    Deletion detection works by absence. An events-only run refreshes nothing
    in the directory, so every identity still carries a stale last_seen_at --
    running it would flag the entire tenant as removed.
    """
    world = _World(db_session)
    world.run({"identity": [_identity_obj("u1"), _identity_obj("u2")], "event": []})

    events_run = world.run({"event": [_audit_obj("e1")]}, object_types=["event"])

    assert events_run.status is ConnectorRunStatus.SUCCESS
    assert events_run.is_incremental is True
    deleted = db_session.scalars(
        select(Event).where(
            Event.org_id == world.org.id,
            Event.change_type == ChangeType.DELETED,
            Event.connector_run_id == events_run.id,
        )
    ).all()
    assert deleted == []
    assert len(db_session.scalars(select(Identity).where(Identity.org_id == world.org.id)).all()) == 2


def test_an_events_only_run_does_not_advance_cursors_for_types_it_skipped(db_session: Session):
    world = _World(db_session)
    world.run({"identity": [_identity_obj("u1")], "event": [_audit_obj("e1")]})
    first = world.cursors()

    world.run({"event": [_audit_obj("e2")]}, object_types=["event"])
    second = world.cursors()

    assert second["identity"] == first["identity"]  # untouched
    assert second["event"] != first["event"]


def test_an_events_only_run_writes_no_graph_snapshot(db_session: Session):
    from kestrel.graph.snapshots import GraphSnapshot

    world = _World(db_session)
    world.run({"identity": [_identity_obj("u1")], "event": []})
    before = len(db_session.scalars(select(GraphSnapshot).where(GraphSnapshot.org_id == world.org.id)).all())

    world.run({"event": [_audit_obj("e1")]}, object_types=["event"])

    after = len(db_session.scalars(select(GraphSnapshot).where(GraphSnapshot.org_id == world.org.id)).all())
    assert after == before


def test_an_events_only_run_is_never_taken_for_the_changes_baseline(db_session: Session):
    """If it were, the real baseline's creations would all flood the feed."""
    world = _World(db_session)
    # An events poll lands first -- a real ordering when beat starts before the
    # operator's first scheduled inventory sync.
    world.run({"event": [_audit_obj("e1")]}, object_types=["event"])
    world.run({"identity": [_identity_obj("u1"), _identity_obj("u2")], "event": []})

    feed = change_feed(db_session, world.org.id, min_significance="low")
    assert feed["changes"] == []


def test_an_events_only_run_does_not_make_a_stale_connector_look_fresh(db_session: Session):
    from kestrel.connectors.health import connector_health_center

    world = _World(db_session)
    long_ago = datetime.now(UTC) - timedelta(days=3)
    full = world.run({"identity": [_identity_obj("u1")], "event": []})
    full.started_at = long_ago
    full.finished_at = long_ago
    db_session.flush()

    world.run({"event": [_audit_obj("e1")]}, object_types=["event"])

    center = connector_health_center(db_session, world.org.id)
    item = next(i for i in center["items"] if i["id"] == world.instance.id)
    assert item["health"] == "stale"


def test_a_first_incremental_run_has_no_stored_cursor(db_session: Session):
    world = _World(db_session)
    since = load_since_by_object_type(db_session, connector_instance_id=world.instance.id)
    # No cursor yet: absent from the stored map. The pipeline fills in the
    # initial lookback window for cursored types (see the first-run tests below).
    assert since == {}


def test_a_degraded_family_does_not_advance_past_events_it_never_saw(db_session: Session):
    world = _World(db_session)
    run = run_sync(
        db_session,
        connector_instance_id=world.instance.id,
        connector=ScriptedConnector(
            {"identity": [_identity_obj("u1")], "event": []},
            {"event": "permission"},
        ),
        config={},
        transport_override=object(),
        triggered_by=ConnectorRunTrigger.SCHEDULE,
    )
    db_session.flush()

    assert run.status is ConnectorRunStatus.PARTIAL_FAILURE
    cursors = world.cursors()
    assert "identity" in cursors
    assert "event" not in cursors


def test_a_failed_run_advances_nothing(db_session: Session):
    world = _World(db_session)
    bad = NormalizedObject(kind="identity", provider_id="u1", attributes={}, raw_source={})
    # Upserting the attribute-less identity raises KeyError. The
    # pipeline then rolls back to record the FAILED run, and because this
    # test's org was only flushed, recording it can itself fail on the
    # foreign key. Either way the run fails and must advance no cursor.
    with pytest.raises((KeyError, IntegrityError)):
        run_sync(
            db_session,
            connector_instance_id=world.instance.id,
            connector=ScriptedConnector({"identity": [bad]}),
            config={},
            transport_override=object(),
            triggered_by=ConnectorRunTrigger.SCHEDULE,
        )
    db_session.rollback()

    remaining = db_session.scalars(
        select(ConnectorCursor).where(ConnectorCursor.connector_instance_id == world.instance.id)
    ).all()
    assert remaining == []


def test_a_non_timestamp_cursor_is_ignored_rather_than_crashing(db_session: Session):
    # Room for an opaque provider cursor (GitHub's audit-log `after` token)
    # in the same column; nothing time-based can be derived from it.
    world = _World(db_session)
    db_session.add(
        ConnectorCursor(
            id=uuid.uuid4(),
            org_id=world.org.id,
            connector_instance_id=world.instance.id,
            object_type="audit_log",
            cursor="MS42NzI1MzE",
            advanced_at=datetime.now(UTC),
        )
    )
    db_session.flush()

    assert load_since_by_object_type(db_session, connector_instance_id=world.instance.id) == {}


# -- First run: a bounded window, not the provider's whole history -------------


class _RecordingCollector:
    """Records the ``since`` handed to each object type; collects nothing."""

    def __init__(self, seen: dict[str, datetime | None], object_types: list[str]) -> None:
        self._seen = seen
        self._object_types = object_types

    def discover(self) -> list[str]:
        return list(self._object_types)

    def collect(self, object_type: str, *, since: datetime | None = None):
        self._seen[object_type] = since
        yield from ()

    def health_check(self):
        from kestrel.connectors.sdk.base import HealthCheckResult

        return HealthCheckResult(healthy=True, message="ok")


class _RecordingConnector(ScriptedConnector):
    """A manifest (the stored-dict shape) declaring ``event`` as cursored and
    ``identity`` as a full inventory."""

    manifest: ClassVar[dict[str, Any]] = {
        "object_types": [
            {"name": "event", "supports_incremental": True},
            {"name": "identity", "supports_incremental": False},
        ]
    }

    def __init__(self) -> None:
        super().__init__({})
        self.seen: dict[str, datetime | None] = {}

    def build_collector(self, transport):
        return _RecordingCollector(self.seen, ["event", "identity"])


def _recorded_run(world: _World, connector: _RecordingConnector):
    run = run_sync(
        world.session,
        connector_instance_id=world.instance.id,
        connector=connector,
        config={},
        transport_override=object(),
        triggered_by=ConnectorRunTrigger.SCHEDULE,
    )
    world.session.flush()
    return run


def test_a_first_run_reads_a_cursored_type_from_a_day_back_not_the_whole_provider_window(db_session: Session):
    world = _World(db_session)
    connector = _RecordingConnector()
    run = _recorded_run(world, connector)

    assert connector.seen["event"] == run.started_at - timedelta(hours=24)
    # A full-inventory type is still walked in full.
    assert connector.seen["identity"] is None


def test_once_a_cursor_exists_it_wins_over_the_initial_window(db_session: Session):
    world = _World(db_session)
    first = _recorded_run(world, _RecordingConnector())
    connector = _RecordingConnector()
    _recorded_run(world, connector)

    assert connector.seen["event"] == first.started_at - OVERLAP_WINDOW


def test_the_initial_window_is_configurable(db_session: Session, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("KESTREL_SYNC_INITIAL_LOOKBACK_HOURS", "6")
    world = _World(db_session)
    connector = _RecordingConnector()
    run = _recorded_run(world, connector)
    assert connector.seen["event"] == run.started_at - timedelta(hours=6)


def test_a_zero_window_restores_the_provider_default(db_session: Session, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("KESTREL_SYNC_INITIAL_LOOKBACK_HOURS", "0")
    world = _World(db_session)
    connector = _RecordingConnector()
    _recorded_run(world, connector)
    assert connector.seen["event"] is None
