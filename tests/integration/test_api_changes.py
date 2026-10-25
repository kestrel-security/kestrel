# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Tier 2 -- the `/changes` feed (`changes.feed` + the router over it).

Covers baseline exclusion, identity resolution, `scan_saturated`,
pagination, and the route. Data is built through `upsert_provenance_objects` and
`ConnectorRun` rows the tests own -- never a demo persona, never a shipped
connector fixture.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from kestrel.changes.feed import FEED_SCAN_CAP, ChangeFeedError, change_feed
from kestrel.connectors.sdk.base import NormalizedObject
from kestrel.db.models.access import Grant, GrantedVia
from kestrel.db.models.connector import ConnectorRun, ConnectorRunStatus, ConnectorRunTrigger
from kestrel.db.models.event import ChangeType, Event
from kestrel.db.models.identity import Identity
from kestrel.db.models.resource import Resource, ResourceType
from kestrel.sync.upsert import UpsertContext, upsert_provenance_objects
from kestrel.testing import (
    api_client,
    make_application_instance,
    make_connector_instance,
    make_organization,
)
from sqlalchemy import insert, select
from sqlalchemy.orm import Session


def _identity(provider_id: str, *, email: str, mfa_enabled: bool | None = True) -> NormalizedObject:
    return NormalizedObject(
        kind="identity",
        provider_id=provider_id,
        attributes={
            "identity_type": "user",
            "email": email,
            "display_name": email.split("@")[0].title(),
            "mfa_enabled": mfa_enabled,
        },
        raw_source={},
    )


class _World:
    """One org with one connector instance, plus helpers to stage drift."""

    def __init__(self, session: Session, *, display_name: str = "Acme GitHub"):
        self.session = session
        self.org = make_organization(session)
        self.app_instance = make_application_instance(session, self.org, display_name=display_name)
        self.instance = make_connector_instance(session, self.org, application_instance=self.app_instance)
        session.flush()

    def sync(
        self,
        objects: list[NormalizedObject],
        *,
        is_incremental: bool = False,
        status: ConnectorRunStatus = ConnectorRunStatus.SUCCESS,
    ) -> ConnectorRun:
        """One run (successful by default) that upserts `objects` and records their changes."""
        run = ConnectorRun(
            id=uuid.uuid4(),
            org_id=self.org.id,
            connector_instance_id=self.instance.id,
            status=status,
            started_at=datetime.now(UTC),
            finished_at=datetime.now(UTC),
            triggered_by=ConnectorRunTrigger.MANUAL,
            is_incremental=is_incremental,
        )
        self.session.add(run)
        self.session.flush()
        ctx = UpsertContext(
            org_id=self.org.id,
            application_instance_id=self.app_instance.id,
            connector_run_id=run.id,
            connector_instance_id=self.instance.id,
        )
        changes = upsert_provenance_objects(self.session, objects, ctx)
        for change in changes:
            self.session.add(
                Event(
                    id=uuid.uuid4(),
                    org_id=self.org.id,
                    connector_run_id=run.id,
                    entity_type=change.entity_type,
                    entity_id=change.entity_id,
                    change_type=change.change_type,
                    field_changes=change.field_changes,
                    detected_at=datetime.now(UTC),
                )
            )
        self.session.flush()
        return run

    def raw_events(self, run: ConnectorRun, count: int, *, entity_type: str = "identity") -> None:
        """Bulk filler events, to push the scan cap without staging real drift."""
        for _ in range(count):
            self.session.add(
                Event(
                    id=uuid.uuid4(),
                    org_id=self.org.id,
                    connector_run_id=run.id,
                    entity_type=entity_type,
                    entity_id=uuid.uuid4(),
                    change_type=ChangeType.CREATED,
                    field_changes=[],
                    detected_at=datetime.now(UTC),
                )
            )
        self.session.flush()


# -- baseline ---------------------------------------------------------------


def test_the_first_successful_run_is_the_baseline_and_never_appears(db_session: Session):
    world = _World(db_session)
    world.sync([_identity("u1", email="ada@acme.test"), _identity("u2", email="grace@acme.test")])

    feed = change_feed(db_session, world.org.id, min_significance="low")

    assert feed["changes"] == []
    assert feed["total"] == 0


def test_drift_after_the_baseline_does_appear(db_session: Session):
    world = _World(db_session)
    world.sync([_identity("u1", email="ada@acme.test")])
    world.sync([_identity("u1", email="ada@acme.test", mfa_enabled=False)])

    feed = change_feed(db_session, world.org.id)

    assert [c["change_class"] for c in feed["changes"]] == ["mfa_disabled"]
    # Medium, not high: this identity holds no privileged role. Severity of an
    # MFA disable is a property of who it happened to.
    assert feed["summary"]["by_significance"] == {"high": 0, "medium": 1, "low": 0}


def test_an_incremental_run_is_not_eligible_to_be_the_baseline(db_session: Session):
    # an events-only poll landing first would otherwise be chosen, and
    # the real baseline's creations would all flood the feed.
    world = _World(db_session)
    world.sync([], is_incremental=True)
    world.sync([_identity("u1", email="ada@acme.test")])

    assert change_feed(db_session, world.org.id, min_significance="low")["changes"] == []


def test_a_partial_failure_first_run_is_still_the_baseline(db_session: Session):
    # A GitHub org without audit-log access is PARTIAL_FAILURE on every run.
    # Its first run must still be the baseline, or every creation it wrote
    # floods the feed for the whole window.
    world = _World(db_session)
    world.sync(
        [_identity("u1", email="ada@acme.test"), _identity("u2", email="grace@acme.test")],
        status=ConnectorRunStatus.PARTIAL_FAILURE,
    )

    assert change_feed(db_session, world.org.id, min_significance="low")["changes"] == []


def test_drift_after_a_partial_failure_baseline_appears(db_session: Session):
    world = _World(db_session)
    world.sync([_identity("u1", email="ada@acme.test")], status=ConnectorRunStatus.PARTIAL_FAILURE)
    world.sync([_identity("u1", email="ada@acme.test", mfa_enabled=False)])

    assert [c["change_class"] for c in change_feed(db_session, world.org.id)["changes"]] == ["mfa_disabled"]


def test_a_failed_run_is_never_the_baseline(db_session: Session):
    world = _World(db_session)
    world.sync([], status=ConnectorRunStatus.FAILED)
    world.sync([_identity("u1", email="ada@acme.test")])

    assert change_feed(db_session, world.org.id, min_significance="low")["changes"] == []


def test_each_connector_instance_gets_its_own_baseline(db_session: Session):
    world = _World(db_session)
    other = _World(db_session, display_name="Acme Okta")
    other.org = world.org  # same org, second connected app
    other.app_instance = make_application_instance(db_session, world.org, display_name="Acme Okta")
    other.instance = make_connector_instance(db_session, world.org, application_instance=other.app_instance)
    db_session.flush()

    world.sync([_identity("u1", email="ada@acme.test")])
    world.sync([_identity("u1", email="ada@acme.test", mfa_enabled=False)])
    other.sync([_identity("o1", email="grace@acme.test")])  # its own baseline

    classes = [c["change_class"] for c in change_feed(db_session, world.org.id)["changes"]]
    assert classes == ["mfa_disabled"]


# -- filters ----------------------------------------------------------------


def test_the_default_view_hides_low_significance_telemetry(db_session: Session):
    world = _World(db_session)
    baseline = world.sync([_identity("u1", email="ada@acme.test")])
    world.raw_events(baseline, 0)
    run = world.sync([_identity("u1", email="ada@acme.test", mfa_enabled=False)])
    world.raw_events(run, 5)

    default = change_feed(db_session, world.org.id)
    everything = change_feed(db_session, world.org.id, min_significance="low")

    assert default["total"] == 1
    assert everything["total"] > default["total"]


def test_a_class_token_narrows_the_feed(db_session: Session):
    world = _World(db_session)
    world.sync([_identity("u1", email="ada@acme.test")])
    world.sync([_identity("u1", email="ada@acme.test", mfa_enabled=False)])

    assert change_feed(db_session, world.org.id, search="class:mfa_disabled")["total"] == 1
    assert change_feed(db_session, world.org.id, search="class:admin_granted")["total"] == 0


def test_an_unknown_class_is_a_feed_error_not_an_empty_page(db_session: Session):
    world = _World(db_session)
    with pytest.raises(ChangeFeedError):
        change_feed(db_session, world.org.id, change_classes=["not_a_class"])


def test_an_unknown_app_token_is_a_feed_error(db_session: Session):
    world = _World(db_session)
    with pytest.raises(ChangeFeedError):
        change_feed(db_session, world.org.id, search="app:nonexistent")


def test_the_window_excludes_older_drift(db_session: Session):
    world = _World(db_session)
    world.sync([_identity("u1", email="ada@acme.test")])
    world.sync([_identity("u1", email="ada@acme.test", mfa_enabled=False)])

    recent = change_feed(db_session, world.org.id, since=datetime.now(UTC) - timedelta(minutes=5))
    future = change_feed(db_session, world.org.id, since=datetime.now(UTC) + timedelta(minutes=5))

    assert recent["total"] == 1
    assert future["total"] == 0


def test_a_non_positive_window_is_rejected(db_session: Session):
    world = _World(db_session)
    with pytest.raises(ChangeFeedError):
        change_feed(db_session, world.org.id, window_hours=0)


# -- identity-aware resolution ----------------------------------------------


def test_a_person_search_finds_their_drift_by_email(db_session: Session):
    world = _World(db_session)
    world.sync([_identity("u1", email="grace@acme.test"), _identity("u2", email="ada@acme.test")])
    world.sync(
        [
            _identity("u1", email="grace@acme.test", mfa_enabled=False),
            _identity("u2", email="ada@acme.test", mfa_enabled=False),
        ]
    )

    feed = change_feed(db_session, world.org.id, search="person:grace@acme.test")

    assert feed["total"] == 1
    assert "Grace" in feed["changes"][0]["summary"] or "grace" in feed["changes"][0]["summary"]


def test_an_explicit_person_with_no_match_returns_nothing_rather_than_everything(
    db_session: Session,
):
    world = _World(db_session)
    world.sync([_identity("u1", email="ada@acme.test")])
    world.sync([_identity("u1", email="ada@acme.test", mfa_enabled=False)])

    assert change_feed(db_session, world.org.id, search="person:nobody@acme.test")["total"] == 0


def test_a_person_is_found_even_when_telemetry_saturates_the_scan(db_session: Session):
    """promise, now actually pinned.

    The scan cap is applied in SQL before classification, so without identity
    resolution a real MFA disable older than 500 filler rows never reaches the
    classifier at all.
    """
    world = _World(db_session)
    world.sync([_identity("u1", email="grace@acme.test")])
    world.sync([_identity("u1", email="grace@acme.test", mfa_enabled=False)])
    noise = world.sync([])
    world.raw_events(noise, FEED_SCAN_CAP + 100)

    browse = change_feed(db_session, world.org.id, min_significance="low")
    targeted = change_feed(db_session, world.org.id, search="person:grace@acme.test")

    assert browse["scan_saturated"] is True
    assert targeted["total"] == 1
    assert targeted["scan_saturated"] is False


def test_a_broad_search_does_not_overflow_the_bind_parameter_limit(db_session: Session):
    # Free text resolves to every matching identity plus all their grants,
    # memberships and OAuth grants. Materialized into `IN (...)`, that blew
    # past psycopg's 65,535 bind parameters and returned a 500.
    world = _World(db_session)
    world.sync([_identity("u1", email="grace@acme.test")])
    drift = world.sync([_identity("u1", email="grace@acme.test", mfa_enabled=False)])
    identity_id = db_session.scalars(
        select(Identity.id).where(Identity.application_instance_id == world.app_instance.id)
    ).one()
    # One grant per resource: grants are unique on their natural key.
    resource_ids = [uuid.uuid4() for _ in range(66_000)]
    db_session.execute(
        insert(Resource),
        [
            {
                "id": rid,
                "org_id": world.org.id,
                "application_instance_id": world.app_instance.id,
                "provider_object_id": f"repo-{n}",
                "source_connector_run_id": drift.id,
                "raw_source": {},
                "resource_type": ResourceType.REPOSITORY,
                "name": f"repo-{n}",
            }
            for n, rid in enumerate(resource_ids)
        ],
    )
    db_session.execute(
        insert(Grant),
        [
            {
                "id": uuid.uuid4(),
                "org_id": world.org.id,
                "identity_id": identity_id,
                "resource_id": rid,
                "granted_via": GrantedVia.DIRECT,
                "permission_level": "read",
                "source_connector_run_id": drift.id,
            }
            for rid in resource_ids
        ],
    )
    db_session.flush()

    feed = change_feed(db_session, world.org.id, search="grace")

    assert [c["change_class"] for c in feed["changes"]] == ["mfa_disabled"]
    assert feed["scan_saturated"] is False


# -- saturation and paging --------------------------------------------------


def test_scan_saturated_is_false_on_a_quiet_tenant(db_session: Session):
    world = _World(db_session)
    world.sync([_identity("u1", email="ada@acme.test")])
    world.sync([_identity("u1", email="ada@acme.test", mfa_enabled=False)])

    assert change_feed(db_session, world.org.id)["scan_saturated"] is False


def test_audit_rows_no_longer_consume_the_scan_budget(db_session: Session):
    """The feed-level half of keeping audit rows out of the Changes feed.

    Before it, every collected audit row wrote an `events` row, so a chatty
    tenant saturated the pre-classification scan and pushed real drift out of
    the window entirely.
    """
    world = _World(db_session)
    world.sync([_identity("u1", email="grace@acme.test")])
    world.sync([_identity("u1", email="grace@acme.test", mfa_enabled=False)])

    audit = [
        NormalizedObject(
            kind="event",
            provider_id=f"log-{i}",
            attributes={
                "action": "privilege.grant",
                "action_category": "privilege",
                "occurred_at": datetime.now(UTC).isoformat(),
                "summary": f"log line {i}",
            },
            raw_source={},
        )
        for i in range(FEED_SCAN_CAP + 100)
    ]
    world.sync(audit)

    feed = change_feed(db_session, world.org.id, min_significance="low")

    assert feed["scan_saturated"] is False
    assert [c["change_class"] for c in feed["changes"]] == ["mfa_disabled"]


def test_paging_walks_the_result_set_without_repeating_or_dropping(db_session: Session):
    world = _World(db_session)
    people = [f"user{i}@acme.test" for i in range(8)]
    world.sync([_identity(f"u{i}", email=email) for i, email in enumerate(people)])
    world.sync([_identity(f"u{i}", email=email, mfa_enabled=False) for i, email in enumerate(people)])

    first = change_feed(db_session, world.org.id, limit=3, offset=0)
    second = change_feed(db_session, world.org.id, limit=3, offset=3)
    third = change_feed(db_session, world.org.id, limit=3, offset=6)

    assert first["total"] == second["total"] == third["total"] == 8
    ids = [c["event_id"] for page in (first, second, third) for c in page["changes"]]
    assert len(ids) == 8
    assert len(set(ids)) == 8


def test_the_limit_is_clamped_rather_than_trusted(db_session: Session):
    world = _World(db_session)
    world.sync([_identity("u1", email="ada@acme.test")])

    assert change_feed(db_session, world.org.id, limit=100_000)["limit"] == 200
    assert change_feed(db_session, world.org.id, limit=0)["limit"] == 1


# -- the route --------------------------------------------------------------


def test_the_route_returns_the_feed(db_session: Session):
    world = _World(db_session)
    client = api_client(db_session, org=world.org)
    world.sync([_identity("u1", email="ada@acme.test")])
    world.sync([_identity("u1", email="ada@acme.test", mfa_enabled=False)])

    response = client.get("/api/v1/changes")

    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 1
    assert body["changes"][0]["change_class"] == "mfa_disabled"


def test_the_route_rejects_an_invalid_filter_with_422(db_session: Session):
    world = _World(db_session)
    client = api_client(db_session, org=world.org)

    response = client.get("/api/v1/changes", params={"change_class": "not_a_class"})

    assert response.status_code == 422


def test_the_route_never_leaks_another_orgs_changes(db_session: Session):
    mine = _World(db_session)
    theirs = _World(db_session, display_name="Other Corp")
    theirs.sync([_identity("t1", email="them@other.test")])
    theirs.sync([_identity("t1", email="them@other.test", mfa_enabled=False)])
    client = api_client(db_session, org=mine.org)

    body = client.get("/api/v1/changes").json()

    assert body["total"] == 0


def test_the_route_rejects_a_connector_instance_from_another_org(db_session: Session):
    mine = _World(db_session)
    theirs = _World(db_session, display_name="Other Corp")
    client = api_client(db_session, org=mine.org)

    response = client.get("/api/v1/changes", params={"connector_instance_id": str(theirs.instance.id)})

    # 422, not 404: the filter is rejected without confirming whether that id
    # exists at all. Either way no other tenant's rows are reachable.
    assert response.status_code == 422


def test_the_classes_route_lists_every_class_and_significance(db_session: Session):
    world = _World(db_session)
    client = api_client(db_session, org=world.org)

    body = client.get("/api/v1/changes/classes").json()

    assert "admin_granted" in body["classes"]
    assert body["significance"] == ["high", "medium", "low"]


def test_when_saturated_the_total_is_a_lower_bound_and_says_so(db_session: Session):
    """The residual limit of deriving classification at read time.

    `FEED_SCAN_CAP` is applied in SQL, before classification, so on a window
    with more raw events than the cap `total` and `summary` count only what was
    scanned. DEC-024 allows persisting `change_class` on `events` as an escape
    hatch "only if scan-cap remains the limiter" -- took audit
    rows out of the feed and identity resolution took the targeted case, it is
    not. What remains is a browse-only under-count, and `scan_saturated` is the
    contract that it must never be silent.
    """
    world = _World(db_session)
    world.sync([_identity("u1", email="ada@acme.test")])
    noise = world.sync([])
    world.raw_events(noise, FEED_SCAN_CAP + 250)

    feed = change_feed(db_session, world.org.id, min_significance="low")

    assert feed["scan_saturated"] is True
    assert feed["total"] <= FEED_SCAN_CAP


# -- audit actor overlay ------------------------------------------


def _audit(
    provider_id: str,
    *,
    action: str,
    actor: str,
    target_provider_id: str | None = None,
    target_email: str | None = None,
    occurred_at: datetime | None = None,
) -> NormalizedObject:
    return NormalizedObject(
        kind="event",
        provider_id=provider_id,
        attributes={
            "action": action,
            "action_category": action.split(".")[0],
            "actor_email": actor,
            "actor_provider_id": actor.split("@")[0],
            "target_provider_id": target_provider_id,
            "target_email": target_email,
            "occurred_at": (occurred_at or datetime.now(UTC)).isoformat(),
            "summary": f"{actor} did {action}",
        },
        raw_source={},
    )


def _mfa_drift_with_audit(world: _World, audit_specs: list[dict]) -> dict:
    """Baseline, then an MFA disable collected alongside the given audit rows.

    Audit rows are built *after* the baseline run so their `occurred_at` falls
    inside the diff interval the second run covers. Building them earlier puts
    them before the baseline, where the overlay correctly refuses to match.
    Specs may override `occurred_at` explicitly.
    """
    world.sync([_identity("u1", email="grace@acme.test")])
    audit = [_audit(**spec) for spec in audit_specs]
    world.sync([_identity("u1", email="grace@acme.test", mfa_enabled=False), *audit])
    return change_feed(world.session, world.org.id)


def test_the_actor_is_attached_to_the_change_they_caused(db_session: Session):
    world = _World(db_session)
    feed = _mfa_drift_with_audit(
        world,
        [{"provider_id": "a1", "action": "mfa.disable", "actor": "dana@acme.test", "target_provider_id": "u1"}],
    )

    row = feed["changes"][0]
    assert row["change_class"] == "mfa_disabled"
    assert row["actor_email"] == "dana@acme.test"
    assert row["actor_action"] == "mfa.disable"
    assert row["actor_occurred_at"] is not None


def test_the_actor_matches_on_email_when_the_provider_reports_no_target_id(db_session: Session):
    world = _World(db_session)
    feed = _mfa_drift_with_audit(
        world,
        [{"provider_id": "a1", "action": "mfa.disable", "actor": "dana@acme.test", "target_email": "GRACE@acme.test"}],
    )

    assert feed["changes"][0]["actor_email"] == "dana@acme.test"


def test_the_overlay_adds_no_rows_of_its_own(db_session: Session):
    """DEC-024: the log never creates a change. One grant, one row."""
    world = _World(db_session)
    feed = _mfa_drift_with_audit(
        world,
        [
            {"provider_id": "a1", "action": "mfa.disable", "actor": "dana@acme.test", "target_provider_id": "u1"},
            {"provider_id": "a2", "action": "mfa.disable", "actor": "dana@acme.test", "target_provider_id": "u1"},
        ],
    )

    assert feed["total"] == 1


def test_a_change_with_no_audit_log_at_all_is_unchanged(db_session: Session):
    world = _World(db_session)
    feed = _mfa_drift_with_audit(world, [])

    row = feed["changes"][0]
    assert row["change_class"] == "mfa_disabled"
    assert row["actor_email"] is None
    assert row["actor_occurred_at"] is None


def test_an_audit_row_for_a_different_person_is_not_borrowed(db_session: Session):
    world = _World(db_session)
    feed = _mfa_drift_with_audit(
        world,
        [{"provider_id": "a1", "action": "mfa.disable", "actor": "dana@acme.test", "target_provider_id": "someone-else"}],
    )

    assert feed["changes"][0]["actor_email"] is None


def test_an_unrelated_action_in_the_window_is_not_borrowed(db_session: Session):
    # A privilege grant happening to the same person does not explain their
    # MFA going away.
    world = _World(db_session)
    feed = _mfa_drift_with_audit(
        world,
        [{"provider_id": "a1", "action": "privilege.grant", "actor": "dana@acme.test", "target_provider_id": "u1"}],
    )

    assert feed["changes"][0]["actor_email"] is None


def test_an_event_from_outside_the_diff_interval_is_not_borrowed(db_session: Session):
    """The window is the interval the change was actually detected across."""
    world = _World(db_session)
    world.sync([_identity("u1", email="grace@acme.test")])
    stale = _audit(
        "a1",
        action="mfa.disable",
        actor="dana@acme.test",
        target_provider_id="u1",
        occurred_at=datetime.now(UTC) - timedelta(days=30),
    )
    world.sync([_identity("u1", email="grace@acme.test", mfa_enabled=False), stale])

    feed = change_feed(db_session, world.org.id)
    assert feed["changes"][0]["actor_email"] is None


def test_another_tenants_audit_row_never_attaches(db_session: Session):
    world = _World(db_session)
    other = _World(db_session, display_name="Other Corp")
    other.org = world.org
    other.app_instance = make_application_instance(db_session, world.org, display_name="Other App")
    other.instance = make_connector_instance(db_session, world.org, application_instance=other.app_instance)
    db_session.flush()
    # Same subject provider id, same action, same window -- different app.
    other.sync([_audit("a1", action="mfa.disable", actor="mallory@acme.test", target_provider_id="u1")])

    feed = _mfa_drift_with_audit(world, [])

    assert feed["changes"][0]["actor_email"] is None


def test_the_latest_matching_action_wins(db_session: Session):
    """Whoever acted last is whose effect the snapshot recorded.

    Timed explicitly rather than through the helper: both events have to land
    inside the diff interval, which only opens once the baseline run exists.
    """
    world = _World(db_session)
    now = datetime.now(UTC)
    baseline = world.sync([_identity("u1", email="grace@acme.test")])
    # Backdate the baseline so the diff interval is an hour wide and the two
    # events are unambiguously ordered inside it.
    baseline.started_at = now - timedelta(hours=1)
    db_session.flush()

    world.sync(
        [
            _identity("u1", email="grace@acme.test", mfa_enabled=False),
            _audit(
                "a1",
                action="mfa.disable",
                actor="early@acme.test",
                target_provider_id="u1",
                occurred_at=now - timedelta(minutes=30),
            ),
            _audit(
                "a2",
                action="mfa.disable",
                actor="late@acme.test",
                target_provider_id="u1",
                occurred_at=now - timedelta(minutes=5),
            ),
        ]
    )

    feed = change_feed(db_session, world.org.id)
    assert feed["changes"][0]["actor_email"] == "late@acme.test"


def test_the_route_exposes_the_actor(db_session: Session):
    world = _World(db_session)
    client = api_client(db_session, org=world.org)
    _mfa_drift_with_audit(
        world,
        [{"provider_id": "a1", "action": "mfa.disable", "actor": "dana@acme.test", "target_provider_id": "u1"}],
    )

    body = client.get("/api/v1/changes").json()

    assert body["changes"][0]["actor_email"] == "dana@acme.test"
