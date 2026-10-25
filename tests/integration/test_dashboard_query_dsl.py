# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Tier 2 -- the dashboard metric DSL against real findings, connectors and snapshots.

``execute_query`` reads the clock itself (it takes no ``now=``), so every
timestamp here sits days away from any window edge: a run that crosses
midnight, or a slow CI box, cannot move a row across a boundary.
"""

from __future__ import annotations

import uuid
from datetime import UTC, date, datetime, timedelta
from typing import Any

import pytest
from kestrel.dashboard.query_dsl import execute_query
from kestrel.db.models.application import ApplicationType
from kestrel.db.models.connector import ConnectorRun, ConnectorRunStatus, ConnectorRunTrigger, SyncMode
from kestrel.db.models.finding import Finding, FindingStatus, FindingSubjectType
from kestrel.db.models.identity import Identity, IdentityType
from kestrel.db.models.policy import (
    Policy,
    PolicyEvaluation,
    PolicyEvaluationStatus,
    PolicySource,
    PolicyVersion,
    Severity,
)
from kestrel.db.models.posture_trend import PostureTrendSnapshot
from kestrel.testing import (
    make_application,
    make_application_instance,
    make_connector_instance,
    make_operator,
    make_organization,
)
from sqlalchemy.orm import Session

NOW = datetime.now(UTC)


class _World:
    def __init__(self, session: Session) -> None:
        self.session = session
        self.org = make_organization(session)
        policy = Policy(id=uuid.uuid4(), org_id=self.org.id, slug="dsl", title="dsl", source=PolicySource.CUSTOM)
        session.add(policy)
        session.flush()
        self.version = PolicyVersion(
            id=uuid.uuid4(),
            policy_id=policy.id,
            version=1,
            source_text="",
            severity=Severity.HIGH,
            compliance_mappings={},
        )
        session.add(self.version)
        session.flush()
        self.evaluation = PolicyEvaluation(
            id=uuid.uuid4(),
            org_id=self.org.id,
            policy_version_id=self.version.id,
            started_at=NOW,
            status=PolicyEvaluationStatus.SUCCESS,
        )
        session.add(self.evaluation)
        session.flush()

    def finding(
        self,
        *,
        severity: Severity = Severity.HIGH,
        status: FindingStatus = FindingStatus.OPEN,
        subject_type: FindingSubjectType = FindingSubjectType.IDENTITY,
        subject_id: uuid.UUID | None = None,
        first_seen_at: datetime = NOW,
        assignee: uuid.UUID | None = None,
    ) -> Finding:
        row = Finding(
            id=uuid.uuid4(),
            org_id=self.org.id,
            policy_version_id=self.version.id,
            policy_evaluation_id=self.evaluation.id,
            title="dsl finding",
            severity=severity,
            status=status,
            first_seen_at=first_seen_at,
            last_seen_at=first_seen_at,
            subject_type=subject_type,
            subject_id=subject_id or uuid.uuid4(),
            assigned_to_operator_id=assignee,
        )
        self.session.add(row)
        self.session.flush()
        return row

    def identity_in(self, app_type: ApplicationType):
        application = make_application(self.session, self.org, application_type=app_type, name=app_type.value)
        app_instance = make_application_instance(self.session, self.org, application=application)
        connector = make_connector_instance(self.session, self.org, application_instance=app_instance)
        run = ConnectorRun(
            id=uuid.uuid4(),
            org_id=self.org.id,
            connector_instance_id=connector.id,
            status=ConnectorRunStatus.SUCCESS,
            started_at=NOW,
            triggered_by=ConnectorRunTrigger.MANUAL,
        )
        self.session.add(run)
        self.session.flush()
        identity = Identity(
            id=uuid.uuid4(),
            org_id=self.org.id,
            application_instance_id=app_instance.id,
            provider_object_id=f"id-{uuid.uuid4().hex[:8]}",
            identity_type=IdentityType.USER,
            email=f"{uuid.uuid4().hex[:8]}@example.test",
            display_name="dsl identity",
            source_connector_run_id=run.id,
            raw_source={},
        )
        self.session.add(identity)
        self.session.flush()
        return app_instance, identity

    def query(self, spec: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
        return execute_query(self.session, org_id=self.org.id, spec=spec, **kwargs)


@pytest.fixture
def world(db_session: Session) -> _World:
    return _World(db_session)


def _total(world: _World, *filters: dict[str, Any], **spec: Any) -> int:
    return world.query({"entity": "finding", "filters": list(filters), **spec})["total"]


def test_a_finding_count_is_a_kpi_scoped_to_the_org(world: _World, db_session: Session):
    world.finding()
    world.finding()
    other = _World(db_session)
    other.finding()

    result = world.query({"entity": "finding"})

    assert result["kind"] == "kpi"
    assert result["total"] == 2
    assert result["series"] == [{"name": "count", "value": 2}]
    assert result["rows"] == [{"label": "count", "value": 2}]


def test_each_filter_op_selects_the_expected_findings(world: _World):
    world.finding(severity=Severity.CRITICAL, status=FindingStatus.OPEN)
    world.finding(severity=Severity.HIGH, status=FindingStatus.OPEN)
    world.finding(severity=Severity.LOW, status=FindingStatus.RESOLVED)

    assert _total(world, {"field": "status", "op": "eq", "value": "open"}) == 2
    assert _total(world, {"field": "status", "op": "neq", "value": "open"}) == 1
    assert _total(world, {"field": "severity", "op": "in", "value": ["critical", "low"]}) == 2
    assert _total(world, {"field": "severity", "op": "not_in", "value": ["critical", "low"]}) == 1
    assert _total(world, {"field": "subject_type", "op": "eq", "value": "identity"}) == 3
    assert _total(world, {"field": "subject_type", "op": "eq", "value": "resource"}) == 0


def test_comparison_ops_on_timestamps(world: _World):
    old = NOW - timedelta(days=40)
    world.finding(first_seen_at=old)
    world.finding(first_seen_at=NOW - timedelta(days=2))
    pivot = NOW - timedelta(days=10)

    assert _total(world, {"field": "first_seen_at", "op": "gt", "value": pivot}) == 1
    assert _total(world, {"field": "first_seen_at", "op": "gte", "value": old}) == 2
    assert _total(world, {"field": "first_seen_at", "op": "lt", "value": pivot}) == 1
    assert _total(world, {"field": "first_seen_at", "op": "lte", "value": old}) == 1
    # ``opened_at`` is an alias for ``first_seen_at``.
    assert _total(world, {"field": "opened_at", "op": "lt", "value": pivot}) == 1
    assert _total(world, {"field": "last_seen_at", "op": "gt", "value": pivot}) == 1


def test_timestamp_comparisons_accept_iso_strings_from_json_specs(world: _World):
    world.finding(first_seen_at=NOW - timedelta(days=40))
    world.finding(first_seen_at=NOW - timedelta(days=2))

    pivot = (NOW - timedelta(days=10)).isoformat()
    assert _total(world, {"field": "first_seen_at", "op": "gt", "value": pivot}) == 1


def test_null_ops_and_assignee_filters(world: _World, db_session: Session):
    me = make_operator(db_session, world.org)
    colleague = make_operator(db_session, world.org)
    world.finding(assignee=me.id)
    world.finding(assignee=colleague.id)
    world.finding()

    mine = world.query(
        {"entity": "finding", "filters": [{"field": "assigned_to_operator_id", "op": "eq", "value": "me"}]},
        viewer_operator_id=me.id,
    )
    assert mine["total"] == 1
    assert _total(world, {"field": "assigned_to_operator_id", "op": "is_null"}) == 1
    assert _total(world, {"field": "assigned_to_operator_id", "op": "not_null"}) == 2
    assert _total(world, {"field": "assigned_to_operator_id", "op": "eq", "value": str(colleague.id)}) == 1


def test_application_type_filter_follows_the_subject_to_its_instance(world: _World):
    okta_instance, okta_identity = world.identity_in(ApplicationType.OKTA)
    _, slack_identity = world.identity_in(ApplicationType.SLACK)
    world.finding(subject_id=okta_identity.id)
    world.finding(subject_id=okta_identity.id)
    world.finding(subject_id=slack_identity.id)
    # A finding on the application instance itself counts for that instance.
    world.finding(subject_type=FindingSubjectType.APPLICATION, subject_id=okta_instance.id)

    assert _total(world, {"field": "application_type", "value": "okta"}) == 3
    assert _total(world, {"field": "application_type", "value": "slack"}) == 1
    # A known type with no instances in the org matches nothing rather than everything.
    assert _total(world, {"field": "application_type", "value": "github"}) == 0
    result = world.query(
        {"entity": "finding", "filters": [{"field": "application_instance_id", "value": str(okta_instance.id)}]}
    )
    assert result["total"] == 3
    assert result["drilldown"] == {"application_instance_id": str(okta_instance.id)}


def test_group_by_defaults_to_count_descending(world: _World):
    for _ in range(3):
        world.finding(severity=Severity.HIGH)
    world.finding(severity=Severity.LOW)
    world.finding(severity=Severity.CRITICAL, status=FindingStatus.RESOLVED)
    world.finding(severity=Severity.CRITICAL, status=FindingStatus.RESOLVED)

    result = world.query({"entity": "finding", "group_by": ["severity"]})

    assert result["kind"] == "aggregate"
    assert result["group_by"] == ["severity"]
    assert result["series"] == [
        {"name": "high", "value": 3},
        {"name": "critical", "value": 2},
        {"name": "low", "value": 1},
    ]
    assert result["rows"][0] == {"label": "high", "value": 3, "severity": "high"}
    assert result["total"] == 6


def test_group_by_two_fields_joins_labels(world: _World):
    world.finding(severity=Severity.HIGH, status=FindingStatus.OPEN)
    world.finding(severity=Severity.HIGH, status=FindingStatus.RESOLVED)
    world.finding(severity=Severity.HIGH, status=FindingStatus.RESOLVED)

    result = world.query({"entity": "finding", "group_by": ["severity", "status"]})

    assert [(r["label"], r["value"]) for r in result["rows"]] == [("high / resolved", 2), ("high / open", 1)]
    assert result["rows"][0]["status"] == "resolved"


def test_order_by_count_ascending_and_by_group_field(world: _World):
    for _ in range(3):
        world.finding(subject_type=FindingSubjectType.RESOURCE)
    world.finding(subject_type=FindingSubjectType.IDENTITY)
    world.finding(subject_type=FindingSubjectType.SETTING)
    world.finding(subject_type=FindingSubjectType.SETTING)

    by_count = world.query(
        {"entity": "finding", "group_by": ["subject_type"], "order_by": [{"field": "count", "dir": "asc"}]}
    )
    assert [r["value"] for r in by_count["rows"]] == [1, 2, 3]

    by_label_desc = world.query(
        {"entity": "finding", "group_by": ["subject_type"], "order_by": [{"field": "subject_type", "dir": "desc"}]}
    )
    by_label_asc = world.query(
        {"entity": "finding", "group_by": ["subject_type"], "order_by": [{"field": "subject_type", "dir": "asc"}]}
    )
    assert [r["label"] for r in by_label_desc["rows"]] == list(reversed([r["label"] for r in by_label_asc["rows"]]))


def test_group_limit_keeps_the_largest_groups(world: _World):
    for count, severity in ((4, Severity.CRITICAL), (3, Severity.HIGH), (2, Severity.MEDIUM), (1, Severity.LOW)):
        for _ in range(count):
            world.finding(severity=severity)

    result = world.query({"entity": "finding", "group_by": ["severity"], "limit": 2})

    assert [r["label"] for r in result["rows"]] == ["critical", "high"]
    assert result["total"] == 7


def test_time_range_last_since_and_until(world: _World):
    world.finding(first_seen_at=NOW - timedelta(days=90))
    world.finding(first_seen_at=NOW - timedelta(days=20))
    world.finding(first_seen_at=NOW - timedelta(days=1))

    def total(time_range: dict[str, Any]) -> int:
        return world.query({"entity": "finding", "time_range": time_range})["total"]

    assert total({"last": "7d"}) == 1
    assert total({"last": "30d"}) == 2
    assert total({"last": "72h"}) == 1
    assert total({"field": "opened_at", "last": "30d"}) == 2
    assert total({"field": "last_seen_at", "since": (NOW - timedelta(days=30)).isoformat()}) == 2
    assert total({"until": (NOW - timedelta(days=10)).isoformat()}) == 2
    assert total({"since": (NOW - timedelta(days=30)).isoformat(), "until": (NOW - timedelta(days=10)).isoformat()}) == 1


def test_drilldown_mirrors_status_and_severity_filters(world: _World):
    eq = world.query(
        {
            "entity": "finding",
            "filters": [{"field": "status", "value": "open"}, {"field": "severity", "value": "high"}],
        }
    )
    assert eq["drilldown"] == {"status": "open", "severity": "high"}

    many = world.query({"entity": "finding", "filters": [{"field": "severity", "op": "in", "value": ["high", "low"]}]})
    assert many["drilldown"] == {"severity": "high,low"}


def _connector(world: _World, *, mode: SyncMode, runs: list[tuple[ConnectorRunStatus, datetime]]) -> None:
    instance = make_connector_instance(world.session, world.org, sync_mode=mode)
    for status, at in runs:
        world.session.add(
            ConnectorRun(
                id=uuid.uuid4(),
                org_id=world.org.id,
                connector_instance_id=instance.id,
                status=status,
                started_at=at,
                finished_at=at,
                triggered_by=ConnectorRunTrigger.MANUAL,
            )
        )
    world.session.flush()


def test_connector_health_counts_and_filters(world: _World, db_session: Session):
    recent = NOW - timedelta(hours=1)
    _connector(world, mode=SyncMode.LIVE, runs=[(ConnectorRunStatus.SUCCESS, recent)])
    _connector(world, mode=SyncMode.LIVE, runs=[(ConnectorRunStatus.SUCCESS, recent)])
    # The latest run decides health even though an older one succeeded.
    _connector(
        world,
        mode=SyncMode.FIXTURES,
        runs=[(ConnectorRunStatus.SUCCESS, NOW - timedelta(days=3)), (ConnectorRunStatus.FAILED, recent)],
    )
    _connector(world, mode=SyncMode.FIXTURES, runs=[])
    _connector(_World(db_session), mode=SyncMode.LIVE, runs=[])  # another org

    assert world.query({"entity": "connector"})["total"] == 4

    by_health = world.query({"entity": "connector", "group_by": ["health"]})
    assert by_health["kind"] == "aggregate"
    assert by_health["series"][0] == {"name": "healthy", "value": 2}
    assert {r["health"]: r["value"] for r in by_health["rows"]} == {"healthy": 2, "failed": 1, "never": 1}

    by_mode = world.query({"entity": "connector", "group_by": ["sync_mode"], "limit": 1})
    assert len(by_mode["rows"]) == 1

    def total(*filters: dict[str, Any]) -> int:
        return world.query({"entity": "connector", "filters": list(filters)})["total"]

    assert total({"field": "health", "op": "eq", "value": "healthy"}) == 2
    assert total({"field": "health", "op": "neq", "value": "healthy"}) == 2
    assert total({"field": "health", "op": "in", "value": ["failed", "never"]}) == 2
    assert total({"field": "sync_mode", "op": "not_in", "value": ["live"]}) == 2
    assert total({"field": "sync_mode", "value": "live"}, {"field": "health", "value": "healthy"}) == 2


def test_connector_list_ops_require_a_list(world: _World):
    _connector(world, mode=SyncMode.LIVE, runs=[])
    with pytest.raises(ValueError, match="in requires a list value"):
        world.query({"entity": "connector", "filters": [{"field": "health", "op": "in", "value": "never"}]})


def test_connector_kpi_with_no_connectors_is_zero(world: _World):
    assert world.query({"entity": "connector"})["total"] == 0


def test_posture_trend_returns_a_daily_series_within_the_window(world: _World, db_session: Session):
    today = date.today()
    for offset, severities, attention in ((100, {"high": 9}, 9), (10, {"high": 2, "low": 1}, 1), (2, {}, 0)):
        db_session.add(
            PostureTrendSnapshot(
                id=uuid.uuid4(),
                org_id=world.org.id,
                snapshot_date=today - timedelta(days=offset),
                open_by_severity=severities,
                factor_counts={},
                attention_count=attention,
            )
        )
    db_session.flush()

    default = world.query({"entity": "posture_trend"})
    assert default["kind"] == "timeseries"
    assert default["total"] == 2
    first = default["series"][0]
    assert first["date"] == (today - timedelta(days=10)).isoformat()
    assert first["open_total"] == 3
    assert first["sev_high"] == 2
    assert first["sev_low"] == 1
    assert first["attention_count"] == 1

    assert world.query({"entity": "posture_trend", "time_range": {"last": "5d"}})["total"] == 1
    assert world.query({"entity": "posture_trend", "time_range": {"last": "365d"}})["total"] == 3
    # Windows are capped at a year and floored at one day.
    assert world.query({"entity": "posture_trend", "time_range": {"last": "9999d"}})["total"] == 3
    assert world.query({"entity": "posture_trend", "time_range": {"last": "1h"}})["total"] == 0
