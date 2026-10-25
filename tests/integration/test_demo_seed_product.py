# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Tier 2 -- the operator-side seeder fills what connectors cannot.

Every table asserted here was empty after a sync-only demo, which left a dozen
working features rendering as empty states. The status/assignment spread matters
as much as the row counts: a page of 250 findings that are all `open` and all
unassigned makes four filter chips and two dashboard widgets look broken.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from kestrel.dashboard.presets import BOARD_TEMPLATES
from kestrel.db.models.audit import AuditLog
from kestrel.db.models.connector import ConnectorRun, ConnectorRunStatus, ConnectorRunTrigger
from kestrel.db.models.dashboard import Dashboard, DashboardWidget
from kestrel.db.models.finding import Exception_, Finding, FindingStatus, FindingSubjectType
from kestrel.db.models.finding_note import FindingNote
from kestrel.db.models.finding_preset import FindingFilterPreset
from kestrel.db.models.finding_watcher import FindingWatcher
from kestrel.db.models.operator import Operator, OperatorRole
from kestrel.db.models.policy import (
    Policy,
    PolicyEvaluation,
    PolicyEvaluationStatus,
    PolicySource,
    PolicyVersion,
    Severity,
)
from kestrel.db.models.posture_trend import PostureTrendSnapshot
from kestrel.db.models.webhook import WebhookEndpoint
from kestrel.demo import DEMO_INSTANCE_MARKER
from kestrel.demo.seed_product import TREND_DAYS, seed_product_data
from kestrel.findings.presets import normalize_filters
from kestrel.testing import make_application_instance, make_connector_instance, make_operator, make_organization
from sqlalchemy import func, select, update
from sqlalchemy.orm import Session


@pytest.fixture
def seeded(db_session: Session):
    """An org with enough findings for the seeder to have something to triage."""
    org = make_organization(db_session)
    make_operator(db_session, org, role=OperatorRole.ADMIN)
    now = datetime.now(UTC)

    policy = Policy(
        id=uuid.uuid4(),
        org_id=org.id,
        slug="demo-seed-policy",
        title="Demo seed policy",
        source=PolicySource.CUSTOM,
    )
    db_session.add(policy)
    db_session.flush()
    version = PolicyVersion(
        id=uuid.uuid4(),
        policy_id=policy.id,
        version=1,
        source_text="def policy(resource):\n    return True\n",
        severity=Severity.HIGH,
    )
    db_session.add(version)
    db_session.flush()
    evaluation = PolicyEvaluation(
        id=uuid.uuid4(),
        org_id=org.id,
        policy_version_id=version.id,
        status=PolicyEvaluationStatus.SUCCESS,
        matched_object_count=60,
    )
    db_session.add(evaluation)
    db_session.flush()

    severities = [Severity.CRITICAL, Severity.HIGH, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
    for index in range(60):
        db_session.add(
            Finding(
                id=uuid.uuid4(),
                org_id=org.id,
                policy_version_id=version.id,
                policy_evaluation_id=evaluation.id,
                title=f"Demo finding {index}",
                severity=severities[index % len(severities)],
                status=FindingStatus.OPEN,
                subject_type=FindingSubjectType.IDENTITY,
                subject_id=uuid.uuid4(),
                first_seen_at=now - timedelta(days=index),
                last_seen_at=now,
            )
        )
    db_session.flush()
    result = seed_product_data(db_session, org, now=now)
    db_session.flush()
    return db_session, org, result


def _count(session: Session, model, *criteria) -> int:
    return session.scalar(select(func.count()).select_from(model).where(*criteria)) or 0


def test_a_team_of_operators_exists_across_every_role(seeded) -> None:
    session, org, _ = seeded
    operators = list(session.scalars(select(Operator).where(Operator.org_id == org.id)).all())
    roles = {op.role for op in operators}
    assert len(operators) >= 5
    assert {OperatorRole.ADMIN, OperatorRole.ANALYST, OperatorRole.READ_ONLY} <= roles
    # An inactive operator, so the deactivate path has something to show.
    assert any(not op.is_active for op in operators)


def test_findings_span_every_status_rather_than_all_being_open(seeded) -> None:
    session, org, _ = seeded
    statuses = {row[0] for row in session.execute(select(Finding.status).where(Finding.org_id == org.id).distinct()).all()}
    assert FindingStatus.OPEN in statuses
    assert len(statuses) >= 4, f"only {statuses} present; status filters would look broken"


def test_some_findings_are_assigned_and_some_are_not(seeded) -> None:
    # "My open findings" and "Unassigned" are separate widgets; both need rows.
    session, org, _ = seeded
    assigned = _count(session, Finding, Finding.org_id == org.id, Finding.assigned_to_operator_id.isnot(None))
    unassigned = _count(session, Finding, Finding.org_id == org.id, Finding.assigned_to_operator_id.is_(None))
    assert assigned > 0
    assert unassigned > 0


def test_muted_findings_include_one_expiring_soon(seeded) -> None:
    session, org, _ = seeded
    muted = list(
        session.scalars(select(Finding).where(Finding.org_id == org.id, Finding.status == FindingStatus.MUTED)).all()
    )
    assert muted
    assert all(f.mute_reason for f in muted)
    soon = datetime.now(UTC) + timedelta(days=7)
    assert any(f.muted_until is not None and f.muted_until <= soon for f in muted), (
        "the mute-expiry queue needs at least one finding expiring inside a week"
    )


def test_notes_watchers_and_exceptions_are_populated(seeded) -> None:
    session, org, _ = seeded
    assert _count(session, FindingNote, FindingNote.org_id == org.id) > 0
    assert _count(session, FindingWatcher, FindingWatcher.org_id == org.id) > 0
    assert _count(session, Exception_, Exception_.org_id == org.id) > 0


def test_exceptions_cover_both_expiring_and_permanent(seeded) -> None:
    session, org, _ = seeded
    exceptions = list(session.scalars(select(Exception_).where(Exception_.org_id == org.id)).all())
    assert any(e.expires_at is None for e in exceptions)
    assert any(e.expires_at is not None for e in exceptions)


def test_the_posture_trend_has_a_full_window_that_actually_moves(seeded) -> None:
    # A single point renders as a dot; a flat line renders as a bug report.
    session, org, _ = seeded
    snapshots = list(
        session.scalars(
            select(PostureTrendSnapshot)
            .where(PostureTrendSnapshot.org_id == org.id)
            .order_by(PostureTrendSnapshot.snapshot_date)
        ).all()
    )
    assert len(snapshots) >= TREND_DAYS
    assert len({s.snapshot_date for s in snapshots}) == len(snapshots)
    attention = {s.attention_count for s in snapshots}
    assert len(attention) > 1, "trend line is flat"


def test_audit_history_is_spread_over_time_and_targets_findings(seeded) -> None:
    session, org, _ = seeded
    rows = list(session.scalars(select(AuditLog).where(AuditLog.org_id == org.id)).all())
    assert len(rows) >= 100
    assert len({r.created_at for r in rows}) > 1, "all audit rows share one timestamp"
    # The finding-detail activity timeline reads rows targeting the finding.
    assert any(r.target_type == "finding" and r.target_id is not None for r in rows)
    assert len({r.action for r in rows}) >= 5


def test_seeding_reports_what_it_skipped_rather_than_failing(seeded) -> None:
    _, _, result = seeded
    assert result.total > 0
    # Skips are recorded, never raised -- a missing master key must not take the
    # whole demo down.
    assert isinstance(result.skipped, list)


def test_seeding_twice_does_not_duplicate_operators(seeded) -> None:
    session, org, _ = seeded
    before = _count(session, Operator, Operator.org_id == org.id)
    seed_product_data(session, org)
    session.flush()
    assert _count(session, Operator, Operator.org_id == org.id) == before


def test_more_than_one_dashboard_exists(seeded) -> None:
    """`BOARD_TEMPLATES` shipped three boards that nothing instantiated, so a
    seeded demo had exactly one dashboard and the multi-board nav was dead."""
    session, org, _ = seeded
    boards = session.scalars(select(Dashboard).where(Dashboard.org_id == org.id)).all()
    assert len(boards) >= len(BOARD_TEMPLATES)
    slugs = {b.slug for b in boards}
    assert {t["slug"] for t in BOARD_TEMPLATES} <= slugs


def test_seeded_boards_actually_carry_widgets(seeded) -> None:
    """A board with no widgets is a worse empty state than no board."""
    session, org, _ = seeded
    for template in BOARD_TEMPLATES:
        board = session.scalars(
            select(Dashboard).where(Dashboard.org_id == org.id, Dashboard.slug == template["slug"])
        ).one()
        widgets = _count(session, DashboardWidget, DashboardWidget.dashboard_id == board.id)
        assert widgets > 0, f"{template['slug']} board seeded with no widgets"


def test_saved_finding_searches_exist(seeded) -> None:
    session, org, _ = seeded
    presets = session.scalars(select(FindingFilterPreset).where(FindingFilterPreset.org_id == org.id)).all()
    assert len(presets) >= 4
    # Stored filters are replayed as listing query params, so they must round-trip.
    for preset in presets:
        assert normalize_filters(preset.filters) == preset.filters


def test_seeding_twice_does_not_duplicate_dashboards(seeded) -> None:
    session, org, _ = seeded
    before = _count(session, Dashboard, Dashboard.org_id == org.id)
    seed_product_data(session, org)
    session.flush()
    assert _count(session, Dashboard, Dashboard.org_id == org.id) == before


def test_connector_history_backfills_runs_and_a_schedule(db_session: Session) -> None:
    """`demo up` syncs each tenant once, so Integrations showed a single run and
    "manual" for every connector -- the run-history table, the health centre's
    degraded state, and the schedule column all unexercised."""
    org = make_organization(db_session)
    make_operator(db_session, org, role=OperatorRole.ADMIN)
    app_instance = make_application_instance(db_session, org, display_name=f"Acme GitHub {DEMO_INSTANCE_MARKER}")
    instance = make_connector_instance(db_session, org, application_instance=app_instance)

    seed_product_data(db_session, org)
    db_session.flush()

    runs = db_session.scalars(select(ConnectorRun).where(ConnectorRun.connector_instance_id == instance.id)).all()
    assert len(runs) >= 14
    assert instance.schedule_cron, "a demo instance with no schedule shows 'manual' in the fleet view"
    # A fleet where nothing ever degraded misrepresents operating this.
    assert {r.status for r in runs} & {ConnectorRunStatus.PARTIAL_FAILURE, ConnectorRunStatus.FAILED}
    # History only: backfilled runs must not carry object provenance that would
    # disturb the Changes timeline.
    assert all(r.triggered_by is ConnectorRunTrigger.SCHEDULE for r in runs)


def test_connector_history_does_not_stack_on_a_second_run(db_session: Session) -> None:
    org = make_organization(db_session)
    make_operator(db_session, org, role=OperatorRole.ADMIN)
    app_instance = make_application_instance(db_session, org, display_name=f"Acme Okta {DEMO_INSTANCE_MARKER}")
    instance = make_connector_instance(db_session, org, application_instance=app_instance)

    seed_product_data(db_session, org)
    db_session.flush()
    before = _count(db_session, ConnectorRun, ConnectorRun.connector_instance_id == instance.id)

    seed_product_data(db_session, org)
    db_session.flush()

    assert _count(db_session, ConnectorRun, ConnectorRun.connector_instance_id == instance.id) == before


def test_connector_history_says_so_when_there_is_nothing_to_backfill(db_session: Session) -> None:
    """No demo instances is a normal state (a bare org), not a failure."""
    org = make_organization(db_session)
    make_operator(db_session, org, role=OperatorRole.ADMIN)

    result = seed_product_data(db_session, org)

    assert any("connector run history" in note for note in result.skipped)


def test_demo_webhook_endpoints_are_disabled_even_when_seeded_earlier(seeded) -> None:
    # Enabled endpoints turned every later sync and `demo change` into real
    # deliveries queued for example.com, piling up a pending backlog.
    session, org, _ = seeded
    for name in ("SIEM forwarder", "PagerDuty critical", "Audit archive"):
        if session.scalar(select(WebhookEndpoint).where(WebhookEndpoint.org_id == org.id, WebhookEndpoint.name == name)):
            continue
        session.add(
            WebhookEndpoint(
                id=uuid.uuid4(),
                org_id=org.id,
                name=name,
                url="https://example.com/hooks/kestrel",
                events=["finding.opened"],
                secret_ciphertext=b"x",
                secret_nonce=b"x",
                secret_key_version=1,
                is_enabled=True,
            )
        )
    session.execute(update(WebhookEndpoint).where(WebhookEndpoint.org_id == org.id).values(is_enabled=True))
    session.flush()

    seed_product_data(session, org)
    session.flush()

    endpoints = list(session.scalars(select(WebhookEndpoint).where(WebhookEndpoint.org_id == org.id)).all())
    assert endpoints
    for endpoint in endpoints:
        session.refresh(endpoint)
    assert not any(endpoint.is_enabled for endpoint in endpoints)
