# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Shared world for the finding lifecycle tests: one org, one connector, a
webhook endpoint subscribed to finding events, and helpers to build
identities, activity, custom policies and to count what was sent."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from kestrel.db.models.activity_event import ActivityEvent
from kestrel.db.models.audit import AuditLog
from kestrel.db.models.connector import ConnectorRun, ConnectorRunStatus, ConnectorRunTrigger
from kestrel.db.models.finding import Finding, FindingStatus
from kestrel.db.models.identity import Identity, IdentityType
from kestrel.db.models.policy import Policy, PolicyVersion
from kestrel.db.models.webhook import FINDING_OPENED, FINDING_RESOLVED, WebhookDelivery
from kestrel.findings.pipeline import evaluate_all_enabled_policies
from kestrel.policies.authoring import create_custom_policy
from kestrel.testing import make_application_instance, make_connector_instance, make_organization
from kestrel.webhooks.authoring import create_endpoint
from sqlalchemy import func, select
from sqlalchemy.orm import Session

ALWAYS_MATCH = """
POLICY_ID = "{slug}"
TITLE = "Always matches"
SEVERITY = "high"
RESOURCE_TYPE = "identity"
DESCRIPTION = "{description}"


def policy(resource):
    return False
"""

EVENT_POLICY = """
POLICY_ID = "{slug}"
TITLE = "Any activity"
SEVERITY = "low"
RESOURCE_TYPE = "event"


def policy(resource):
    return False
"""


class FindingWorld:
    def __init__(self, session: Session) -> None:
        self.session = session
        self.org = make_organization(session)
        self.app_instance = make_application_instance(session, self.org)
        self.connector_instance = make_connector_instance(session, self.org, application_instance=self.app_instance)
        session.flush()
        self.run = self.new_run()
        self.endpoint, _ = create_endpoint(
            session,
            org_id=self.org.id,
            name="lifecycle",
            url="https://93.184.216.34/hook",
            events=[FINDING_OPENED, FINDING_RESOLVED],
        )
        session.flush()

    def new_run(self, *, incremental: bool = False) -> ConnectorRun:
        run = ConnectorRun(
            id=uuid.uuid4(),
            org_id=self.org.id,
            connector_instance_id=self.connector_instance.id,
            status=ConnectorRunStatus.SUCCESS,
            started_at=datetime.now(UTC),
            triggered_by=ConnectorRunTrigger.MANUAL,
            is_incremental=incremental,
        )
        self.session.add(run)
        self.session.flush()
        return run

    def identity(self) -> Identity:
        row = Identity(
            id=uuid.uuid4(),
            org_id=self.org.id,
            application_instance_id=self.app_instance.id,
            provider_object_id=f"identity-{uuid.uuid4().hex[:8]}",
            identity_type=IdentityType.USER,
            email=f"{uuid.uuid4().hex[:8]}@example.test",
            display_name="Test Identity",
            source_connector_run_id=self.run.id,
            raw_source={},
        )
        self.session.add(row)
        self.session.flush()
        return row

    def activity_event(self, run: ConnectorRun) -> ActivityEvent:
        now = datetime.now(UTC)
        row = ActivityEvent(
            id=uuid.uuid4(),
            org_id=self.org.id,
            application_instance_id=self.app_instance.id,
            provider_object_id=f"evt-{uuid.uuid4().hex[:8]}",
            source_connector_run_id=run.id,
            raw_source={},
            first_seen_at=now,
            last_seen_at=now,
            action="privilege.grant",
            action_category="privilege",
            occurred_at=now,
            summary="granted",
            attributes={},
        )
        self.session.add(row)
        self.session.flush()
        return row

    def policy(self, *, source: str = ALWAYS_MATCH, description: str = "v1") -> Policy:
        slug = f"lifecycle-{uuid.uuid4().hex[:8]}"
        policy = create_custom_policy(
            self.session, org_id=self.org.id, source_text=source.format(slug=slug, description=description)
        )
        self.session.flush()
        return policy

    def evaluate(self) -> None:
        evaluate_all_enabled_policies(self.session, self.org.id)
        self.session.flush()

    def findings(self, policy: Policy, *, unresolved_only: bool = True) -> list[Finding]:
        self.session.flush()
        stmt = (
            select(Finding)
            .join(PolicyVersion, PolicyVersion.id == Finding.policy_version_id)
            .where(Finding.org_id == self.org.id, PolicyVersion.policy_id == policy.id)
        )
        if unresolved_only:
            stmt = stmt.where(Finding.status != FindingStatus.RESOLVED)
        return list(self.session.scalars(stmt).all())

    def deliveries(self, event_type: str) -> int:
        self.session.flush()
        return (
            self.session.scalar(
                select(func.count())
                .select_from(WebhookDelivery)
                .where(WebhookDelivery.org_id == self.org.id, WebhookDelivery.event_type == event_type)
            )
            or 0
        )

    def audit(self, finding: Finding, action: str) -> list[AuditLog]:
        self.session.flush()
        return list(
            self.session.scalars(select(AuditLog).where(AuditLog.target_id == finding.id, AuditLog.action == action)).all()
        )
