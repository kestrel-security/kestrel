# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Shared row-building helpers for the API test tier (`test_api_*.py`).

Not a test file itself -- no function here starts with ``test_``, so pytest
collects zero tests from it. It is named to satisfy the qa-api-engineer file
boundary (`tests/integration/test_api_*.py` only): everything else in the
rebuilt suite owns `conftest.py`, `pyproject.toml`, and `tests/unit` /
`tests/system` / the non-API integration tests, so a helper module has to
live inside the glob this agent is allowed to touch.

Layered on top of `kestrel.testing` (org / operator / application /
connector-instance factories, `api_client`). Anything that already has a
service-layer "authoring" function -- webhook endpoints, ticket
integrations, custom policies, dashboards -- is built through that function
rather than hand-inserted, so tests exercise the same construction path
production code uses. Findings have no such shortcut: a Finding only exists
after a policy match is reconciled, so `make_finding` builds one identity row
plus an always-non-compliant custom policy and evaluates it for real (not a
connector sync, per docs/testing.md rule 1).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from kestrel.db.models.application import ApplicationInstance
from kestrel.db.models.connector import ConnectorInstance, ConnectorRun, ConnectorRunStatus, ConnectorRunTrigger
from kestrel.db.models.finding import Finding
from kestrel.db.models.identity import Identity, IdentityType
from kestrel.db.models.org import Organization
from kestrel.db.models.policy import Policy, PolicyVersion
from kestrel.db.models.ticket import TicketIntegration
from kestrel.db.models.webhook import FINDING_OPENED, WebhookEndpoint
from kestrel.findings.pipeline import evaluate_policy_version
from kestrel.policies.authoring import create_custom_policy
from kestrel.testing import make_application_instance, make_connector_instance
from kestrel.ticketing.authoring import create_integration
from kestrel.webhooks.authoring import create_endpoint
from sqlalchemy import select
from sqlalchemy.orm import Session


def _suffix() -> str:
    return uuid.uuid4().hex[:8]


class FakeTaskQueue:
    """A `TaskQueue` (see `kestrel_api.tasks_client`) that records enqueued
    work instead of touching a broker. Pass to `api_client(..., task_queue=...)`."""

    def __init__(self) -> None:
        self.connector_syncs: list[dict] = []
        self.webhook_deliveries: list[str] = []

    def enqueue_connector_sync(self, *, connector_instance_id: str, connector_name: str, config: dict) -> str:
        task_id = str(uuid.uuid4())
        self.connector_syncs.append(
            {
                "connector_instance_id": connector_instance_id,
                "connector_name": connector_name,
                "config": config,
                "task_id": task_id,
            }
        )
        return task_id

    def enqueue_webhook_deliveries(self, delivery_ids: list[str]) -> list[str]:
        self.webhook_deliveries.extend(delivery_ids)
        return [str(uuid.uuid4()) for _ in delivery_ids]


def make_connector_run(
    session: Session,
    connector_instance: ConnectorInstance,
    *,
    status: ConnectorRunStatus = ConnectorRunStatus.SUCCESS,
) -> ConnectorRun:
    run = ConnectorRun(
        id=uuid.uuid4(),
        org_id=connector_instance.org_id,
        connector_instance_id=connector_instance.id,
        status=status,
        started_at=datetime.now(UTC),
        finished_at=datetime.now(UTC),
        object_counts={},
        triggered_by=ConnectorRunTrigger.MANUAL,
    )
    session.add(run)
    session.flush()
    return run


def make_identity(
    session: Session,
    org: Organization,
    *,
    application_instance: ApplicationInstance | None = None,
    connector_instance: ConnectorInstance | None = None,
    email: str | None = None,
    display_name: str = "Test Identity",
    mfa_enabled: bool | None = False,
    is_disabled: bool = False,
    is_external: bool = False,
) -> Identity:
    """A normalized Identity row with real provenance (a connector instance +
    connector run), never through a connector sync.

    Pass a shared `connector_instance` (and, implicitly, its
    `application_instance`) when seeding many identities in one test --
    otherwise each call provisions its own connector instance, which is
    correct but needlessly expensive for e.g. pagination fixtures.
    """
    if connector_instance is None:
        if application_instance is None:
            application_instance = make_application_instance(session, org)
        connector_instance = make_connector_instance(session, org, application_instance=application_instance)
    application_instance_id = connector_instance.application_instance_id
    run = make_connector_run(session, connector_instance)
    identity = Identity(
        id=uuid.uuid4(),
        org_id=org.id,
        application_instance_id=application_instance_id,
        provider_object_id=f"user-{_suffix()}",
        identity_type=IdentityType.USER,
        email=email or f"identity-{_suffix()}@example.com",
        display_name=display_name,
        is_disabled=is_disabled,
        mfa_enabled=mfa_enabled,
        is_external=is_external,
        source_connector_run_id=run.id,
        raw_source={},
    )
    session.add(identity)
    session.flush()
    return identity


_ALWAYS_MATCH_POLICY = """\
POLICY_ID = "{slug}"
TITLE = "{title}"
SEVERITY = "{severity}"
RESOURCE_TYPE = "identity"
DESCRIPTION = "Always-matching test policy."
REMEDIATION = "n/a"

def policy(resource):
    return False
"""


def make_policy(
    session: Session,
    org: Organization,
    *,
    created_by: str = "test-harness@example.com",
    slug: str | None = None,
    severity: str = "medium",
) -> Policy:
    """A custom policy whose `policy()` always returns False (non-compliant),
    so evaluating it against any identity row in the org always matches.

    `severity` is what the findings it opens inherit -- pass it when a test
    needs a mix, as the severity-ranked findings ordering does."""
    ident = slug or f"api-test-policy-{_suffix()}"
    source = _ALWAYS_MATCH_POLICY.format(slug=ident, title=f"Test policy {ident}", severity=severity)
    return create_custom_policy(session, org_id=org.id, source_text=source, created_by=created_by)


def make_finding(
    session: Session,
    org: Organization,
    *,
    application_instance: ApplicationInstance | None = None,
    identity: Identity | None = None,
    policy: Policy | None = None,
) -> Finding:
    """A real Finding produced by evaluating an always-matching custom policy
    against one factory-built identity."""
    if identity is None:
        identity = make_identity(session, org, application_instance=application_instance)
    if policy is None:
        policy = make_policy(session, org)
    assert policy.current_version_id is not None
    version = session.get(PolicyVersion, policy.current_version_id)
    assert version is not None
    evaluate_policy_version(session, version, org.id)
    return session.scalars(select(Finding).where(Finding.org_id == org.id, Finding.subject_id == identity.id)).one()


def make_findings_batch(
    session: Session,
    org: Organization,
    count: int,
    *,
    application_instance: ApplicationInstance | None = None,
    severity: str = "medium",
) -> list[Finding]:
    """`count` findings sharing one `PolicyEvaluation` batch, and therefore
    the exact same `last_seen_at` -- `_reconcile_findings`
    (kestrel/findings/pipeline.py) stamps every finding it creates in one
    call with a single `now = datetime.now(UTC)`. That is what makes this
    the tool for the pagination contract's "stable ordering with duplicate
    sort keys" case: identities.py/audit.py get duplicate timestamps for
    free from one savepoint transaction sharing Postgres `now()`, but
    Finding.last_seen_at is assigned in application code, so findings need
    to be produced by one shared evaluation on purpose."""
    if application_instance is None:
        application_instance = make_application_instance(session, org)
    connector_instance = make_connector_instance(session, org, application_instance=application_instance)
    identities = [make_identity(session, org, connector_instance=connector_instance) for _ in range(count)]
    policy = make_policy(session, org, severity=severity)
    assert policy.current_version_id is not None
    version = session.get(PolicyVersion, policy.current_version_id)
    assert version is not None
    evaluate_policy_version(session, version, org.id)
    subject_ids = {identity.id for identity in identities}
    rows = session.scalars(select(Finding).where(Finding.org_id == org.id)).all()
    matched = [f for f in rows if f.subject_id in subject_ids]
    assert len(matched) == count
    return matched


def make_webhook(
    session: Session,
    org: Organization,
    *,
    name: str | None = None,
    url: str = "https://93.184.216.34/kestrel-webhook",
    events: list[str] | None = None,
    description: str | None = None,
) -> tuple[WebhookEndpoint, str]:
    """Returns `(endpoint, plaintext_signing_secret)` -- the secret is only
    ever available at creation, exactly like the real create-endpoint flow."""
    endpoint, secret = create_endpoint(
        session,
        org_id=org.id,
        name=name or f"Test webhook {_suffix()}",
        url=url,
        events=events or [FINDING_OPENED],
        description=description,
    )
    return endpoint, secret


def make_ticket_integration(
    session: Session,
    org: Organization,
    *,
    name: str | None = None,
    provider: str = "github_issues",
    api_token: str | None = None,
    config: dict | None = None,
    description: str | None = None,
) -> TicketIntegration:
    return create_integration(
        session,
        org_id=org.id,
        name=name or f"Test integration {_suffix()}",
        provider=provider,
        api_token=api_token or f"test-token-{_suffix()}-0123456789",
        config=config if config is not None else {"repo": "kestrel-testing/example-repo"},
        description=description,
    )
