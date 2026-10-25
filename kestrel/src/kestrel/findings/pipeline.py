# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Turns Python policy matches into persisted Findings with evidence,
diffing against previously-open Findings so a finding auto-resolves once the
underlying condition is fixed.
"""

from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from kestrel.db.locks import POLICY_EVALUATION, org_advisory_xact_lock
from kestrel.db.models.activity_event import ActivityEvent
from kestrel.db.models.connector import ConnectorRun
from kestrel.db.models.event import Event
from kestrel.db.models.finding import Finding, FindingEvidence, FindingStatus, FindingSubjectType
from kestrel.db.models.policy import Policy, PolicyEvaluation, PolicyEvaluationStatus, PolicySource, PolicyVersion
from kestrel.db.models.webhook import FINDING_OPENED, FINDING_RESOLVED
from kestrel.findings.investigation.status import apply_status_transition
from kestrel.findings.lifecycle import live_policy_exception, survivors_by_subject, unresolved_findings_for_policy
from kestrel.notifications.dispatch import schedule_finding_notifications
from kestrel.observability.metrics import observe_policy_evaluation
from kestrel.observability.tracing import get_tracer
from kestrel.policies.dataload import RESOURCE_TYPE_TO_FROM_TYPE, RowCache
from kestrel.policies.runtime import CompiledPolicy, PolicyCompileError, PolicyEvaluationResult, get_default_runtime
from kestrel.policies.runtime.factory import get_trusted_runtime
from kestrel.webhooks.dispatch import schedule_finding_webhooks

logger = logging.getLogger(__name__)


def evaluate_policy_version(
    session: Session,
    policy_version: PolicyVersion,
    org_id: uuid.UUID,
    connector_run_id: uuid.UUID | None = None,
    webhook_delivery_ids: list[uuid.UUID] | None = None,
    row_cache: RowCache | None = None,
    compiled: CompiledPolicy | None = None,
) -> PolicyEvaluation:
    """Runs one policy version, records a PolicyEvaluation row, and
    reconciles Findings (create new matches, auto-resolve stale ones).

    ``row_cache`` shares one load of each row family across a batch of
    policies; without it each policy loads its own rows, which is what a
    single ad-hoc evaluation wants. ``compiled`` skips a second compile when
    the caller already has one.

    Takes the org's ``POLICY_EVALUATION`` advisory lock before reading
    anything (re-entrant, so a batch that already holds it pays nothing)."""
    org_advisory_xact_lock(session, org_id, POLICY_EVALUATION)
    started_at = datetime.now(UTC)
    monotonic_started = time.monotonic()
    policy = session.get(Policy, policy_version.policy_id)
    trusted = policy is not None and policy.source in (PolicySource.PACK, PolicySource.SYSTEM)
    runtime = get_trusted_runtime() if trusted else get_default_runtime()

    policy_evaluation = PolicyEvaluation(
        id=uuid.uuid4(),
        org_id=org_id,
        policy_version_id=policy_version.id,
        connector_run_id=connector_run_id,
        started_at=started_at,
        status=PolicyEvaluationStatus.SUCCESS,
    )
    session.add(policy_evaluation)
    session.flush()

    tracer = get_tracer("kestrel.policy")
    with tracer.start_as_current_span(
        "kestrel.policy.evaluate",
        attributes={
            "kestrel.policy_version_id": str(policy_version.id),
            "kestrel.policy_evaluation_id": str(policy_evaluation.id),
        },
    ) as span:
        try:
            if compiled is None:
                compiled = runtime.compile(policy_version.source_text)
            rows = None
            if row_cache is not None:
                rows = row_cache.rows(RESOURCE_TYPE_TO_FROM_TYPE[compiled.contract.resource_type])
            result = runtime.evaluate_all(compiled, session, org_id, rows=rows)
        except Exception as exc:  # deliberately broad: policy code can fail any way; recorded as an ERROR evaluation
            logger.warning("policy evaluation %s failed", policy_evaluation.id, exc_info=True)
            policy_evaluation.status = PolicyEvaluationStatus.ERROR
            policy_evaluation.error_message = str(exc)
            policy_evaluation.finished_at = datetime.now(UTC)
            session.flush()
            span.set_attribute("kestrel.policy.status", policy_evaluation.status.value)
            observe_policy_evaluation(
                status=policy_evaluation.status.value,
                duration_seconds=time.monotonic() - monotonic_started,
            )
            return policy_evaluation

        policy_evaluation.matched_object_count = len(result.matches)
        policy_evaluation.finished_at = datetime.now(UTC)

        _reconcile_findings(
            session,
            org_id,
            policy_version,
            policy_evaluation,
            result,
            webhook_delivery_ids=webhook_delivery_ids,
        )

        span.set_attribute("kestrel.policy.status", policy_evaluation.status.value)
        span.set_attribute("kestrel.policy.match_count", policy_evaluation.matched_object_count or 0)
        observe_policy_evaluation(
            status=policy_evaluation.status.value,
            duration_seconds=time.monotonic() - monotonic_started,
            match_count=policy_evaluation.matched_object_count or 0,
        )
        return policy_evaluation


#: Policy ``RESOURCE_TYPE``s whose rows come from provider audit activity
#: rather than inventory. Only these can change after an audit-log poll.
ACTIVITY_RESOURCE_TYPES: frozenset[str] = frozenset({"event"})


@dataclass(frozen=True)
class EvaluationPlan:
    """What a finished sync needs re-evaluated. ``resource_types`` None means
    every enabled policy."""

    evaluate: bool
    resource_types: frozenset[str] | None
    reason: str


def evaluation_plan_for_run(session: Session, run: ConnectorRun) -> EvaluationPlan:
    """Decides how much of the org a finished sync must re-evaluate.

    A full (or degraded) inventory run evaluates everything, as does any run
    while an earlier sync's evaluation is still owed. An incremental
    run -- the audit-log poll every few minutes -- evaluates everything only
    if it changed inventory (it wrote change ``events``); otherwise only
    activity policies can have a different answer, and only if the poll
    stored activity it had not seen before. A poll that brought nothing new
    evaluates nothing, which is most of them.
    """
    if not run.is_incremental:
        return EvaluationPlan(True, None, "full_inventory_run")
    session.flush()
    owed = session.scalar(
        select(ConnectorRun.id)
        .where(
            ConnectorRun.org_id == run.org_id,
            ConnectorRun.evaluation_pending.is_(True),
            ConnectorRun.id != run.id,
        )
        .limit(1)
    )
    if owed is not None:
        # An earlier sync's evaluation never completed; its changes are unevaluated.
        return EvaluationPlan(True, None, "earlier_evaluation_owed")
    changed_inventory = session.scalar(select(Event.id).where(Event.connector_run_id == run.id).limit(1))
    if changed_inventory is not None:
        return EvaluationPlan(True, None, "incremental_run_changed_inventory")
    new_activity = None
    if run.started_at is not None:
        new_activity = session.scalar(
            select(ActivityEvent.id)
            .where(
                ActivityEvent.source_connector_run_id == run.id,
                ActivityEvent.first_seen_at >= run.started_at,
            )
            .limit(1)
        )
    if new_activity is not None:
        return EvaluationPlan(True, ACTIVITY_RESOURCE_TYPES, "incremental_run_new_activity")
    return EvaluationPlan(False, frozenset(), "incremental_run_no_changes")


def evaluate_all_enabled_policies(
    session: Session,
    org_id: uuid.UUID,
    connector_run_id: uuid.UUID | None = None,
    webhook_delivery_ids: list[uuid.UUID] | None = None,
    resource_types: frozenset[str] | None = None,
) -> list[PolicyEvaluation]:
    """Evaluates every enabled PolicyVersion currently installed for the org.

    Skips ``PolicySource.SYSTEM`` versions: their matches are not evaluated
    from source. Toxic-combination system findings are derived from the open
    findings this pass leaves behind, so they are reconciled last.

    ``resource_types`` limits the pass to policies of those ``RESOURCE_TYPE``s
    (``{"event"}`` after an audit-log poll that changed no inventory).

    Serialised per org: the ``POLICY_EVALUATION`` advisory lock is taken
    before any row is read and held until the caller's transaction ends.
    Without it, two syncs evaluating at once each reconcile against rows read
    before the other committed, resolving the other's fresh findings and
    reopening ones it just fixed. Callers that also rebuild identity
    correlation take that lock first (see ``kestrel.db.locks``).
    """
    from kestrel.db.models.policy import PolicySource
    from kestrel.findings.toxic_combo import reconcile_toxic_combination_findings

    org_advisory_xact_lock(session, org_id, POLICY_EVALUATION)
    policy_versions = session.scalars(
        select(PolicyVersion)
        .join(Policy, Policy.id == PolicyVersion.policy_id)
        .where(
            Policy.org_id == org_id,
            Policy.source != PolicySource.SYSTEM,
            PolicyVersion.is_enabled.is_(True),
            Policy.current_version_id == PolicyVersion.id,
        )
    ).all()
    # One load of each row family for the whole pass. A stock install has
    # around a hundred enabled policies over six families; without this each
    # policy re-read the directory it shares with every other policy of its
    # resource type.
    row_cache = RowCache(session, org_id)
    runtime = get_default_runtime()
    evaluations: list[PolicyEvaluation] = []
    for pv in policy_versions:
        compiled: CompiledPolicy | None = None
        if resource_types is not None:
            try:
                compiled = runtime.compile(pv.source_text)
            except PolicyCompileError:
                # The next full pass records it as an ERROR evaluation.
                continue
            if compiled.contract.resource_type not in resource_types:
                continue
        evaluations.append(
            evaluate_policy_version(
                session,
                pv,
                org_id,
                connector_run_id,
                webhook_delivery_ids=webhook_delivery_ids,
                row_cache=row_cache,
                compiled=compiled,
            )
        )
    session.flush()
    evaluations.extend(
        reconcile_toxic_combination_findings(
            session,
            org_id,
            connector_run_id,
            webhook_delivery_ids=webhook_delivery_ids,
        )
    )
    return evaluations


def _reconcile_findings(
    session: Session,
    org_id: uuid.UUID,
    policy_version: PolicyVersion,
    policy_evaluation: PolicyEvaluation,
    result: PolicyEvaluationResult,
    webhook_delivery_ids: list[uuid.UUID] | None = None,
) -> None:
    """Create / refresh / auto-resolve findings for one policy's matches.

    Keyed by ``(policy, subject)`` across every version of the policy, against
    the latest non-resolved finding -- see ``kestrel.findings.lifecycle`` for
    the rules. Triaged findings keep their status; a live policy-scoped
    exception turns new matches (and open findings) into ``exception``.
    """
    now = datetime.now(UTC)
    policy = session.get(Policy, policy_version.policy_id)
    title = policy.title if policy is not None else str(policy_version.policy_id)

    session.flush()
    existing_by_subject = survivors_by_subject(
        session,
        org_id,
        unresolved_findings_for_policy(session, org_id, policy_version.policy_id),
        now=now,
    )
    policy_exception = live_policy_exception(session, org_id, policy_version.policy_id, now=now)

    matched_subjects: set[tuple[str, str]] = set()
    for match in result.matches:
        key = (match.subject_type, str(match.subject_id))
        if key in matched_subjects:
            continue
        matched_subjects.add(key)

        existing = existing_by_subject.get(key)
        if existing is not None:
            existing.last_seen_at = now
            existing.policy_version_id = policy_version.id
            existing.severity = policy_version.severity
            existing.title = title
            if existing.status == FindingStatus.OPEN and policy_exception is not None:
                apply_status_transition(existing, FindingStatus.EXCEPTION, now=now)
            _replace_evidence(session, existing, match.evidence)
            continue

        status = FindingStatus.EXCEPTION if policy_exception is not None else FindingStatus.OPEN
        finding = Finding(
            id=uuid.uuid4(),
            org_id=org_id,
            policy_version_id=policy_version.id,
            policy_evaluation_id=policy_evaluation.id,
            title=title,
            severity=policy_version.severity,
            status=status,
            first_seen_at=now,
            last_seen_at=now,
            subject_type=FindingSubjectType(match.subject_type),
            subject_id=match.subject_id,
        )
        session.add(finding)
        session.flush()
        _replace_evidence(session, finding, match.evidence)
        if status != FindingStatus.OPEN:
            continue
        schedule_finding_webhooks(
            session,
            org_id=org_id,
            event_type=FINDING_OPENED,
            finding=finding,
            delivery_ids=webhook_delivery_ids,
        )
        schedule_finding_notifications(
            session,
            org_id=org_id,
            event_type=FINDING_OPENED,
            finding=finding,
        )

    for key, finding in existing_by_subject.items():
        # Only open findings auto-resolve. A triaged one stays as the operator
        # left it, so the condition recurring lands back on it.
        if key not in matched_subjects and finding.status == FindingStatus.OPEN:
            finding.status = FindingStatus.RESOLVED
            finding.resolved_at = now
            schedule_finding_webhooks(
                session,
                org_id=org_id,
                event_type=FINDING_RESOLVED,
                finding=finding,
                delivery_ids=webhook_delivery_ids,
            )
            schedule_finding_notifications(
                session,
                org_id=org_id,
                event_type=FINDING_RESOLVED,
                finding=finding,
            )


def _replace_evidence(session: Session, finding: Finding, evidence: dict) -> None:
    session.query(FindingEvidence).filter(FindingEvidence.finding_id == finding.id).delete()
    for label, value in evidence.items():
        session.add(FindingEvidence(id=uuid.uuid4(), finding_id=finding.id, label=label, value=value))
