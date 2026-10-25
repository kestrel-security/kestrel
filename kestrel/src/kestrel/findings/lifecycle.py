# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Finding lifecycle rules shared by evaluation, policy authoring and the
expiry sweep.

A finding is identified by ``(policy, subject)``, not by policy *version*:
publishing a new version, rolling back, or re-installing a pack must keep the
same finding (and its assignee, notes, watchers, tickets and exceptions) rather
than opening a second one. The latest non-resolved finding per key is the one
evaluation reconciles against, whatever its status:

- ``open`` findings are refreshed while they match and auto-resolve when they
  stop matching.
- ``muted``, ``suppressed`` and ``exception`` findings are triage decisions.
  While they match, evaluation refreshes ``last_seen_at`` and evidence but
  keeps the status and sends nothing. They are not auto-resolved either, so a
  recurrence lands on the same triaged finding instead of reopening it.

Mutes and dated exceptions end on their own: ``reopen_expired_deferrals``
(run by Celery beat) moves an expired one back to ``open`` and announces it the
same way a manual reopen does.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime

from sqlalchemy import or_, select, update
from sqlalchemy.orm import Session

from kestrel.audit.service import record_audit_event
from kestrel.db.locks import POLICY_EVALUATION, org_advisory_xact_lock
from kestrel.db.models.finding import Exception_, Finding, FindingStatus
from kestrel.db.models.finding_note import FindingNote
from kestrel.db.models.finding_watcher import FindingWatcher
from kestrel.db.models.policy import Policy, PolicyVersion
from kestrel.db.models.ticket import FindingTicket
from kestrel.db.models.webhook import FINDING_OPENED, FINDING_RESOLVED
from kestrel.findings.investigation.status import apply_status_transition
from kestrel.notifications.dispatch import schedule_finding_notifications
from kestrel.webhooks.dispatch import schedule_finding_webhooks

#: Operator triage states that evaluation must never overwrite.
TRIAGED_STATUSES = frozenset({FindingStatus.MUTED, FindingStatus.SUPPRESSED, FindingStatus.EXCEPTION})

#: Audit actions written for status changes Kestrel makes on its own. The
#: finding activity timeline reads them, so the reason is visible on the finding.
AUTO_RESOLVED_ACTION = "finding.auto_resolved"
AUTO_REOPENED_ACTION = "finding.auto_reopened"

REASON_POLICY_DISABLED = "policy_disabled"
REASON_MUTE_EXPIRED = "mute_expired"
REASON_EXCEPTION_EXPIRED = "exception_expired"
REASON_DUPLICATE = "duplicate_merged"

SubjectKey = tuple[str, str]


def _utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def subject_key(finding: Finding) -> SubjectKey:
    return (finding.subject_type.value, str(finding.subject_id))


def _recency(finding: Finding) -> tuple[datetime, str]:
    created = _utc(finding.created_at) or _utc(finding.first_seen_at) or datetime.min.replace(tzinfo=UTC)
    first_seen = _utc(finding.first_seen_at) or created
    return (max(first_seen, created), str(finding.id))


def unresolved_findings_for_policy(session: Session, org_id: uuid.UUID, policy_id: uuid.UUID) -> list[Finding]:
    """Every non-resolved finding of ``policy_id``, across all its versions."""
    return list(
        session.scalars(
            select(Finding)
            .join(PolicyVersion, PolicyVersion.id == Finding.policy_version_id)
            .where(
                Finding.org_id == org_id,
                PolicyVersion.policy_id == policy_id,
                Finding.status != FindingStatus.RESOLVED,
            )
        ).all()
    )


def survivors_by_subject(
    session: Session,
    org_id: uuid.UUID,
    findings: Iterable[Finding],
    *,
    now: datetime | None = None,
) -> dict[SubjectKey, Finding]:
    """The latest non-resolved finding per subject; older duplicates are merged
    into it (see ``merge_duplicate_into``) and resolved.

    Duplicates only exist from before reconciliation was keyed this way: a
    re-published policy version, or a triaged finding shadowed by a fresh open
    one. Folding them together here is what lets an upgraded install converge.
    """
    clock = now or datetime.now(UTC)
    grouped: dict[SubjectKey, list[Finding]] = {}
    for finding in findings:
        grouped.setdefault(subject_key(finding), []).append(finding)

    survivors: dict[SubjectKey, Finding] = {}
    for key, rows in grouped.items():
        rows.sort(key=_recency, reverse=True)
        survivor = rows[0]
        for duplicate in rows[1:]:
            merge_duplicate_into(session, org_id, survivor=survivor, duplicate=duplicate, now=clock)
        survivors[key] = survivor
    return survivors


def merge_duplicate_into(
    session: Session,
    org_id: uuid.UUID,
    *,
    survivor: Finding,
    duplicate: Finding,
    now: datetime,
) -> None:
    """Moves the operator's work from ``duplicate`` onto ``survivor`` and
    resolves the duplicate quietly (it is the same issue, still tracked).

    Notes, tickets and finding-scoped exceptions are re-pointed; watchers are
    re-pointed unless the operator already watches the survivor; the assignee
    carries over when the survivor has none; a triage state (mute, suppress,
    exception) carries over when the survivor is merely open.
    """
    session.execute(update(FindingNote).where(FindingNote.finding_id == duplicate.id).values(finding_id=survivor.id))
    session.execute(update(FindingTicket).where(FindingTicket.finding_id == duplicate.id).values(finding_id=survivor.id))
    session.execute(update(Exception_).where(Exception_.finding_id == duplicate.id).values(finding_id=survivor.id))

    existing_watchers = set(
        session.scalars(select(FindingWatcher.operator_id).where(FindingWatcher.finding_id == survivor.id)).all()
    )
    for watcher in session.scalars(select(FindingWatcher).where(FindingWatcher.finding_id == duplicate.id)).all():
        if watcher.operator_id in existing_watchers:
            session.delete(watcher)
        else:
            watcher.finding_id = survivor.id
            existing_watchers.add(watcher.operator_id)

    if survivor.assigned_to_operator_id is None and duplicate.assigned_to_operator_id is not None:
        survivor.assigned_to_operator_id = duplicate.assigned_to_operator_id

    if survivor.status == FindingStatus.OPEN and duplicate.status in TRIAGED_STATUSES:
        survivor.status = duplicate.status
        survivor.muted_until = duplicate.muted_until
        survivor.mute_reason = duplicate.mute_reason

    _utc_first_seen = _utc(duplicate.first_seen_at)
    if _utc_first_seen is not None and _utc_first_seen < (_utc(survivor.first_seen_at) or _utc_first_seen):
        survivor.first_seen_at = duplicate.first_seen_at

    apply_status_transition(duplicate, FindingStatus.RESOLVED, now=now)
    record_audit_event(
        session,
        org_id=org_id,
        actor_operator_id=None,
        action=AUTO_RESOLVED_ACTION,
        target_type="finding",
        target_id=duplicate.id,
        context={"status": FindingStatus.RESOLVED.value, "reason": REASON_DUPLICATE, "merged_into": str(survivor.id)},
    )
    session.flush()


def live_policy_exception(
    session: Session, org_id: uuid.UUID, policy_id: uuid.UUID, *, now: datetime | None = None
) -> Exception_ | None:
    """A policy-scoped exception (``finding_id`` null, e.g. from GitOps) that
    has not expired. Its matches are accepted risk, not new open findings."""
    clock = now or datetime.now(UTC)
    return session.scalars(
        select(Exception_)
        .where(
            Exception_.org_id == org_id,
            Exception_.policy_id == policy_id,
            Exception_.finding_id.is_(None),
            or_(Exception_.expires_at.is_(None), Exception_.expires_at > clock),
        )
        .limit(1)
    ).first()


def repoint_findings_to_current_version(session: Session, policy: Policy) -> int:
    """After ``current_version_id`` moves (publish, rollback, pack re-install),
    keep every non-resolved finding on the version that now evaluates it, so
    filters by version and the dry-run "existing" view stay accurate.

    Severity follows the version; title follows the policy. Returns the number
    of findings moved.
    """
    # Before touching findings: an evaluation in flight writes them too, and
    # would otherwise deadlock with this or write the old version back.
    org_advisory_xact_lock(session, policy.org_id, POLICY_EVALUATION)
    if policy.current_version_id is None:
        return 0
    version = session.get(PolicyVersion, policy.current_version_id)
    if version is None:
        return 0
    session.flush()
    stale = [
        f
        for f in unresolved_findings_for_policy(session, policy.org_id, policy.id)
        if f.policy_version_id != version.id or f.severity != version.severity or f.title != policy.title
    ]
    for finding in stale:
        finding.policy_version_id = version.id
        finding.severity = version.severity
        finding.title = policy.title
    session.flush()
    return len(stale)


def resolve_findings_for_disabled_policy(
    session: Session,
    policy: Policy,
    *,
    actor_operator_id: uuid.UUID | None = None,
    webhook_delivery_ids: list[uuid.UUID] | None = None,
    now: datetime | None = None,
) -> int:
    """A disabled policy is no longer evaluated, so nothing would ever resolve
    its findings. Resolve every open one now, with an ``finding.auto_resolved``
    audit row (reason ``policy_disabled``) on each so the timeline says why.

    Triaged findings (muted, suppressed, exception) are resolved too: the check
    they defer no longer runs. ``finding.resolved`` webhooks are only scheduled
    when the caller passes ``webhook_delivery_ids`` and so will enqueue them
    after commit; in-app and email notifications always go out.
    """
    clock = now or datetime.now(UTC)
    # An evaluation already in flight could otherwise reopen what this resolves.
    org_advisory_xact_lock(session, policy.org_id, POLICY_EVALUATION)
    session.flush()
    findings = unresolved_findings_for_policy(session, policy.org_id, policy.id)
    for finding in findings:
        apply_status_transition(finding, FindingStatus.RESOLVED, now=clock)
        record_audit_event(
            session,
            org_id=policy.org_id,
            actor_operator_id=actor_operator_id,
            action=AUTO_RESOLVED_ACTION,
            target_type="finding",
            target_id=finding.id,
            context={"status": FindingStatus.RESOLVED.value, "reason": REASON_POLICY_DISABLED, "policy": policy.slug},
        )
        if webhook_delivery_ids is not None:
            schedule_finding_webhooks(
                session,
                org_id=policy.org_id,
                event_type=FINDING_RESOLVED,
                finding=finding,
                delivery_ids=webhook_delivery_ids,
            )
        schedule_finding_notifications(session, org_id=policy.org_id, event_type=FINDING_RESOLVED, finding=finding)
    session.flush()
    return len(findings)


@dataclass
class ReopenResult:
    mutes_reopened: list[uuid.UUID] = field(default_factory=list)
    exceptions_reopened: list[uuid.UUID] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.mutes_reopened) + len(self.exceptions_reopened)


def reopen_expired_deferrals(
    session: Session,
    org_id: uuid.UUID,
    *,
    now: datetime | None = None,
    webhook_delivery_ids: list[uuid.UUID] | None = None,
) -> ReopenResult:
    """Moves findings whose mute or exception has expired back to ``open``.

    - ``muted`` with ``muted_until`` in the past.
    - ``exception`` whose exceptions -- its own, plus policy-scoped ones for its
      policy -- have all expired. A finding put in ``exception`` status with no
      exception row at all (a plain status change) has nothing to expire and
      is left alone, as is any finding still covered by a live exception.

    Each reopen gets an ``finding.auto_reopened`` audit row and the same
    ``finding.opened`` webhook and notifications as a manual reopen. Does not
    commit.
    """
    clock = now or datetime.now(UTC)
    result = ReopenResult()

    muted = session.scalars(
        select(Finding).where(
            Finding.org_id == org_id,
            Finding.status == FindingStatus.MUTED,
            Finding.muted_until.is_not(None),
            Finding.muted_until <= clock,
        )
    ).all()
    for finding in muted:
        expired_at = _utc(finding.muted_until)
        _reopen(
            session,
            org_id,
            finding,
            reason=REASON_MUTE_EXPIRED,
            expired_at=expired_at,
            now=clock,
            webhook_delivery_ids=webhook_delivery_ids,
        )
        result.mutes_reopened.append(finding.id)

    excepted = list(
        session.scalars(select(Finding).where(Finding.org_id == org_id, Finding.status == FindingStatus.EXCEPTION)).all()
    )
    if excepted:
        policy_by_version: dict[uuid.UUID, uuid.UUID] = dict(
            session.execute(
                select(PolicyVersion.id, PolicyVersion.policy_id).where(
                    PolicyVersion.id.in_({f.policy_version_id for f in excepted})
                )
            )
            .tuples()
            .all()
        )
        rows = session.scalars(
            select(Exception_).where(
                Exception_.org_id == org_id,
                or_(
                    Exception_.finding_id.in_([f.id for f in excepted]),
                    (Exception_.finding_id.is_(None) & Exception_.policy_id.in_(set(policy_by_version.values()))),
                ),
            )
        ).all()
        by_finding: dict[uuid.UUID, list[Exception_]] = {}
        by_policy: dict[uuid.UUID, list[Exception_]] = {}
        for row in rows:
            if row.finding_id is not None:
                by_finding.setdefault(row.finding_id, []).append(row)
            elif row.policy_id is not None:
                by_policy.setdefault(row.policy_id, []).append(row)

        for finding in excepted:
            finding_policy_id = policy_by_version.get(finding.policy_version_id)
            covering = by_finding.get(finding.id, [])
            if finding_policy_id is not None:
                covering = covering + by_policy.get(finding_policy_id, [])
            if not covering:
                continue
            expiries = [_utc(row.expires_at) for row in covering]
            if any(expiry is None or expiry > clock for expiry in expiries):
                continue
            _reopen(
                session,
                org_id,
                finding,
                reason=REASON_EXCEPTION_EXPIRED,
                expired_at=max(e for e in expiries if e is not None),
                now=clock,
                webhook_delivery_ids=webhook_delivery_ids,
            )
            result.exceptions_reopened.append(finding.id)

    session.flush()
    return result


def _reopen(
    session: Session,
    org_id: uuid.UUID,
    finding: Finding,
    *,
    reason: str,
    expired_at: datetime | None,
    now: datetime,
    webhook_delivery_ids: list[uuid.UUID] | None,
) -> None:
    previous = finding.status
    apply_status_transition(finding, FindingStatus.OPEN, now=now)
    record_audit_event(
        session,
        org_id=org_id,
        actor_operator_id=None,
        action=AUTO_REOPENED_ACTION,
        target_type="finding",
        target_id=finding.id,
        context={
            "status": FindingStatus.OPEN.value,
            "previous_status": previous.value,
            "reason": reason,
            "expired_at": expired_at.isoformat() if expired_at else None,
        },
    )
    schedule_finding_webhooks(
        session,
        org_id=org_id,
        event_type=FINDING_OPENED,
        finding=finding,
        delivery_ids=webhook_delivery_ids,
    )
    schedule_finding_notifications(session, org_id=org_id, event_type=FINDING_OPENED, finding=finding)
