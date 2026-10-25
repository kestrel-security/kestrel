# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Attach the audit actor to a change row.

Snapshot-diff knows *what* moved and *when Kestrel noticed*. It structurally
cannot know *who did it* -- that only exists in a provider audit log. Operators
opening `/changes` could see "grace@acme.example became an org admin" and had no
way to answer the next question without leaving the product.

Per DEC-024 this is an overlay and nothing more. The audit log never creates a
row, never removes one, and never changes a classification; a connector that
collects no audit log produces exactly the feed it produced before. If the
match fails, the row renders as it always did.

Matching is deliberately narrow, because a wrong actor is worse than no actor:

* **Same tenant.** Only activity from the same application instance as the
  change.
* **Same subject.** The audit row's target must resolve to the entity the
  change is about -- by provider id, or by email when the provider only
  reports one. Grants, memberships, and OAuth grants resolve through to the
  identity they concern.
* **Same kind of action.** `_ACTIONS_FOR_CLASS` maps each ChangeClass to the
  normalized actions that could have caused it, so an unrelated event in the
  window is not borrowed.
* **Same interval.** The window is the diff interval itself: from the previous
  full run's start to this run's start. That is precisely the period the
  change was detected across, so an event outside it did not cause this row.

When several candidates match, the latest one wins -- it is the action whose
effect the snapshot recorded.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from dataclasses import replace
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from kestrel.changes.classify import ChangeClass, ClassifiedChange
from kestrel.db.models.access import Grant, GroupMembership
from kestrel.db.models.activity_event import ActivityEvent
from kestrel.db.models.connector import ConnectorRun, ConnectorRunStatus
from kestrel.db.models.event import Event
from kestrel.db.models.identity import Identity
from kestrel.db.models.oauth import OAuthApplication, OAuthGrant

# Normalized audit actions that could have produced each class. Actions come
# from the connectors' curated taxonomies (docs/changes.md); anything
# unmapped simply never overlays.
_PRIVILEGE_UP = frozenset({"privilege.grant", "privilege.external", "service_account.escalate"})
_PRIVILEGE_DOWN = frozenset({"privilege.revoke"})

_ACTIONS_FOR_CLASS: dict[ChangeClass, frozenset[str]] = {
    ChangeClass.ADMIN_GRANTED: _PRIVILEGE_UP,
    ChangeClass.ADMIN_REVOKED: _PRIVILEGE_DOWN,
    ChangeClass.PRIVILEGE_ESCALATED: _PRIVILEGE_UP,
    ChangeClass.PRIVILEGE_REDUCED: _PRIVILEGE_DOWN,
    ChangeClass.ACCESS_GRANTED: _PRIVILEGE_UP | {"access.grant"},
    ChangeClass.ACCESS_REVOKED: _PRIVILEGE_DOWN | {"access.revoke"},
    ChangeClass.GROUP_MEMBER_ADDED: frozenset({"privilege.grant", "group.member.add"}),
    ChangeClass.GROUP_MEMBER_REMOVED: frozenset({"privilege.revoke", "group.member.remove"}),
    ChangeClass.OAUTH_APP_INSTALLED: frozenset({"oauth.app.install", "oauth.sensitive_consent", "token.grant"}),
    ChangeClass.OAUTH_APP_REVOKED: frozenset({"oauth.app.revoke"}),
    ChangeClass.OAUTH_SCOPE_EXPANDED: frozenset({"oauth.scope.expand"}),
    ChangeClass.MFA_DISABLED: frozenset({"mfa.disable"}),
    ChangeClass.IDENTITY_DISABLED: frozenset({"identity.deactivate"}),
    ChangeClass.IDENTITY_ADDED: frozenset({"identity.add", "identity.guest", "dormant.reactivate"}),
    ChangeClass.IDENTITY_REMOVED: frozenset({"identity.deactivate"}),
    ChangeClass.EXTERNAL_SHARING_ENABLED: frozenset({"sharing.external"}),
    # Settings drift covers a wide surface, so only actions that unambiguously
    # loosen a security control attribute here. `config.change` and
    # `policy.change` are deliberately absent: they are catch-alls for vendor
    # setting-edit noise and would attach an unrelated edit to whichever
    # setting happened to drift. `sso.change` is included because SSO
    # enforcement flips are rare and high-signal.
    ChangeClass.CONFIG_DRIFT: frozenset(
        {
            "branch_protection.disable",
            "sso.change",
            "webhook.create",
            "deploy_key.create",
        }
    ),
}

# Used only when a change's run has no predecessor, which the baseline
# exclusion normally prevents. Bounded rather than unbounded so a stale audit
# row can never be attributed to a much later change.
_FALLBACK_WINDOW = timedelta(days=7)


def _aware(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def _run_windows(
    db: Session, org_id: uuid.UUID, run_ids: set[uuid.UUID]
) -> dict[uuid.UUID, tuple[datetime, datetime, uuid.UUID]]:
    """(window_start, window_end, application_instance_id) per run.

    The window is the diff interval: the previous full run's start to this
    run's start. Incremental runs are skipped when looking for the predecessor
    -- an events-only poll collects no inventory, so it is not the snapshot
    this change was diffed against.
    """
    if not run_ids:
        return {}

    runs = {
        run.id: run
        for run in db.scalars(select(ConnectorRun).where(ConnectorRun.org_id == org_id, ConnectorRun.id.in_(run_ids))).all()
    }
    if not runs:
        return {}

    instance_ids = {run.connector_instance_id for run in runs.values()}
    history = db.scalars(
        select(ConnectorRun)
        .where(
            ConnectorRun.org_id == org_id,
            ConnectorRun.connector_instance_id.in_(instance_ids),
            ConnectorRun.is_incremental.is_(False),
            ConnectorRun.status.in_([ConnectorRunStatus.SUCCESS, ConnectorRunStatus.PARTIAL_FAILURE]),
        )
        .order_by(ConnectorRun.connector_instance_id, ConnectorRun.started_at.asc())
    ).all()

    previous_start: dict[uuid.UUID, datetime] = {}
    last_start_by_instance: dict[uuid.UUID, datetime] = {}
    for run in history:
        started = _aware(run.started_at)
        if started is None:
            continue
        earlier = last_start_by_instance.get(run.connector_instance_id)
        if earlier is not None:
            previous_start[run.id] = earlier
        last_start_by_instance[run.connector_instance_id] = started

    from kestrel.db.models.connector import ConnectorInstance

    instances = {
        instance.id: instance
        for instance in db.scalars(select(ConnectorInstance).where(ConnectorInstance.id.in_(instance_ids))).all()
    }

    windows: dict[uuid.UUID, tuple[datetime, datetime, uuid.UUID]] = {}
    for run_id, run in runs.items():
        end = _aware(run.started_at)
        instance = instances.get(run.connector_instance_id)
        if end is None or instance is None:
            continue
        start = previous_start.get(run_id, end - _FALLBACK_WINDOW)
        windows[run_id] = (start, end, instance.application_instance_id)
    return windows


def _subject_keys(
    db: Session, org_id: uuid.UUID, classified: Sequence[ClassifiedChange]
) -> dict[uuid.UUID, tuple[str | None, str | None]]:
    """(provider id, email) identifying the subject of each change.

    Relationship-shaped changes resolve through to the identity they concern:
    the audit log reports who a role was granted *to*, not the id of Kestrel's
    grant row.
    """
    by_type: dict[str, set[uuid.UUID]] = {}
    for change in classified:
        by_type.setdefault(change.entity_type, set()).add(change.entity_id)

    identity_for_entity: dict[uuid.UUID, uuid.UUID] = {}
    wanted_identities: set[uuid.UUID] = set(by_type.get("identity", set()))

    # Each relationship kind is queried on its own model rather than through a
    # loop over a heterogeneous list: the three tables share the shape but not
    # a common base that exposes `id` / `identity_id` to the type checker.
    grant_ids = by_type.get("grant")
    if grant_ids:
        for grant in db.scalars(select(Grant).where(Grant.org_id == org_id, Grant.id.in_(grant_ids))).all():
            if grant.identity_id is not None:
                identity_for_entity[grant.id] = grant.identity_id
                wanted_identities.add(grant.identity_id)

    membership_ids = by_type.get("group_membership")
    if membership_ids:
        for membership in db.scalars(
            select(GroupMembership).where(GroupMembership.org_id == org_id, GroupMembership.id.in_(membership_ids))
        ).all():
            identity_for_entity[membership.id] = membership.identity_id
            wanted_identities.add(membership.identity_id)

    oauth_grant_ids = by_type.get("oauth_grant")
    if oauth_grant_ids:
        for oauth_grant in db.scalars(
            select(OAuthGrant).where(OAuthGrant.org_id == org_id, OAuthGrant.id.in_(oauth_grant_ids))
        ).all():
            identity_for_entity[oauth_grant.id] = oauth_grant.identity_id
            wanted_identities.add(oauth_grant.identity_id)

    identities = {
        row.id: row
        for row in db.scalars(select(Identity).where(Identity.org_id == org_id, Identity.id.in_(wanted_identities))).all()
    }

    keys: dict[uuid.UUID, tuple[str | None, str | None]] = {}
    for change in classified:
        if change.entity_type == "identity":
            identity = identities.get(change.entity_id)
        elif change.entity_type == "oauth_application":
            app_ids = by_type.get("oauth_application") or set()
            app = (
                db.scalars(
                    select(OAuthApplication).where(
                        OAuthApplication.org_id == org_id,
                        OAuthApplication.id.in_(app_ids),
                        OAuthApplication.id == change.entity_id,
                    )
                ).one_or_none()
                if app_ids
                else None
            )
            if app is not None:
                keys[change.entity_id] = (app.provider_object_id, None)
            continue
        else:
            identity_id = identity_for_entity.get(change.entity_id)
            identity = identities.get(identity_id) if identity_id else None
        if identity is not None:
            keys[change.entity_id] = (identity.provider_object_id, identity.email)
    return keys


def attach_audit_actors(
    db: Session,
    org_id: uuid.UUID,
    events: Sequence[Event],
    classified: list[ClassifiedChange],
) -> list[ClassifiedChange]:
    """Return `classified` with an audit actor attached wherever one matches.

    Purely additive. Rows without a match, and orgs whose connectors collect no
    audit log, come back untouched.
    """
    if not classified:
        return classified

    actionable = [c for c in classified if _ACTIONS_FOR_CLASS.get(c.change_class)]
    if not actionable:
        return classified

    run_by_event = {event.id: event.connector_run_id for event in events}
    windows = _run_windows(db, org_id, {run_by_event[c.event_id] for c in actionable if c.event_id in run_by_event})
    if not windows:
        return classified

    subject_keys = _subject_keys(db, org_id, actionable)
    if not subject_keys:
        return classified

    wanted_actions = {action for c in actionable for action in _ACTIONS_FOR_CLASS[c.change_class]}
    earliest = min(start for start, _end, _app in windows.values())
    latest = max(end for _start, end, _app in windows.values())

    activity = db.scalars(
        select(ActivityEvent).where(
            ActivityEvent.org_id == org_id,
            ActivityEvent.action.in_(wanted_actions),
            ActivityEvent.occurred_at >= earliest,
            ActivityEvent.occurred_at <= latest,
        )
    ).all()
    if not activity:
        return classified

    by_index = {id(change): index for index, change in enumerate(classified)}
    result = list(classified)

    for change in actionable:
        run_id = run_by_event.get(change.event_id)
        window = windows.get(run_id) if run_id else None
        key = subject_keys.get(change.entity_id)
        if window is None or key is None:
            continue
        start, end, application_instance_id = window
        provider_id, email = key
        needle_email = email.casefold() if email else None
        actions = _ACTIONS_FOR_CLASS[change.change_class]

        best: ActivityEvent | None = None
        for row in activity:
            if row.application_instance_id != application_instance_id:
                continue
            if row.action not in actions:
                continue
            occurred = _aware(row.occurred_at)
            if occurred is None or occurred < start or occurred > end:
                continue
            target_matches = (provider_id is not None and row.target_provider_id == provider_id) or (
                needle_email is not None and row.target_email is not None and row.target_email.casefold() == needle_email
            )
            if not target_matches:
                continue
            if best is None or (_aware(best.occurred_at) or start) < occurred:
                best = row

        if best is None:
            continue
        result[by_index[id(change)]] = replace(
            change,
            actor_email=best.actor_email,
            actor_provider_id=best.actor_provider_id,
            actor_action=best.action,
            actor_occurred_at=_aware(best.occurred_at),
        )

    return result
