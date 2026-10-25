# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Org-wide change feed across sync runs.

Answers "what changed in the last N hours, across every connected app" — the
counterpart to run drift, which answers "what did this one sync see".

Because classification is derived rather than stored (see ``classify``), class
and significance filters can't be pushed into SQL for the browse path. The feed
scans a bounded window of recent events, classifies them, then filters. That
keeps classification rules improvable without a backfill, at the cost of an
exact total when the window is saturated -- callers get ``scan_saturated`` so
they can say so rather than silently under-report.

When search resolves to people / related grants, the feed loads those entity
ids directly so a high-significance grant is not lost behind telemetry noise.

Rows are then overlaid with the audit actor where one matches. That
step is additive only: it never adds, removes, or reclassifies a row, so a
connector with no audit log produces the same feed it always did.

Each connector instance's first completed (SUCCESS or PARTIAL_FAILURE) full run
is excluded: it establishes the baseline rather than observing change.
"""

from __future__ import annotations

import uuid
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import CompoundSelect, Select, exists, or_, select, union_all
from sqlalchemy.orm import Session

from kestrel.changes.classify import ChangeClass, ClassifiedChange, Significance, classify_events
from kestrel.changes.overlay import attach_audit_actors
from kestrel.changes.query import ParsedChangeSearch, parse_change_search
from kestrel.db.models.access import Grant, GroupMembership
from kestrel.db.models.application import ApplicationInstance
from kestrel.db.models.connector import ConnectorInstance, ConnectorRun, ConnectorRunStatus
from kestrel.db.models.event import ChangeType, Event
from kestrel.db.models.identity import Identity
from kestrel.db.models.oauth import OAuthGrant

FEED_SCAN_CAP = 500
LIMIT_DEFAULT = 50
LIMIT_MAX = 200
DEFAULT_WINDOW_HOURS = 24 * 7
# Default browse hides low/other telemetry; pass min_significance=low to see everything.
DEFAULT_MIN_SIGNIFICANCE = Significance.MEDIUM.value


class ChangeFeedError(ValueError):
    """Invalid feed filter."""


def clamp_limit(raw: int | None) -> int:
    if raw is None:
        return LIMIT_DEFAULT
    return max(1, min(int(raw), LIMIT_MAX))


def _parse_classes(raw: list[str] | None) -> set[ChangeClass] | None:
    if not raw:
        return None
    try:
        return {ChangeClass(value) for value in raw}
    except ValueError as exc:
        raise ChangeFeedError(f"unknown change_class: {exc}") from exc


def _parse_significance(raw: str | None) -> Significance:
    if not raw:
        return Significance(DEFAULT_MIN_SIGNIFICANCE)
    try:
        return Significance(raw)
    except ValueError as exc:
        raise ChangeFeedError(f"unknown significance: {raw}") from exc


def _matches(
    change: ClassifiedChange,
    classes: set[ChangeClass] | None,
    min_significance: Significance | None,
) -> bool:
    if classes is not None and change.change_class not in classes:
        return False
    if min_significance is not None:
        order = {Significance.HIGH: 0, Significance.MEDIUM: 1, Significance.LOW: 2}
        if order[change.significance] > order[min_significance]:
            return False
    return True


def _evidence_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value)


def _matches_search(change: ClassifiedChange, query: str | None) -> bool:
    if not query:
        return True
    needle = query.strip().lower()
    if not needle:
        return True
    haystacks = [
        change.summary,
        change.label,
        change.change_class.value,
        change.entity_type,
        change.application_display_name,
        _evidence_text(change.before),
        _evidence_text(change.after),
    ]
    return any(h and needle in str(h).lower() for h in haystacks)


def _enrich_with_connector_context(
    db: Session,
    org_id: uuid.UUID,
    events: list[Event],
    classified: list[ClassifiedChange],
) -> list[ClassifiedChange]:
    """Attach connector instance + application display name without N+1 in classify."""
    if not classified:
        return classified

    run_ids = {event.connector_run_id for event in events}
    runs = {
        run.id: run
        for run in db.scalars(
            select(ConnectorRun).where(
                ConnectorRun.org_id == org_id,
                ConnectorRun.id.in_(run_ids),
            )
        ).all()
    }
    instance_ids = {run.connector_instance_id for run in runs.values()}
    instances = {
        instance.id: instance
        for instance in db.scalars(
            select(ConnectorInstance).where(
                ConnectorInstance.org_id == org_id,
                ConnectorInstance.id.in_(instance_ids),
            )
        ).all()
    }
    app_ids = {instance.application_instance_id for instance in instances.values()}
    apps = {
        app.id: app
        for app in db.scalars(
            select(ApplicationInstance).where(
                ApplicationInstance.org_id == org_id,
                ApplicationInstance.id.in_(app_ids),
            )
        ).all()
    }

    event_by_id = {event.id: event for event in events}
    enriched: list[ClassifiedChange] = []
    for change in classified:
        event = event_by_id.get(change.event_id)
        connector_instance_id = None
        application_display_name = None
        if event is not None:
            run = runs.get(event.connector_run_id)
            if run is not None:
                connector_instance_id = run.connector_instance_id
                instance = instances.get(run.connector_instance_id)
                if instance is not None:
                    app = apps.get(instance.application_instance_id)
                    if app is not None:
                        application_display_name = app.display_name
        enriched.append(
            replace(
                change,
                connector_instance_id=connector_instance_id,
                application_display_name=application_display_name,
            )
        )
    return enriched


def _baseline_run_ids(org_id: uuid.UUID) -> Select[tuple[uuid.UUID]]:
    """The first completed full run of each connector instance, as a subquery.

    That run doesn't observe change, it establishes what "normal" is -- every
    row it writes is a creation. Counting it would open the feed with hundreds
    of "new admin" entries on day one and bury real drift forever.

    PARTIAL_FAILURE runs count. A connector that can never read one family (a
    GitHub org without audit-log access) is partial on every run; requiring
    SUCCESS would leave it with no baseline, so its first run's creations would
    flood the feed, and a later SUCCESS would be wrongly treated as the
    baseline, hiding its real drift.

    Incremental runs are excluded from the search for it. An
    events-only poll is a SUCCESS but collects a fraction of the tenant, so if
    one landed before the first full sync it would be picked as the baseline
    and the actual baseline's creations would all flood the feed.
    """
    return (
        select(ConnectorRun.id)
        .distinct(ConnectorRun.connector_instance_id)
        .where(
            ConnectorRun.org_id == org_id,
            ConnectorRun.status.in_((ConnectorRunStatus.SUCCESS, ConnectorRunStatus.PARTIAL_FAILURE)),
            ConnectorRun.is_incremental.is_(False),
        )
        .order_by(ConnectorRun.connector_instance_id, ConnectorRun.started_at.asc())
    )


def _resolve_app_connector_instance_id(db: Session, org_id: uuid.UUID, app_query: str) -> uuid.UUID | None:
    """Match ``app:`` against application display name."""
    needle = app_query.strip().lower()
    if not needle:
        return None
    instances = list(db.scalars(select(ConnectorInstance).where(ConnectorInstance.org_id == org_id)).all())
    if not instances:
        return None
    apps = {
        app.id: app
        for app in db.scalars(
            select(ApplicationInstance).where(
                ApplicationInstance.org_id == org_id,
                ApplicationInstance.id.in_({i.application_instance_id for i in instances}),
            )
        ).all()
    }
    for instance in instances:
        app = apps.get(instance.application_instance_id)
        label = (app.display_name if app else None) or ""
        if label and needle in label.lower():
            return instance.id
    return None


def _identity_ids_matching(org_id: uuid.UUID, needle: str) -> Select[tuple[uuid.UUID]]:
    pattern = f"%{needle}%"
    return select(Identity.id).where(
        Identity.org_id == org_id,
        or_(
            Identity.email.ilike(pattern),
            Identity.display_name.ilike(pattern),
            Identity.provider_object_id.ilike(pattern),
        ),
    )


def _related_entity_ids(org_id: uuid.UUID, identity_ids: Select[tuple[uuid.UUID]]) -> CompoundSelect:
    """The matched identities plus grants / memberships / OAuth grants pointing at them.

    Returned as SQL, never materialized: a broad needle ("com") in a large
    tenant matches hundreds of thousands of rows, and a literal ``IN`` list of
    them overflows the driver's 65,535 bind-parameter limit.
    """
    matched = identity_ids.scalar_subquery()
    return union_all(
        identity_ids,
        select(Grant.id).where(Grant.org_id == org_id, Grant.identity_id.in_(matched)),
        select(GroupMembership.id).where(GroupMembership.org_id == org_id, GroupMembership.identity_id.in_(matched)),
        select(OAuthGrant.id).where(OAuthGrant.org_id == org_id, OAuthGrant.identity_id.in_(matched)),
    )


def _merge_parsed_filters(
    *,
    change_classes: list[str] | None,
    min_significance: str | None,
    connector_instance_id: uuid.UUID | None,
    parsed: ParsedChangeSearch,
    db: Session,
    org_id: uuid.UUID,
) -> tuple[list[str] | None, str | None, uuid.UUID | None, str | None, str | None]:
    """Combine URL params with tokens from ``search``. Tokens win when set."""
    classes = list(change_classes) if change_classes else []
    classes.extend(parsed.change_classes)
    class_list = classes or None

    significance = parsed.min_significance or min_significance

    connector_id = connector_instance_id
    if parsed.app and connector_id is None:
        resolved = _resolve_app_connector_instance_id(db, org_id, parsed.app)
        if resolved is None:
            raise ChangeFeedError(f"unknown app: {parsed.app}")
        connector_id = resolved

    free_text = parsed.free_text
    person = parsed.person
    return class_list, significance, connector_id, free_text, person


def _load_events(
    db: Session,
    org_id: uuid.UUID,
    *,
    since: datetime,
    connector_instance_id: uuid.UUID | None,
    entity_ids: CompoundSelect | None,
) -> list[Event]:
    stmt = (
        select(Event)
        .join(ConnectorRun, ConnectorRun.id == Event.connector_run_id)
        .where(
            Event.org_id == org_id,
            Event.change_type != ChangeType.UNCHANGED,
            Event.detected_at >= since,
        )
        .order_by(Event.detected_at.desc(), Event.id.desc())
        .limit(FEED_SCAN_CAP)
    )
    if connector_instance_id is not None:
        stmt = stmt.where(ConnectorRun.connector_instance_id == connector_instance_id)
    stmt = stmt.where(Event.connector_run_id.not_in(_baseline_run_ids(org_id)))
    if entity_ids is not None:
        stmt = stmt.where(Event.entity_id.in_(entity_ids))
    return list(db.scalars(stmt).all())


def change_feed(
    db: Session,
    org_id: uuid.UUID,
    *,
    since: datetime | None = None,
    window_hours: int | None = None,
    change_classes: list[str] | None = None,
    min_significance: str | None = None,
    connector_instance_id: uuid.UUID | None = None,
    search: str | None = None,
    limit: int | None = None,
    offset: int = 0,
) -> dict[str, Any]:
    """Classified changes across the org, most significant first."""
    parsed = parse_change_search(search)
    class_list, significance_raw, connector_id, free_text, person = _merge_parsed_filters(
        change_classes=change_classes,
        min_significance=min_significance,
        connector_instance_id=connector_instance_id,
        parsed=parsed,
        db=db,
        org_id=org_id,
    )
    classes = _parse_classes(class_list)
    significance = _parse_significance(significance_raw)
    lim = clamp_limit(limit)
    off = max(0, int(offset))

    if since is None:
        hours = window_hours if window_hours is not None else DEFAULT_WINDOW_HOURS
        if hours <= 0:
            raise ChangeFeedError("window_hours must be positive")
        since = datetime.now(UTC) - timedelta(hours=hours)

    entity_scope: CompoundSelect | None = None
    no_person_match = False
    person_needle = person or None
    # Prefer explicit person:; otherwise resolve free text against identities so
    # "grace" finds grants even when telemetry saturates the browse scan.
    resolve_needle = person_needle or free_text
    if resolve_needle:
        identity_ids = _identity_ids_matching(org_id, resolve_needle)
        if db.scalar(select(exists(identity_ids))):
            entity_scope = _related_entity_ids(org_id, identity_ids)
        elif person_needle:
            # Explicit person: with no match → empty feed, not a blind scan.
            no_person_match = True

    scanned = (
        []
        if no_person_match
        else _load_events(
            db,
            org_id,
            since=since,
            connector_instance_id=connector_id,
            entity_ids=entity_scope,
        )
    )
    scoped = entity_scope is not None or no_person_match

    classified = _enrich_with_connector_context(db, org_id, scanned, classify_events(db, org_id, scanned))
    # Snapshot-diff is still the only thing that creates a row (DEC-024); this
    # only fills in who did it, where an audit log happens to say.
    classified = attach_audit_actors(db, org_id, scanned, classified)

    # When we scoped by identity, do not re-require free-text match on summary —
    # the entity resolution already answered "this person". Still apply free text
    # when we fell back to the browse scan.
    text_filter = None if scoped else free_text
    matching = [c for c in classified if _matches(c, classes, significance) and _matches_search(c, text_filter)]

    by_class: dict[str, int] = {}
    by_significance: dict[str, int] = {"high": 0, "medium": 0, "low": 0}
    for change in matching:
        by_class[change.change_class.value] = by_class.get(change.change_class.value, 0) + 1
        by_significance[change.significance.value] += 1

    page = matching[off : off + lim]
    display_search = search.strip() if search and search.strip() else None
    return {
        "since": since.isoformat(),
        "limit": lim,
        "offset": off,
        "total": len(matching),
        "scan_saturated": not scoped and len(scanned) >= FEED_SCAN_CAP,
        "summary": {"by_class": dict(sorted(by_class.items())), "by_significance": by_significance},
        "changes": [c.as_dict() for c in page],
        "filters": {
            "change_classes": sorted(c.value for c in classes) if classes else None,
            "min_significance": significance.value,
            "connector_instance_id": connector_id,
            "search": display_search,
        },
    }


def resolve_connector_instance(db: Session, org_id: uuid.UUID, connector_instance_id: uuid.UUID) -> ConnectorInstance:
    """Tenant-scoped lookup so a feed filter can't reference another org's connector."""
    instance = db.get(ConnectorInstance, connector_instance_id)
    if instance is None or instance.org_id != org_id:
        raise ChangeFeedError("unknown connector instance")
    return instance
