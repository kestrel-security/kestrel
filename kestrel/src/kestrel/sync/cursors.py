# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Read and advance connector high-water marks.

`Collector.collect(since=)` shipped with the SDK and Okta and Slack both
forward it to their audit-log clients -- but `run_sync` never supplied it,
so every sync re-read the provider's full default window (about seven days for
Okta). This module is the missing half: where the last run got to.

Two rules make re-reads safe:

**Overlap.** The watermark handed to a collector is the stored one minus
`OVERLAP_WINDOW`, never the exact last position. Provider audit logs are
eventually consistent -- an event that occurred at T can become visible after a
poll that asked for everything since T -- so asking for the exact boundary
drops events. Re-reading a few minutes twice is free because of the second
rule.

**Idempotent writes.** Audit rows upsert on
`(application_instance_id, provider_object_id)`, so a re-read updates the row
it already wrote instead of duplicating it, and `NON_FEED_KINDS`
keeps either outcome out of the Changes feed.

Cursors advance only for object types the run actually collected, and only
when the run did not fail -- a failed run has no idea what it read.

**First run.** An incremental object type with no cursor yet is handed
``run_started_at - KESTREL_SYNC_INITIAL_LOOKBACK_HOURS`` (default 24 hours)
rather than nothing. "Nothing" meant the provider's whole default window --
GitHub's 180-day web audit log, Okta's seven days of System Log -- which on a
large tenant exhausts the request budget or the page cap, fails the run, never
advances the cursor, and so repeats on every run. Setting the variable to 0
restores the provider default window.
"""

from __future__ import annotations

import uuid
from collections.abc import Collection, Mapping
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from kestrel.db.models.connector import ConnectorCursor
from kestrel.env import getenv_int

# Re-read this far behind the stored watermark. Sized for provider audit-log
# ingestion lag, which is minutes for every provider Kestrel supports.
OVERLAP_WINDOW = timedelta(minutes=15)

# How far back a first incremental run reads when no cursor exists yet.
DEFAULT_INITIAL_LOOKBACK_HOURS = 24
_ENV_INITIAL_LOOKBACK = "KESTREL_SYNC_INITIAL_LOOKBACK_HOURS"


def initial_lookback() -> timedelta | None:
    """The first-run window, or None when the operator asked for the provider default (0)."""
    hours = getenv_int(_ENV_INITIAL_LOOKBACK, DEFAULT_INITIAL_LOOKBACK_HOURS)
    return timedelta(hours=hours) if hours > 0 else None


def with_initial_lookback(
    since: Mapping[str, datetime],
    *,
    incremental_object_types: Collection[str],
    run_started_at: datetime,
) -> dict[str, datetime]:
    """`since` with a default watermark for every incremental type that has none.

    Types that already have a cursor keep it; types the manifest does not mark
    ``supports_incremental`` are left out, so a full-inventory collector still
    receives ``None`` and walks everything.
    """
    result = dict(since)
    window = initial_lookback()
    if window is None:
        return result
    for name in incremental_object_types:
        result.setdefault(name, run_started_at - window)
    return result


def _parse(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        # An opaque provider cursor rather than a timestamp. Nothing time-based
        # can be derived from it; the caller full-syncs that object type.
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


def load_since_by_object_type(
    session: Session,
    *,
    connector_instance_id: uuid.UUID,
    overlap: timedelta = OVERLAP_WINDOW,
) -> dict[str, datetime]:
    """Watermarks to hand this instance's collector, already overlapped.

    An object type with no cursor is absent from the result, which the runner
    reads as "collect the provider's default window" -- the correct behaviour
    for a first incremental run.
    """
    rows = session.scalars(
        select(ConnectorCursor).where(ConnectorCursor.connector_instance_id == connector_instance_id)
    ).all()
    since: dict[str, datetime] = {}
    for row in rows:
        parsed = _parse(row.cursor)
        if parsed is not None:
            since[row.object_type] = parsed - overlap
    return since


def advance_cursors(
    session: Session,
    *,
    org_id: uuid.UUID,
    connector_instance_id: uuid.UUID,
    object_types: list[str],
    watermark: datetime,
) -> None:
    """Move the watermark for each named object type to `watermark`.

    `watermark` should be the time collection *started*, not the time it
    finished: anything that happened during the run is not guaranteed to have
    been visible to it, and the overlap window is what covers the gap.
    """
    if not object_types:
        return
    existing = {
        row.object_type: row
        for row in session.scalars(
            select(ConnectorCursor).where(
                ConnectorCursor.connector_instance_id == connector_instance_id,
                ConnectorCursor.object_type.in_(object_types),
            )
        ).all()
    }
    now = datetime.now(UTC)
    value = watermark.isoformat()
    for object_type in object_types:
        row = existing.get(object_type)
        if row is None:
            session.add(
                ConnectorCursor(
                    id=uuid.uuid4(),
                    org_id=org_id,
                    connector_instance_id=connector_instance_id,
                    object_type=object_type,
                    cursor=value,
                    advanced_at=now,
                )
            )
        else:
            row.cursor = value
            row.advanced_at = now


def incremental_object_types(manifest: object) -> list[str]:
    """Object types a manifest declares as incrementally collectable.

    Accepts both shapes a manifest arrives in: the SDK's `ConnectorManifest`
    when the caller loaded the connector code, and the plain dict stored on
    `Connector.manifest` when the beat dispatcher only has the DB row and does
    not want to import every connector package to decide who to poll.
    """
    if isinstance(manifest, dict):
        specs: list[Any] = list(manifest.get("object_types") or [])
    else:
        specs = list(getattr(manifest, "object_types", None) or [])

    names: list[str] = []
    for spec in specs:
        if isinstance(spec, dict):
            name, incremental = spec.get("name"), spec.get("supports_incremental", False)
        else:
            name, incremental = getattr(spec, "name", None), getattr(spec, "supports_incremental", False)
        if name and incremental:
            names.append(str(name))
    return names
