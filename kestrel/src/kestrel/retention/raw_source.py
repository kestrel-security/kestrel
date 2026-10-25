# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Retention for `raw_source` provenance payloads.

`raw_source` holds the verbatim provider response for every collected
entity. That is deliberate -- it's what makes a finding defensible ("here is
exactly what the API said") -- but it is also the most sensitive and
fastest-growing data Kestrel stores, and it keeps growing for as long as an
entity exists.

This module trims those payloads without touching the entities themselves.
Two design choices matter:

**Entities are never deleted.** Only the `raw_source` column is rewritten.
Deleting an Identity or Resource to reclaim space would destroy the access
graph, silently resolve findings that are still true, and break historical
`events`. Trimming is a redaction, not a purge.

**Trimmed payloads become a tombstone, not NULL.** `raw_source` is
`NOT NULL` on ProvenanceMixin, and making it nullable would push
"is this missing or was it trimmed?" onto every reader. A tombstone answers
that question in the data itself, and re-syncing an entity naturally
overwrites it with a fresh payload.

Retention is opt-in and explicit: nothing here runs on a schedule unless an
operator wires it up (see docs/operations/data-retention.md).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import cast

from sqlalchemy import select
from sqlalchemy.orm import Session

from kestrel.db.models.access import Group, Permission, Role
from kestrel.db.models.identity import Identity
from kestrel.db.models.oauth import OAuthApplication
from kestrel.db.models.resource import Resource

# Unions rather than a bare tuple of classes, for the same reason
# kestrel.sync.upsert declares ProvenanceModel/ProvenanceEntity: mypy can then
# resolve the ProvenanceMixin attributes (org_id, last_seen_at, raw_source)
# these otherwise-unrelated classes share, and SQLAlchemy's select() stubs
# widen the row type back to the declarative Base, so results are cast().
TrimmableModel = type[Identity] | type[Group] | type[Role] | type[Permission] | type[Resource] | type[OAuthApplication]
TrimmableEntity = Identity | Group | Role | Permission | Resource | OAuthApplication

# Every model carrying ProvenanceMixin.raw_source.
TRIMMABLE_MODELS: tuple[TrimmableModel, ...] = (
    Identity,
    Group,
    Role,
    Permission,
    Resource,
    OAuthApplication,
)

TOMBSTONE_KEY = "_kestrel_raw_source_trimmed"


def make_tombstone(trimmed_at: datetime) -> dict:
    return {TOMBSTONE_KEY: True, "trimmed_at": trimmed_at.isoformat()}


def is_trimmed(raw_source: dict | None) -> bool:
    if not raw_source:
        return False
    return raw_source.get(TOMBSTONE_KEY) is True


@dataclass
class TrimResult:
    cutoff: datetime
    dry_run: bool
    trimmed_by_model: dict[str, int] = field(default_factory=dict)

    @property
    def total(self) -> int:
        return sum(self.trimmed_by_model.values())


def trim_raw_source(
    session: Session,
    *,
    org_id: uuid.UUID,
    older_than_days: int,
    dry_run: bool = False,
) -> TrimResult:
    """Replaces `raw_source` with a tombstone on entities not seen since the
    cutoff. Returns per-model counts.

    Selects on `last_seen_at`, not `created_at`: an identity created two
    years ago but still present in every sync is live data, and trimming its
    payload would throw away provenance for a currently-true finding. The
    cutoff means "not observed recently", which is what retention is
    actually about.

    Already-trimmed rows are skipped, so re-running is idempotent and the
    reported counts stay meaningful instead of re-counting the same rows.

    Does not commit -- the caller controls the transaction boundary.
    """
    if older_than_days < 1:
        raise ValueError("older_than_days must be >= 1")

    now = datetime.now(UTC)
    cutoff = now - timedelta(days=older_than_days)
    result = TrimResult(cutoff=cutoff, dry_run=dry_run)
    tombstone = make_tombstone(now)

    for model in TRIMMABLE_MODELS:
        rows = cast(
            list[TrimmableEntity],
            list(session.scalars(select(model).where(model.org_id == org_id, model.last_seen_at < cutoff)).all()),
        )
        stale = [row for row in rows if not is_trimmed(row.raw_source)]
        if not dry_run:
            for row in stale:
                row.raw_source = tombstone
        result.trimmed_by_model[model.__name__] = len(stale)

    if not dry_run:
        session.flush()
    return result
