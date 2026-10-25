# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Unique grants by their natural key.

The sync upsert finds a grant by (org, identity, resource, role, source
group, granted_via) with ``one_or_none()``. Nothing enforced that key, so two
interleaved syncs of one instance could write the same grant twice, after
which every later sync raised MultipleResultsFound on it. Most of the key's
columns are nullable (a team grant has no identity, an org role no resource),
so the index uses ``NULLS NOT DISTINCT`` (Postgres 15+; Kestrel runs on 16).

Existing duplicates are collapsed first: the survivor is the live row seen
most recently, it inherits the earliest ``first_seen_at`` of its group, and
change events that named a removed duplicate are re-pointed at it. No foreign
key references ``grants.id``.

Revision ID: g6b7c8d9e0f1
Revises: f5a6b7c8d9e0
Create Date: 2026-10-05
"""

from typing import Sequence, Union

from alembic import op

revision: str = "g6b7c8d9e0f1"
down_revision: Union[str, None] = "f5a6b7c8d9e0"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_INDEX = "uq_grants_natural_key"


def upgrade() -> None:
    op.execute(
        """
        CREATE TEMPORARY TABLE _grant_dupes ON COMMIT DROP AS
        SELECT id,
               first_value(id) OVER w AS keeper,
               min(first_seen_at) OVER (
                   PARTITION BY org_id, identity_id, resource_id, role_id, source_group_id, granted_via
               ) AS earliest_seen
        FROM grants
        WINDOW w AS (
            PARTITION BY org_id, identity_id, resource_id, role_id, source_group_id, granted_via
            ORDER BY (deleted_at IS NULL) DESC, last_seen_at DESC NULLS LAST, id
        )
        """
    )
    op.execute(
        """
        UPDATE events e
        SET entity_id = d.keeper
        FROM _grant_dupes d
        WHERE e.entity_type = 'grant' AND e.entity_id = d.id AND d.id <> d.keeper
        """
    )
    op.execute(
        """
        UPDATE grants g
        SET first_seen_at = d.earliest_seen
        FROM _grant_dupes d
        WHERE g.id = d.id AND d.id = d.keeper AND d.earliest_seen < g.first_seen_at
        """
    )
    op.execute("DELETE FROM grants g USING _grant_dupes d WHERE g.id = d.id AND d.id <> d.keeper")
    op.execute("DROP TABLE _grant_dupes")
    op.execute(
        f"""
        CREATE UNIQUE INDEX {_INDEX} ON grants
            (org_id, identity_id, resource_id, role_id, source_group_id, granted_via)
            NULLS NOT DISTINCT
        """
    )


def downgrade() -> None:
    op.execute(f"DROP INDEX IF EXISTS {_INDEX}")
