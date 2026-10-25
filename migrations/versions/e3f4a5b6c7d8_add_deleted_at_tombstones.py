# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Add deleted_at tombstones to provenance and relationship tables.

Revision ID: e3f4a5b6c7d8
Revises: d2e3f4a5b6c7
Create Date: 2026-09-04
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "e3f4a5b6c7d8"
down_revision: Union[str, None] = "d2e3f4a5b6c7"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# Every table that ``sync.upsert.detect_deletions`` can tombstone. ``activity_events``
# is append-only and never tombstoned, but it shares ``ProvenanceMixin`` so the
# column exists there too for model consistency.
_TABLES = (
    "identities",
    "groups",
    "roles",
    "resources",
    "permissions",
    "oauth_applications",
    "tenant_settings",
    "activity_events",
    "group_memberships",
    "grants",
    "oauth_grants",
)

# Hot read paths filter on ``deleted_at IS NULL`` inside one org; a partial
# index keeps that cheap without indexing the tombstones themselves.
_PARTIAL_INDEX_TABLES = ("identities", "grants", "group_memberships", "oauth_grants", "resources")


def upgrade() -> None:
    for table in _TABLES:
        op.add_column(table, sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True))
    for table in _PARTIAL_INDEX_TABLES:
        op.create_index(
            f"ix_{table}_active_org",
            table,
            ["org_id"],
            postgresql_where=sa.text("deleted_at IS NULL"),
        )


def downgrade() -> None:
    for table in _PARTIAL_INDEX_TABLES:
        op.drop_index(f"ix_{table}_active_org", table_name=table)
    for table in _TABLES:
        op.drop_column(table, "deleted_at")
