# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Add connector_cursors + ConnectorRun.is_incremental.

`Collector.collect(since=)` was in the protocol from the start and three
connectors plumbed it, but nothing ever passed it because there was nowhere to
persist a high-water mark. Every sync re-read the provider's full audit window.

`is_incremental` marks a run that deliberately collected only some object
types. It is a SUCCESS, but it is not a full inventory, so it must not become
the Changes baseline or stand in for a full sync in staleness checks.

Revision ID: d2e3f4a5b6c7
Revises: c1d2e3f4a5b6
Create Date: 2026-08-30
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "d2e3f4a5b6c7"
down_revision: Union[str, None] = "c1d2e3f4a5b6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "connector_cursors",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("org_id", sa.UUID(), nullable=False),
        sa.Column("connector_instance_id", sa.UUID(), nullable=False),
        sa.Column("object_type", sa.String(), nullable=False),
        sa.Column("cursor", sa.String(), nullable=False),
        sa.Column("advanced_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["connector_instance_id"], ["connector_instances.id"]),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("connector_instance_id", "object_type"),
    )
    op.create_index("ix_connector_cursors_org_id", "connector_cursors", ["org_id"])
    op.create_index(
        "ix_connector_cursors_connector_instance_id",
        "connector_cursors",
        ["connector_instance_id"],
    )

    # Existing runs were all full inventory runs.
    op.add_column(
        "connector_runs",
        sa.Column("is_incremental", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.alter_column("connector_runs", "is_incremental", server_default=None)


def downgrade() -> None:
    op.drop_column("connector_runs", "is_incremental")
    op.drop_index("ix_connector_cursors_connector_instance_id", table_name="connector_cursors")
    op.drop_index("ix_connector_cursors_org_id", table_name="connector_cursors")
    op.drop_table("connector_cursors")
