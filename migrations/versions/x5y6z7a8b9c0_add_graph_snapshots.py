# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Create graph_snapshots table.

Revision ID: x5y6z7a8b9c0
Revises: w4x5y6z7a8b9
Create Date: 2026-08-11
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "x5y6z7a8b9c0"
down_revision: Union[str, None] = "w4x5y6z7a8b9"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "graph_snapshots",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("org_id", sa.UUID(), nullable=False),
        sa.Column("application_instance_id", sa.UUID(), nullable=False),
        sa.Column("connector_run_id", sa.UUID(), nullable=False),
        sa.Column("content_hash", sa.String(length=64), nullable=False),
        sa.Column("node_count", sa.Integer(), nullable=False),
        sa.Column("edge_count", sa.Integer(), nullable=False),
        sa.Column("payload", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["application_instance_id"], ["application_instances.id"]),
        sa.ForeignKeyConstraint(["connector_run_id"], ["connector_runs.id"]),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_graph_snapshots_instance_created",
        "graph_snapshots",
        ["org_id", "application_instance_id", "created_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_graph_snapshots_instance_created", table_name="graph_snapshots")
    op.drop_table("graph_snapshots")
