# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Investigate saved queries table.

Revision ID: d9e0f1a2b3c4
Revises: c8d9e0f1a2b3
Create Date: 2026-07-22
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "d9e0f1a2b3c4"
down_revision: Union[str, None] = "c8d9e0f1a2b3"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "investigate_saved_queries",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("operator_id", sa.UUID(), nullable=False),
        sa.Column("prompt", sa.String(length=2000), nullable=False),
        sa.Column("is_favorite", sa.Boolean(), nullable=False),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("org_id", sa.UUID(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["operator_id"], ["operators.id"]),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("org_id", "operator_id", "prompt"),
    )
    op.create_index(
        op.f("ix_investigate_saved_queries_org_id"),
        "investigate_saved_queries",
        ["org_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_investigate_saved_queries_operator_id"),
        "investigate_saved_queries",
        ["operator_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_investigate_saved_queries_operator_id"), table_name="investigate_saved_queries")
    op.drop_index(op.f("ix_investigate_saved_queries_org_id"), table_name="investigate_saved_queries")
    op.drop_table("investigate_saved_queries")
