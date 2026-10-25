# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Add finding_notes for investigation collaboration.

Revision ID: f7a8b9c0d1e2
Revises: e6f7a8b9c0d1
Create Date: 2026-07-30
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "f7a8b9c0d1e2"
down_revision: Union[str, None] = "e6f7a8b9c0d1"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "finding_notes",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("finding_id", sa.UUID(), nullable=False),
        sa.Column("author_operator_id", sa.UUID(), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("org_id", sa.UUID(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["author_operator_id"], ["operators.id"]),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_finding_notes_org_id"), "finding_notes", ["org_id"], unique=False)
    op.create_index(op.f("ix_finding_notes_finding_id"), "finding_notes", ["finding_id"], unique=False)
    op.create_index(
        op.f("ix_finding_notes_author_operator_id"),
        "finding_notes",
        ["author_operator_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_finding_notes_author_operator_id"), table_name="finding_notes")
    op.drop_index(op.f("ix_finding_notes_finding_id"), table_name="finding_notes")
    op.drop_index(op.f("ix_finding_notes_org_id"), table_name="finding_notes")
    op.drop_table("finding_notes")
