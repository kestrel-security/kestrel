# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Finding watchers / subscribe.

Revision ID: d5e6f7a8b9c0
Revises: c4d5e6f7a8b9
Create Date: 2026-07-23
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "d5e6f7a8b9c0"
down_revision: Union[str, None] = "c4d5e6f7a8b9"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "finding_watchers",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("operator_id", sa.UUID(), nullable=False),
        sa.Column("finding_id", sa.UUID(), nullable=False),
        sa.Column("org_id", sa.UUID(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"]),
        sa.ForeignKeyConstraint(["operator_id"], ["operators.id"]),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("org_id", "operator_id", "finding_id"),
    )
    op.create_index(op.f("ix_finding_watchers_org_id"), "finding_watchers", ["org_id"], unique=False)
    op.create_index(
        op.f("ix_finding_watchers_operator_id"),
        "finding_watchers",
        ["operator_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_finding_watchers_finding_id"),
        "finding_watchers",
        ["finding_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_finding_watchers_finding_id"), table_name="finding_watchers")
    op.drop_index(op.f("ix_finding_watchers_operator_id"), table_name="finding_watchers")
    op.drop_index(op.f("ix_finding_watchers_org_id"), table_name="finding_watchers")
    op.drop_table("finding_watchers")
