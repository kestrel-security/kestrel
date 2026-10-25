# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Add access-review reviewer operator FKs.

Revision ID: g8b9c0d1e2f3
Revises: f7a8b9c0d1e2
Create Date: 2026-07-30
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "g8b9c0d1e2f3"
down_revision: Union[str, None] = "f7a8b9c0d1e2"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "access_review_campaigns",
        sa.Column("reviewer_operator_id", sa.UUID(), nullable=True),
    )
    op.create_index(
        op.f("ix_access_review_campaigns_reviewer_operator_id"),
        "access_review_campaigns",
        ["reviewer_operator_id"],
        unique=False,
    )
    op.create_foreign_key(
        "fk_access_review_campaigns_reviewer_operator_id",
        "access_review_campaigns",
        "operators",
        ["reviewer_operator_id"],
        ["id"],
    )

    op.add_column(
        "access_review_items",
        sa.Column("assigned_reviewer_operator_id", sa.UUID(), nullable=True),
    )
    op.create_index(
        op.f("ix_access_review_items_assigned_reviewer_operator_id"),
        "access_review_items",
        ["assigned_reviewer_operator_id"],
        unique=False,
    )
    op.create_foreign_key(
        "fk_access_review_items_assigned_reviewer_operator_id",
        "access_review_items",
        "operators",
        ["assigned_reviewer_operator_id"],
        ["id"],
    )


def downgrade() -> None:
    op.drop_constraint(
        "fk_access_review_items_assigned_reviewer_operator_id",
        "access_review_items",
        type_="foreignkey",
    )
    op.drop_index(
        op.f("ix_access_review_items_assigned_reviewer_operator_id"),
        table_name="access_review_items",
    )
    op.drop_column("access_review_items", "assigned_reviewer_operator_id")

    op.drop_constraint(
        "fk_access_review_campaigns_reviewer_operator_id",
        "access_review_campaigns",
        type_="foreignkey",
    )
    op.drop_index(
        op.f("ix_access_review_campaigns_reviewer_operator_id"),
        table_name="access_review_campaigns",
    )
    op.drop_column("access_review_campaigns", "reviewer_operator_id")
