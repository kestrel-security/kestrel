# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Operator rules that classify identities into a worker type.

Revision ID: n3c4d5e6f7a8
Revises: m2b3c4d5e6f7
Create Date: 2026-10-28
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "n3c4d5e6f7a8"
down_revision: str | None = "m2b3c4d5e6f7"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "org_identity_classification_rules",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("org_id", sa.UUID(), nullable=False),
        sa.Column("priority", sa.Integer(), nullable=False),
        sa.Column("is_enabled", sa.Boolean(), nullable=False),
        sa.Column("worker_type", sa.String(length=32), nullable=False),
        sa.Column("match_kind", sa.String(length=32), nullable=False),
        sa.Column("match_value", sa.String(length=512), nullable=False),
        sa.Column("application_type", sa.String(length=64), nullable=True),
        sa.Column("label", sa.String(length=200), nullable=True),
        sa.Column("created_by_operator_id", sa.UUID(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"]),
        sa.ForeignKeyConstraint(["created_by_operator_id"], ["operators.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_org_identity_classification_rules_org_id"), "org_identity_classification_rules", ["org_id"], unique=False
    )
    op.create_index(
        "ix_org_identity_classification_rules_priority",
        "org_identity_classification_rules",
        ["org_id", "priority"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_org_identity_classification_rules_priority", table_name="org_identity_classification_rules")
    op.drop_index(op.f("ix_org_identity_classification_rules_org_id"), table_name="org_identity_classification_rules")
    op.drop_table("org_identity_classification_rules")
