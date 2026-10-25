# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Operator in-app notification inbox.

Revision ID: c4d5e6f7a8b9
Revises: b3c4d5e6f7a8
Create Date: 2026-07-23
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "c4d5e6f7a8b9"
down_revision: Union[str, None] = "b3c4d5e6f7a8"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "operator_in_app_notifications",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("operator_id", sa.UUID(), nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("event_type", sa.String(length=64), nullable=False),
        sa.Column("title", sa.String(length=512), nullable=False),
        sa.Column("body", sa.Text(), nullable=True),
        sa.Column("finding_id", sa.UUID(), nullable=True),
        sa.Column("severity", sa.String(length=32), nullable=True),
        sa.Column("payload", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("read_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("org_id", sa.UUID(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"]),
        sa.ForeignKeyConstraint(["operator_id"], ["operators.id"]),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_operator_in_app_notifications_org_id"),
        "operator_in_app_notifications",
        ["org_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_operator_in_app_notifications_operator_id"),
        "operator_in_app_notifications",
        ["operator_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_operator_in_app_notifications_finding_id"),
        "operator_in_app_notifications",
        ["finding_id"],
        unique=False,
    )
    op.create_index(
        "ix_operator_in_app_notifications_inbox",
        "operator_in_app_notifications",
        ["org_id", "operator_id", "read_at", "created_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_operator_in_app_notifications_inbox", table_name="operator_in_app_notifications")
    op.drop_index(
        op.f("ix_operator_in_app_notifications_finding_id"),
        table_name="operator_in_app_notifications",
    )
    op.drop_index(
        op.f("ix_operator_in_app_notifications_operator_id"),
        table_name="operator_in_app_notifications",
    )
    op.drop_index(
        op.f("ix_operator_in_app_notifications_org_id"),
        table_name="operator_in_app_notifications",
    )
    op.drop_table("operator_in_app_notifications")
