# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Operator notification preferences.

Revision ID: b3c4d5e6f7a8
Revises: a2b3c4d5e6f7
Create Date: 2026-07-23
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "b3c4d5e6f7a8"
down_revision: Union[str, None] = "a2b3c4d5e6f7"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "operator_notification_preferences",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("operator_id", sa.UUID(), nullable=False),
        sa.Column("email_enabled", sa.Boolean(), nullable=False),
        sa.Column("in_app_enabled", sa.Boolean(), nullable=False),
        sa.Column("findings_enabled", sa.Boolean(), nullable=False),
        sa.Column("webhook_failures_enabled", sa.Boolean(), nullable=False),
        sa.Column("min_severity", sa.String(length=32), nullable=False),
        sa.Column("muted_events", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("org_id", sa.UUID(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["operator_id"], ["operators.id"]),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("org_id", "operator_id"),
    )
    op.create_index(
        op.f("ix_operator_notification_preferences_org_id"),
        "operator_notification_preferences",
        ["org_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_operator_notification_preferences_operator_id"),
        "operator_notification_preferences",
        ["operator_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        op.f("ix_operator_notification_preferences_operator_id"),
        table_name="operator_notification_preferences",
    )
    op.drop_index(
        op.f("ix_operator_notification_preferences_org_id"),
        table_name="operator_notification_preferences",
    )
    op.drop_table("operator_notification_preferences")
