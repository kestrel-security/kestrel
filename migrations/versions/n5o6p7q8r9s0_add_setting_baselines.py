# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Add setting_baselines for configuration drift attestation.

Revision ID: n5o6p7q8r9s0
Revises: m4n5o6p7q8r9
Create Date: 2026-07-30
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "n5o6p7q8r9s0"
down_revision: Union[str, None] = "m4n5o6p7q8r9"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "setting_baselines",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("application_instance_id", sa.UUID(), nullable=False),
        sa.Column("snapshot", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("attested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("attested_by_operator_id", sa.UUID(), nullable=False),
        sa.Column("org_id", sa.UUID(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(
            ["application_instance_id"],
            ["application_instances.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(["attested_by_operator_id"], ["operators.id"]),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("application_instance_id", name="uq_setting_baselines_application_instance"),
    )
    op.create_index(
        op.f("ix_setting_baselines_org_id"),
        "setting_baselines",
        ["org_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_setting_baselines_application_instance_id"),
        "setting_baselines",
        ["application_instance_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_setting_baselines_application_instance_id"), table_name="setting_baselines")
    op.drop_index(op.f("ix_setting_baselines_org_id"), table_name="setting_baselines")
    op.drop_table("setting_baselines")
