# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Add tenant_settings + setting subject/node enums.

Revision ID: h9c0d1e2f3a4
Revises: g8b9c0d1e2f3
Create Date: 2026-07-30
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "h9c0d1e2f3a4"
down_revision: Union[str, None] = "g8b9c0d1e2f3"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("ALTER TYPE finding_subject_type ADD VALUE IF NOT EXISTS 'setting'")
    op.execute("ALTER TYPE graph_node_type ADD VALUE IF NOT EXISTS 'setting'")

    op.create_table(
        "tenant_settings",
        sa.Column("key", sa.String(), nullable=False),
        sa.Column("category", sa.String(), nullable=False),
        sa.Column("label", sa.String(), nullable=False),
        sa.Column("value", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("value_type", sa.String(), nullable=False),
        sa.Column("description", sa.String(), nullable=True),
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("application_instance_id", sa.UUID(), nullable=False),
        sa.Column("provider_object_id", sa.String(), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("source_connector_run_id", sa.UUID(), nullable=False),
        sa.Column("raw_source", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False),
        sa.Column("org_id", sa.UUID(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["application_instance_id"], ["application_instances.id"]),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"]),
        sa.ForeignKeyConstraint(["source_connector_run_id"], ["connector_runs.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("application_instance_id", "provider_object_id"),
    )
    op.create_index(
        op.f("ix_tenant_settings_application_instance_id"),
        "tenant_settings",
        ["application_instance_id"],
        unique=False,
    )
    op.create_index(op.f("ix_tenant_settings_category"), "tenant_settings", ["category"], unique=False)
    op.create_index(op.f("ix_tenant_settings_key"), "tenant_settings", ["key"], unique=False)
    op.create_index(op.f("ix_tenant_settings_org_id"), "tenant_settings", ["org_id"], unique=False)
    op.create_index(
        op.f("ix_tenant_settings_provider_object_id"),
        "tenant_settings",
        ["provider_object_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_tenant_settings_provider_object_id"), table_name="tenant_settings")
    op.drop_index(op.f("ix_tenant_settings_org_id"), table_name="tenant_settings")
    op.drop_index(op.f("ix_tenant_settings_key"), table_name="tenant_settings")
    op.drop_index(op.f("ix_tenant_settings_category"), table_name="tenant_settings")
    op.drop_index(op.f("ix_tenant_settings_application_instance_id"), table_name="tenant_settings")
    op.drop_table("tenant_settings")
    # Postgres cannot remove enum values safely; leave finding_subject_type /
    # graph_node_type 'setting' in place on downgrade.
