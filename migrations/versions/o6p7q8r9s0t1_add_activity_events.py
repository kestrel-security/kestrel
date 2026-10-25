# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Add activity_events for SaaS audit ingestion.

Revision ID: o6p7q8r9s0t1
Revises: n5o6p7q8r9s0
Create Date: 2026-07-30
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "o6p7q8r9s0t1"
down_revision: Union[str, None] = "n5o6p7q8r9s0"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("ALTER TYPE finding_subject_type ADD VALUE IF NOT EXISTS 'event'")

    op.create_table(
        "activity_events",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("application_instance_id", sa.UUID(), nullable=False),
        sa.Column("provider_object_id", sa.String(), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("source_connector_run_id", sa.UUID(), nullable=False),
        sa.Column("raw_source", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("schema_version", sa.Integer(), server_default="1", nullable=False),
        sa.Column("action", sa.String(), nullable=False),
        sa.Column("action_category", sa.String(), nullable=False),
        sa.Column("actor_email", sa.String(), nullable=True),
        sa.Column("actor_provider_id", sa.String(), nullable=True),
        sa.Column("target_email", sa.String(), nullable=True),
        sa.Column("target_type", sa.String(), nullable=True),
        sa.Column("target_provider_id", sa.String(), nullable=True),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("summary", sa.String(), nullable=False),
        sa.Column(
            "attributes",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column("org_id", sa.UUID(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["application_instance_id"], ["application_instances.id"]),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"]),
        sa.ForeignKeyConstraint(["source_connector_run_id"], ["connector_runs.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("application_instance_id", "provider_object_id"),
    )
    op.create_index("ix_activity_events_org_action", "activity_events", ["org_id", "action"], unique=False)
    op.create_index(
        "ix_activity_events_org_occurred", "activity_events", ["org_id", "occurred_at"], unique=False
    )
    op.create_index(op.f("ix_activity_events_action"), "activity_events", ["action"], unique=False)
    op.create_index(
        op.f("ix_activity_events_action_category"), "activity_events", ["action_category"], unique=False
    )
    op.create_index(
        op.f("ix_activity_events_application_instance_id"),
        "activity_events",
        ["application_instance_id"],
        unique=False,
    )
    op.create_index(op.f("ix_activity_events_org_id"), "activity_events", ["org_id"], unique=False)
    op.create_index(
        op.f("ix_activity_events_provider_object_id"),
        "activity_events",
        ["provider_object_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_activity_events_provider_object_id"), table_name="activity_events")
    op.drop_index(op.f("ix_activity_events_org_id"), table_name="activity_events")
    op.drop_index(op.f("ix_activity_events_application_instance_id"), table_name="activity_events")
    op.drop_index(op.f("ix_activity_events_action_category"), table_name="activity_events")
    op.drop_index(op.f("ix_activity_events_action"), table_name="activity_events")
    op.drop_index("ix_activity_events_org_occurred", table_name="activity_events")
    op.drop_index("ix_activity_events_org_action", table_name="activity_events")
    op.drop_table("activity_events")
    # Postgres cannot remove enum values safely; leave finding_subject_type 'event'.
