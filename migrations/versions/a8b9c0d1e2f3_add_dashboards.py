# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Add dashboards, widgets, schedules, exports.

Revision ID: a8b9c0d1e2f3
Revises: z7a8b9c0d1e2
Create Date: 2026-08-24
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "a8b9c0d1e2f3"
down_revision: Union[str, None] = "z7a8b9c0d1e2"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    dashboard_visibility = postgresql.ENUM(
        "org", "private", name="dashboard_visibility", create_type=False
    )
    dashboard_viz_type = postgresql.ENUM(
        "kpi",
        "table",
        "bar",
        "pie",
        "donut",
        "line",
        "area",
        "list",
        "markdown",
        "preset",
        name="dashboard_viz_type",
        create_type=False,
    )
    dashboard_schedule_format = postgresql.ENUM(
        "pdf", "html", "json", name="dashboard_schedule_format", create_type=False
    )
    dashboard_visibility.create(op.get_bind(), checkfirst=True)
    dashboard_viz_type.create(op.get_bind(), checkfirst=True)
    dashboard_schedule_format.create(op.get_bind(), checkfirst=True)

    op.create_table(
        "dashboards",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("org_id", sa.UUID(), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("slug", sa.String(length=120), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("is_default", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column(
            "visibility",
            postgresql.ENUM(
                "org", "private", name="dashboard_visibility", create_type=False
            ),
            nullable=False,
            server_default="org",
        ),
        sa.Column("created_by_operator_id", sa.UUID(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"]),
        sa.ForeignKeyConstraint(["created_by_operator_id"], ["operators.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("org_id", "slug"),
    )
    op.create_index("ix_dashboards_org_id", "dashboards", ["org_id"])
    op.create_index("ix_dashboards_is_default", "dashboards", ["is_default"])

    op.create_table(
        "dashboard_widgets",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("org_id", sa.UUID(), nullable=False),
        sa.Column("dashboard_id", sa.UUID(), nullable=False),
        sa.Column("widget_key", sa.String(length=80), nullable=False),
        sa.Column("title", sa.String(length=200), nullable=False),
        sa.Column(
            "viz_type",
            postgresql.ENUM(
                "kpi",
                "table",
                "bar",
                "pie",
                "donut",
                "line",
                "area",
                "list",
                "markdown",
                "preset",
                name="dashboard_viz_type",
                create_type=False,
            ),
            nullable=False,
        ),
        sa.Column("query_spec", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("layout", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("refresh_seconds", sa.Integer(), nullable=True),
        sa.Column("sort_order", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("body_markdown", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"]),
        sa.ForeignKeyConstraint(["dashboard_id"], ["dashboards.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_dashboard_widgets_org_id", "dashboard_widgets", ["org_id"])
    op.create_index("ix_dashboard_widgets_dashboard_id", "dashboard_widgets", ["dashboard_id"])

    op.create_table(
        "dashboard_schedules",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("org_id", sa.UUID(), nullable=False),
        sa.Column("dashboard_id", sa.UUID(), nullable=False),
        sa.Column("cron", sa.String(length=120), nullable=False),
        sa.Column("timezone", sa.String(length=64), nullable=False, server_default="UTC"),
        sa.Column(
            "format",
            postgresql.ENUM(
                "pdf", "html", "json", name="dashboard_schedule_format", create_type=False
            ),
            nullable=False,
            server_default="pdf",
        ),
        sa.Column(
            "recipient_operator_ids",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_status", sa.String(length=40), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("created_by_operator_id", sa.UUID(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"]),
        sa.ForeignKeyConstraint(["dashboard_id"], ["dashboards.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["created_by_operator_id"], ["operators.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_dashboard_schedules_org_id", "dashboard_schedules", ["org_id"])
    op.create_index("ix_dashboard_schedules_dashboard_id", "dashboard_schedules", ["dashboard_id"])

    op.create_table(
        "dashboard_exports",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("org_id", sa.UUID(), nullable=False),
        sa.Column("dashboard_id", sa.UUID(), nullable=False),
        sa.Column("operator_id", sa.UUID(), nullable=False),
        sa.Column("format", sa.String(length=20), nullable=False),
        sa.Column("byte_size", sa.Integer(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"]),
        sa.ForeignKeyConstraint(["dashboard_id"], ["dashboards.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["operator_id"], ["operators.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_dashboard_exports_org_id", "dashboard_exports", ["org_id"])
    op.create_index("ix_dashboard_exports_dashboard_id", "dashboard_exports", ["dashboard_id"])


def downgrade() -> None:
    op.drop_table("dashboard_exports")
    op.drop_table("dashboard_schedules")
    op.drop_table("dashboard_widgets")
    op.drop_table("dashboards")
    op.execute("DROP TYPE IF EXISTS dashboard_schedule_format")
    op.execute("DROP TYPE IF EXISTS dashboard_viz_type")
    op.execute("DROP TYPE IF EXISTS dashboard_visibility")
