# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Add discovered_applications for shadow SaaS discovery.

Revision ID: i0d1e2f3a4b5
Revises: h9c0d1e2f3a4
Create Date: 2026-07-30
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "i0d1e2f3a4b5"
down_revision: Union[str, None] = "h9c0d1e2f3a4"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    discovered_application_source = postgresql.ENUM(
        "google_workspace",
        name="discovered_application_source",
        create_type=False,
    )
    discovered_application_status = postgresql.ENUM(
        "sanctioned",
        "unsanctioned",
        "under_review",
        name="discovered_application_status",
        create_type=False,
    )
    discovered_application_source.create(op.get_bind(), checkfirst=True)
    discovered_application_status.create(op.get_bind(), checkfirst=True)

    op.create_table(
        "discovered_applications",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column(
            "source",
            postgresql.ENUM(
                "google_workspace",
                name="discovered_application_source",
                create_type=False,
            ),
            nullable=False,
        ),
        sa.Column("external_app_id", sa.String(), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column(
            "status",
            postgresql.ENUM(
                "sanctioned",
                "unsanctioned",
                "under_review",
                name="discovered_application_status",
                create_type=False,
            ),
            nullable=False,
        ),
        sa.Column("owner_identity_id", sa.UUID(), nullable=True),
        sa.Column(
            "first_seen_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "last_seen_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("scopes", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("catalog_match", sa.String(), nullable=True),
        sa.Column("sensitivity", sa.String(length=32), nullable=False),
        sa.Column("raw_source", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("application_instance_id", sa.UUID(), nullable=True),
        sa.Column("promoted_application_id", sa.UUID(), nullable=True),
        sa.Column("org_id", sa.UUID(), nullable=False),
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
        sa.ForeignKeyConstraint(["application_instance_id"], ["application_instances.id"]),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"]),
        sa.ForeignKeyConstraint(["owner_identity_id"], ["identities.id"]),
        sa.ForeignKeyConstraint(["promoted_application_id"], ["applications.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "org_id",
            "source",
            "external_app_id",
            name="uq_discovered_apps_org_source_ext",
        ),
    )
    op.create_index(
        op.f("ix_discovered_applications_application_instance_id"),
        "discovered_applications",
        ["application_instance_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_discovered_applications_external_app_id"),
        "discovered_applications",
        ["external_app_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_discovered_applications_org_id"),
        "discovered_applications",
        ["org_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_discovered_applications_owner_identity_id"),
        "discovered_applications",
        ["owner_identity_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_discovered_applications_status"),
        "discovered_applications",
        ["status"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_discovered_applications_status"), table_name="discovered_applications")
    op.drop_index(
        op.f("ix_discovered_applications_owner_identity_id"), table_name="discovered_applications"
    )
    op.drop_index(op.f("ix_discovered_applications_org_id"), table_name="discovered_applications")
    op.drop_index(
        op.f("ix_discovered_applications_external_app_id"), table_name="discovered_applications"
    )
    op.drop_index(
        op.f("ix_discovered_applications_application_instance_id"),
        table_name="discovered_applications",
    )
    op.drop_table("discovered_applications")
    op.execute("DROP TYPE IF EXISTS discovered_application_status")
    op.execute("DROP TYPE IF EXISTS discovered_application_source")
