# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Access review campaigns + items.

Revision ID: a2b3c4d5e6f7
Revises: f1a2b3c4d5e6
Create Date: 2026-07-23
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "a2b3c4d5e6f7"
down_revision: Union[str, None] = "f1a2b3c4d5e6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "access_review_campaigns",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column(
            "status",
            sa.Enum("open", "completed", "cancelled", name="access_review_campaign_status"),
            nullable=False,
        ),
        sa.Column(
            "scope",
            sa.Enum("privileged", "oauth", "both", name="access_review_scope"),
            nullable=False,
        ),
        sa.Column("created_by_operator_id", sa.UUID(), nullable=False),
        sa.Column("snapshot_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("due_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
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
        sa.ForeignKeyConstraint(["created_by_operator_id"], ["operators.id"]),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_access_review_campaigns_org_id"),
        "access_review_campaigns",
        ["org_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_access_review_campaigns_created_by_operator_id"),
        "access_review_campaigns",
        ["created_by_operator_id"],
        unique=False,
    )

    op.create_table(
        "access_review_items",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("campaign_id", sa.UUID(), nullable=False),
        sa.Column(
            "kind",
            sa.Enum("privileged_role", "oauth_grant", name="access_review_item_kind"),
            nullable=False,
        ),
        sa.Column("source_key", sa.String(length=200), nullable=False),
        sa.Column("identity_id", sa.UUID(), nullable=True),
        sa.Column("role_id", sa.UUID(), nullable=True),
        sa.Column("oauth_grant_id", sa.UUID(), nullable=True),
        sa.Column("oauth_application_id", sa.UUID(), nullable=True),
        sa.Column("application_instance_id", sa.UUID(), nullable=True),
        sa.Column("snapshot", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column(
            "decision",
            sa.Enum("pending", "attest", "revoke", "defer", name="access_review_decision"),
            nullable=False,
        ),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("reviewed_by_operator_id", sa.UUID(), nullable=True),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
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
        sa.ForeignKeyConstraint(
            ["campaign_id"],
            ["access_review_campaigns.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(["identity_id"], ["identities.id"]),
        sa.ForeignKeyConstraint(["role_id"], ["roles.id"]),
        sa.ForeignKeyConstraint(["oauth_grant_id"], ["oauth_grants.id"]),
        sa.ForeignKeyConstraint(["oauth_application_id"], ["oauth_applications.id"]),
        sa.ForeignKeyConstraint(["application_instance_id"], ["application_instances.id"]),
        sa.ForeignKeyConstraint(["reviewed_by_operator_id"], ["operators.id"]),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "campaign_id",
            "kind",
            "source_key",
            name="uq_access_review_items_source",
        ),
    )
    op.create_index(
        op.f("ix_access_review_items_org_id"),
        "access_review_items",
        ["org_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_access_review_items_campaign_id"),
        "access_review_items",
        ["campaign_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_access_review_items_identity_id"),
        "access_review_items",
        ["identity_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_access_review_items_identity_id"), table_name="access_review_items")
    op.drop_index(op.f("ix_access_review_items_campaign_id"), table_name="access_review_items")
    op.drop_index(op.f("ix_access_review_items_org_id"), table_name="access_review_items")
    op.drop_table("access_review_items")
    op.drop_index(
        op.f("ix_access_review_campaigns_created_by_operator_id"),
        table_name="access_review_campaigns",
    )
    op.drop_index(op.f("ix_access_review_campaigns_org_id"), table_name="access_review_campaigns")
    op.drop_table("access_review_campaigns")
    sa.Enum(name="access_review_decision").drop(op.get_bind(), checkfirst=True)
    sa.Enum(name="access_review_item_kind").drop(op.get_bind(), checkfirst=True)
    sa.Enum(name="access_review_scope").drop(op.get_bind(), checkfirst=True)
    sa.Enum(name="access_review_campaign_status").drop(op.get_bind(), checkfirst=True)
